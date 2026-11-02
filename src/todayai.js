'use strict';
/**
 * todayai.js — your-domain.example.com 的 todayai.cn 通道（协议转换层，多账号版）
 *
 * 上游：
 *   认证/会话  https://todayai.cn        （better-auth：短信登录 → session cookie → POST /api/token 换 JWT）
 *   业务 API   https://api.todayai.cn    （自研 REST：/v1/messages 发消息、/v1/conversations/messages 取回复）
 * 对外：
 *   OpenAI 兼容 /v1/chat/completions（流式 + 非流式）与 /v1/models 的 todayai-* 模型
 *
 * 账号来源（优先级）：
 *   ① 站点用户自己绑定的 todayai 账号（v2db.todayai_accounts，cookie 加密存储）—— 与 upstream 站"每人绑自己账号"同构
 *   ② 全局账号（data/todayai-account.json）—— 兜底（未绑定用户/未登录场景）
 */
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const toolbridge = require('./toolbridge');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const ACCOUNT_FILE = path.join(DATA_DIR, 'todayai-account.json');
const WEB = 'https://todayai.cn';
const API = 'https://api.todayai.cn';

const MODEL_MAP = {
  'todayai-deepseek': 'model.deepseek-v4.1-flash',
  'todayai-minimax': 'model.minimax-m31-flash',
  'todayai-glm': 'model.glm-5.3'
};
const DISPLAY_NAME = {
  'model.deepseek-v4.1-flash': 'DeepSeek V4.1 Flash',
  'model.minimax-m31-flash': 'MiniMax M3.1 Flash',
  'model.glm-5.3': 'GLM 5.3'
};
const DEFAULT_MODEL = 'model.deepseek-v4.1-flash';

let upstreamOptions = [];
let v2dbRef = null;
const ACCOUNTS = new Map();   // key -> acct

function log(...a) { console.log('[todayai]', ...a); }
function db() {
  if (v2dbRef) return v2dbRef;
  try { v2dbRef = require('./v2db'); } catch (e) { v2dbRef = null; }
  return v2dbRef;
}
function slug(optionId) { return String(optionId).replace(/^model\./, '').replace(/[^a-zA-Z0-9]+/g, '-').toLowerCase(); }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// ---------------- 账号装载 ----------------
function readGlobalFile() {
  try { return JSON.parse(fs.readFileSync(ACCOUNT_FILE, 'utf8')) || {}; } catch (e) { return {}; }
}
function writeGlobalFile(a) {
  try {
    fs.writeFileSync(ACCOUNT_FILE, JSON.stringify({
      cookie: a.cookie, jwt: a.jwt || '', jwtExp: a.jwtExp || 0,
      selectedOption: a.selectedOption || '', userId: a.userId || '', updatedAt: Date.now()
    }, null, 2));
    fs.chmodSync(ACCOUNT_FILE, 0o600);
  } catch (e) { log('保存全局账号失败:', e.message); }
}

function acctKeyFor(userV2Id) { return userV2Id ? 'u' + Number(userV2Id) : 'global'; }

function loadAccount(userV2Id) {
  const key = acctKeyFor(userV2Id);
  if (ACCOUNTS.has(key)) return ACCOUNTS.get(key);
  let a = null;

  if (key !== 'global') {
    const d = db();
    if (d && d.udb) {
      try {
        const row = d.udb.prepare(
          'SELECT id, label, cookie, jwt, jwt_exp, upstream_user_id, selected_option FROM todayai_accounts WHERE user_id=? AND enabled=1 ORDER BY created_at DESC LIMIT 1'
        ).get(Number(key.slice(1)));
        if (row && row.cookie) {
          a = {
            key, id: row.id, label: row.label || '', source: 'user',
            cookie: d.decryptCred(row.cookie),
            jwt: row.jwt || '', jwtExp: Number(row.jwt_exp || 0),
            userId: row.upstream_user_id || '', selectedOption: row.selected_option || ''
          };
        }
      } catch (e) { log('读取用户 todayai 账号失败:', e.message); }
    }
  }

  if (!a) {
    const g = readGlobalFile();
    if (g.cookie) {
      a = {
        key: 'global', source: 'global', label: g.label || '全局账号',
        cookie: g.cookie, jwt: g.jwt || '', jwtExp: Number(g.jwtExp || 0),
        userId: g.userId || '', selectedOption: g.selectedOption || ''
      };
    }
  }
  if (!a) a = { key, source: 'none', cookie: '', jwt: '', jwtExp: 0, userId: '', selectedOption: '' };
  ACCOUNTS.set(key, a);
  return a;
}

function persist(a) {
  if (a.source === 'user' && a.id) {
    const d = db();
    if (d && d.udb) {
      try {
        d.udb.prepare('UPDATE todayai_accounts SET jwt=?, jwt_exp=?, upstream_user_id=?, selected_option=? WHERE id=?')
          .run(a.jwt || '', a.jwtExp || 0, a.userId || '', a.selectedOption || '', a.id);
      } catch (e) { log('写回用户账号失败:', e.message); }
    }
  } else if (a.source === 'global') {
    writeGlobalFile(a);
  }
}

function configured() {
  if (loadAccount(null).cookie) return true;
  const d = db();
  if (d && d.udb) {
    try { return !!d.udb.prepare('SELECT id FROM todayai_accounts WHERE enabled=1 LIMIT 1').get(); } catch (e) {}
  }
  return false;
}

// ---------------- HTTP ----------------
function httpJson(urlStr, opts) {
  const o = opts || {};
  const u = new URL(urlStr);
  const data = o.body == null ? null : (typeof o.body === 'string' ? o.body : JSON.stringify(o.body));
  const headers = Object.assign({ accept: 'application/json', 'user-agent': 'today-gateway/1.0' }, o.headers || {});
  if (data) { headers['content-type'] = 'application/json'; headers['content-length'] = Buffer.byteLength(data); }
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: u.hostname, path: u.pathname + (u.search || ''), method: o.method || 'GET',
      headers, timeout: o.timeout || 30000
    }, (r) => {
      const chunks = [];
      r.on('data', (c) => chunks.push(c));
      r.on('end', () => {
        const txt = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(txt); } catch (e) {}
        resolve({ status: r.statusCode, json, text: txt, headers: r.headers });
      });
    });
    req.on('timeout', () => req.destroy(new Error('upstream timeout ' + (o.timeout || 30000) + 'ms')));
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// ---------------- 登录/绑定（供用户中心调用） ----------------
async function sendOtp(phone) {
  const p = String(phone || '').replace(/\D/g, '');
  const target = p.startsWith('86') ? '+' + p : '+86' + p;
  const r = await httpJson(WEB + '/api/auth/phone-number/send-otp', {
    method: 'POST', body: { phoneNumber: target }, timeout: 20000
  });
  if (r.status !== 200) return { ok: false, msg: '发送失败: HTTP ' + r.status + ' ' + String(r.text || '').slice(0, 120) };
  return { ok: true };
}

async function verifyLogin(phone, code) {
  const p = String(phone || '').replace(/\D/g, '');
  const target = p.startsWith('86') ? '+' + p : '+86' + p;
  const r = await httpJson(WEB + '/api/auth/phone-number/verify', {
    method: 'POST', body: { phoneNumber: target, code: String(code || '').trim() }, timeout: 25000
  });
  if (r.status !== 200 || !r.json || !r.json.user) {
    return { ok: false, msg: (r.json && r.json.message) || ('登录失败: HTTP ' + r.status) };
  }
  // 从 set-cookie 里提取 session cookie
  const sc = r.headers['set-cookie'] || [];
  const jar = [];
  for (const c of sc) {
    const m = /^([^=]+)=([^;]*)/.exec(c);
    if (m && /better-auth\.session_token/.test(m[1])) jar.push(m[1] + '=' + m[2]);
  }
  if (!jar.length) return { ok: false, msg: '未获取到 session cookie' };
  const cookie = jar.join('; ');

  // 立即换一次 JWT 并取账号信息（验证可用性）
  const t = await httpJson(WEB + '/api/token', { method: 'POST', headers: { cookie }, body: { audience: API }, timeout: 20000 });
  const jwt = t.json && t.json.token;
  if (!jwt) return { ok: false, msg: '换取 JWT 失败' };
  let userId = '';
  try {
    const me = await httpJson(API + '/v1/users/me', { headers: { authorization: 'Bearer ' + jwt }, timeout: 20000 });
    userId = (me.json && me.json.id) || '';
  } catch (e) {}
  let exp = Math.floor(Date.now() / 1000) + 3300;
  try { const pl = JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url').toString('utf8')); if (pl.exp) exp = pl.exp; } catch (e) {}

  return { ok: true, cookie, jwt, jwtExp: exp, userId, phone: target };
}

// ---------------- 认证 ----------------
async function ensureJwt(a, force) {
  if (!force && a.jwt && (a.jwtExp - Math.floor(Date.now() / 1000) > 300)) return a.jwt;
  if (!a.cookie) throw new Error(a.source === 'user' ? '你还没有绑定 TodayAI 账号（用户中心 → 绑定账号）' : 'todayai 账号未配置');
  const r = await httpJson(WEB + '/api/token', { method: 'POST', headers: { cookie: a.cookie }, body: { audience: API }, timeout: 20000 });
  const t = r.json && r.json.token;
  if (r.status !== 200 || !t) throw new Error('换取 JWT 失败: HTTP ' + r.status + ' ' + String(r.text || '').slice(0, 160));
  let exp = Math.floor(Date.now() / 1000) + 3300;
  try { const pl = JSON.parse(Buffer.from(String(t).split('.')[1], 'base64url').toString('utf8')); if (pl.exp) exp = pl.exp; } catch (e) {}
  a.jwt = t; a.jwtExp = exp; persist(a);
  log('JWT 已刷新', a.source, a.label || '', new Date(exp * 1000).toISOString());
  return t;
}

async function apiReq(a, method, p, body) {
  const jwt = await ensureJwt(a);
  return httpJson(API + p, { method, headers: { authorization: 'Bearer ' + jwt }, body: body == null ? null : body, timeout: 30000 });
}

async function ensureUserId(a) {
  if (a.userId) return a.userId;
  const r = await apiReq(a, 'GET', '/v1/users/me');
  const id = r.json && r.json.id;
  if (r.status !== 200 || !id) throw new Error('获取账号信息失败: HTTP ' + r.status);
  a.userId = id; persist(a);
  return id;
}

// ---------------- 模型 ----------------
async function listModels(userV2Id) {
  const a = userV2Id ? loadAccount(userV2Id) : loadAccount(null);
  const r = await apiReq(a, 'GET', '/v1/pricing/status');
  const mo = r.json && r.json.data && r.json.data.status && r.json.data.status.modelOptions;
  if (!mo || !Array.isArray(mo.options)) throw new Error('上游未返回 modelOptions: HTTP ' + r.status);
  upstreamOptions = mo.options.map((o) => ({ id: o.id, title: (o.display && o.display.title) || o.id, disabled: !!o.disabled }));
  a.selectedOption = mo.selectedOptionId || a.selectedOption;
  persist(a);
  return { options: upstreamOptions, selected: a.selectedOption };
}

function isTodayModel(m) {
  if (typeof m !== 'string') return false;
  if (Object.prototype.hasOwnProperty.call(MODEL_MAP, m)) return true;
  if (!m.startsWith('todayai-')) return false;
  return upstreamOptions.some((o) => 'todayai-' + slug(o.id) === m);
}
function resolveOption(model) {
  if (MODEL_MAP[model]) return MODEL_MAP[model];
  const hit = upstreamOptions.find((o) => 'todayai-' + slug(o.id) === model);
  if (hit) return hit.id;
  if (typeof model === 'string' && model.startsWith('todayai-')) return 'model.' + model.slice(9);
  return DEFAULT_MODEL;
}
function publicModels() {
  const out = Object.entries(MODEL_MAP).map(([alias, up]) => ({
    id: alias, object: 'model', created: 0, owned_by: 'todayai', todayai_model: up, upstream: DISPLAY_NAME[up] || up
  }));
  const fixed = new Set(Object.values(MODEL_MAP));
  for (const o of upstreamOptions) {
    if (fixed.has(o.id)) continue;
    const alias = 'todayai-' + slug(o.id);
    if (!out.some((x) => x.id === alias)) {
      out.push({ id: alias, object: 'model', created: 0, owned_by: 'todayai', todayai_model: o.id, upstream: o.title, disabled: !!o.disabled });
    }
  }
  return out;
}

async function ensureModel(a, optionId) {
  if (a.selectedOption === optionId) return;
  const r = await apiReq(a, 'PUT', '/v1/pricing/model-option', { optionId });
  if (r.status !== 200) throw new Error('切换模型失败: HTTP ' + r.status + ' ' + String(r.text || '').slice(0, 160));
  const sel = r.json && r.json.data && r.json.data.modelOptions && r.json.data.modelOptions.selectedOptionId;
  a.selectedOption = sel || optionId; persist(a);
  log('模型已切换 →', a.selectedOption);
}

// ---------------- 对话 ----------------
function extractText(item) {
  const parts = item && item.body && Array.isArray(item.body.parts) ? item.body.parts : [];
  let out = '';
  for (const p of parts) {
    if (p && p.messageType === 'text' && p.content && typeof p.content.text === 'string') out += p.content.text;
  }
  return out;
}
function buildContent(messages) {
  const arr = Array.isArray(messages) ? messages : [];
  let system = '', lastUser = '';
  for (const m of arr) {
    if (!m) continue;
    let text = '';
    if (typeof m.content === 'string') text = m.content;
    else if (Array.isArray(m.content)) text = m.content.map((c) => (c && (c.text || c.content)) || '').join('');
    if (m.role === 'system') system += (system ? '\n' : '') + text;
    else if (m.role === 'user') lastUser = text;
    else if (m.role === 'assistant' && text && !lastUser) lastUser = text;
  }
  if (!lastUser) throw new Error('请求中没有 user 消息');
  return system ? ('【系统指令】' + system + '\n\n' + lastUser) : lastUser;
}

/** 只取最后一条 user 文本（工具协议已注入该条，不能再拼 system 前缀，否则稀释协议遵循度） */
function lastUserOnly(messages) {
  const arr = Array.isArray(messages) ? messages : [];
  for (let i = arr.length - 1; i >= 0; i--) {
    const m = arr[i];
    if (!m || m.role !== 'user') continue;
    if (typeof m.content === 'string') return m.content;
    if (Array.isArray(m.content)) return m.content.map((c) => (c && (c.text || c.content)) || '').join('');
  }
  throw new Error('请求中没有 user 消息');
}

/** 只渲染对话本身（不含任何附加指令），用于把工具协议放在最前面时拼接 */
function renderDialog(messages) {
  const arr = Array.isArray(messages) ? messages : [];
  const parts = [];
  for (const m of arr) {
    if (!m) continue;
    let text = typeof m.content === 'string' ? m.content : (Array.isArray(m.content) ? m.content.map((c) => (c && (c.text || c.content)) || '').join('') : '');
    if (m.role === 'system') { if (text) parts.push('【系统指令】\n' + text); continue; }
    if (m.role === 'tool') { if (text) parts.push('【工具执行结果】\n' + text); continue; }
    if (m.role === 'assistant') {
      let s = text ? ('【助手】\n' + text) : '';
      const tcs = Array.isArray(m.tool_calls) ? m.tool_calls : [];
      if (tcs.length) {
        const tc = tcs.map((t) => '<tool_call>' + JSON.stringify({
          name: t.function && t.function.name, arguments: (t.function && t.function.arguments) || '{}'
        }) + '</tool_call>').join('\n');
        s = (s ? s + '\n' : '【助手】\n') + tc;
      }
      if (s) parts.push(s);
      continue;
    }
    if (text) parts.push('【用户】\n' + text);
  }
  return parts.join('\n\n');
}

/** 把 messages 渲染成单条文本：客户端上下文全带上，并显式要求上游忽略它自己的历史（上游会话固定无法新建，只能靠这条约束避免串味） */
function renderThread(messages) {
  const arr = Array.isArray(messages) ? messages : [];
  const parts = ['【会话说明】这是一次独立请求，请完全忽略你此前与该账号的历史对话，仅依据下面提供的内容回答。'];
  for (const m of arr) {
    if (!m) continue;
    let text = typeof m.content === 'string' ? m.content : (Array.isArray(m.content) ? m.content.map((c) => (c && (c.text || c.content)) || '').join('') : '');
    if (m.role === 'system') { if (text) parts.push('【系统指令】\n' + text); continue; }
    if (m.role === 'tool') { if (text) parts.push('【工具执行结果】\n' + text); continue; }
    if (m.role === 'assistant') {
      let s = text ? ('【助手】\n' + text) : '';
      const tcs = Array.isArray(m.tool_calls) ? m.tool_calls : [];
      if (tcs.length) {
        const tc = tcs.map((t) => '<tool_call>' + JSON.stringify({
          name: t.function && t.function.name,
          arguments: (t.function && t.function.arguments) || '{}'
        }) + '</tool_call>').join('\n');
        s = (s ? s + '\n' : '【助手】\n') + tc;
      }
      if (s) parts.push(s);
      continue;
    }
    if (text) parts.push('【用户】\n' + text);
  }
  parts.push('【请回答最后一条用户消息】');
  return parts.join('\n\n');
}

function buildThreadContent(messages) {
  let arr = Array.isArray(messages) ? messages.slice() : [];
  let out = renderThread(arr);
  let guard = 0;
  while (out.length > 24000 && arr.length > 2 && guard++ < 30) {
    const idx = arr.findIndex((m) => m && m.role !== 'system');
    if (idx < 0) break;
    arr.splice(idx, 1);
    out = renderThread(arr);
  }
  if (out.length > 30000) out = out.slice(out.length - 30000);
  return out;
}

async function postMessage(a, text) {
  const r = await apiReq(a, 'POST', '/v1/messages', { content: text });
  if (!(r.status === 200 || r.status === 201 || r.status === 202) || !r.json || !r.json.threadId) {
    throw new Error('发送消息失败: HTTP ' + r.status + ' ' + String(r.text || '').slice(0, 200));
  }
  return r.json;
}

async function pollReply(a, threadId, onDelta, opts) {
  const convId = a.userId || (await ensureUserId(a));
  const deadline = Date.now() + ((opts && opts.timeoutMs) || 180000);
  let sent = '', finished = false, got = false;
  while (Date.now() < deadline) {
    let r;
    try {
      r = await apiReq(a, 'GET', '/v1/conversations/messages?conversationId=' + encodeURIComponent(convId) + '&limit=5');
    } catch (e) { await sleep(500); continue; }
    if (r.status === 401) { await ensureJwt(a, true); continue; }
    const items = (r.json && r.json.data && r.json.data.items) || [];
    const mine = items.filter((m) => m && m.threadId === threadId && m.role === 'assistant');
    if (mine.length) {
      const m = mine[mine.length - 1];
      const txt = extractText(m);
      got = true;
      if (txt.length > sent.length) {
        const delta = txt.slice(sent.length);
        sent = txt;
        if (delta && onDelta) onDelta(delta);
      }
      if (m.isFinal === true && m.state === 'completed') { finished = true; break; }
    }
    await sleep(got ? 250 : 300);
  }
  return { text: sent, finished };
}

function estimateTokens(text) { return Math.max(1, Math.round(String(text || '').length / 4)); }

async function handleChat(req, res, body, ctx) {
  const started = Date.now();
  const userV2Id = ctx && ctx.userV2Id;
  const acct = loadAccount(userV2Id);
  const optionId = resolveOption(body && body.model);
  const model = (body && body.model) || 'todayai-deepseek';

  const hasTools = !!(body && Array.isArray(body.tools) && body.tools.length);
  let content = '';
  let toolNames = [];
  try {
    if (hasTools) {
      // 干净形式：协议提示由 toolbridge 注入到最后一条 user 里（实践验证遵循度最高；
      // 额外追加"忽略历史/硬性要求"等元指令会让上游模型判定为 prompt injection 而拒绝执行）
      const up = toolbridge.buildUpstreamMessages(body.messages, body.tools);
      toolNames = up.toolNames || [];
      content = lastUserOnly(up.messages);
    } else {
      content = buildThreadContent(body.messages);
    }
  } catch (e) { return sendJson(res, 400, { error: { message: e.message, type: 'invalid_request_error' } }); }

  try {
    await ensureModel(acct, optionId);
    const sent = await postMessage(acct, content);

    if (body && body.stream === true) {
      res.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache', connection: 'keep-alive', 'x-accel-buffering': 'no'
      });
      const id = 'chatcmpl-' + crypto.randomBytes(12).toString('hex');
      const created = Math.floor(Date.now() / 1000);
      const emit = (delta, finish) => {
        res.write('data: ' + JSON.stringify({ id, object: 'chat.completion.chunk', created, model, choices: [{ index: 0, delta, finish_reason: finish || null }] }) + '\n\n');
      };
      emit({ role: 'assistant', content: '' }, null);
      if (!hasTools) {
        const r = await pollReply(acct, sent.threadId, (delta) => emit({ content: delta }, null), { timeoutMs: 180000 });
        if (!r.text) emit({ content: '（上游未返回内容）' }, null);
        emit({}, 'stop');
        res.write('data: [DONE]\n\n');
        res.end();
        log('stream done', model, 'acct=' + acct.source, 'chars=' + (r.text || '').length, (Date.now() - started) + 'ms');
        return;
      }
      // 带 tools：必须看全文才能解析工具调用，故不逐段转发
      const rr = await pollReply(acct, sent.threadId, null, { timeoutMs: 180000 });
      const parsed = toolbridge.parseToolCalls(rr.text || '', toolNames);
      if (parsed.toolCalls && parsed.toolCalls.length) {
        parsed.toolCalls.forEach((tc, i) => {
          emit({ tool_calls: [{ index: i, id: tc.id, type: 'function', function: { name: tc.function.name, arguments: '' } }] }, null);
          emit({ tool_calls: [{ index: i, function: { arguments: tc.function.arguments } }] }, null);
        });
        emit({}, 'tool_calls');
      } else {
        emit({ content: parsed.cleaned || rr.text || '' }, null);
        emit({}, 'stop');
      }
      res.write('data: [DONE]\n\n');
      res.end();
      log('stream done(tools) ', model, 'acct=' + acct.source, 'toolCalls=' + ((parsed.toolCalls && parsed.toolCalls.length) || 0), (Date.now() - started) + 'ms');
      return;
    }

    const r = await pollReply(acct, sent.threadId, null, { timeoutMs: 180000 });
    const text = r.text || '';
    const usage = { prompt_tokens: estimateTokens(content), completion_tokens: estimateTokens(text), total_tokens: estimateTokens(content) + estimateTokens(text) };
    const cid = 'chatcmpl-' + crypto.randomBytes(12).toString('hex');

    if (hasTools) {
      const parsed = toolbridge.parseToolCalls(text, toolNames);
      const comp = toolbridge.buildCompletion({
        id: cid, model,
        content: parsed.cleaned || text,
        toolCalls: parsed.toolCalls || [],
        usage
      });
      comp.todayai = { threadId: sent.threadId, option: optionId, account: acct.source, finished: r.finished };
      log('chat done(tools)', model, 'acct=' + acct.source, 'toolCalls=' + ((parsed.toolCalls && parsed.toolCalls.length) || 0), (Date.now() - started) + 'ms');
      return sendJson(res, 200, comp);
    }

    log('chat done', model, 'acct=' + acct.source, 'chars=' + text.length, (Date.now() - started) + 'ms');
    return sendJson(res, 200, {
      id: cid,
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model,
      choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }],
      usage,
      todayai: { threadId: sent.threadId, option: optionId, account: acct.source, finished: r.finished }
    });
  } catch (e) {
    log('chat error:', e.message);
    if (!res.headersSent) {
      return sendJson(res, 502, { error: { message: 'todayai 上游失败: ' + e.message, type: 'upstream_error' } });
    }
    try { res.write('data: ' + JSON.stringify({ error: { message: e.message } }) + '\n\n'); res.write('data: [DONE]\n\n'); res.end(); } catch (e2) {}
  }
}

// ---------------- 账号额度（用户中心展示） ----------------
async function usage(userV2Id) {
  const a = loadAccount(userV2Id);
  const r = await apiReq(a, 'GET', '/v1/pricing/status');
  const st = r.json && r.json.data && r.json.data.status;
  if (!st) throw new Error('上游未返回 status: HTTP ' + r.status + ' ' + String(r.text || '').slice(0, 140));
  const u = st.usage || {};
  return {
    account: a.source,
    label: a.label || '',
    plan: st.plan || '',
    accessSource: st.accessSource || '',
    serviceState: st.serviceState || '',
    entitlementEndsAt: st.entitlementEndsAt || '',
    currentPeriodEndAt: st.currentPeriodEndAt || '',
    selectedOption: (st.modelOptions && st.modelOptions.selectedOptionId) || a.selectedOption || '',
    models: (st.modelOptions && Array.isArray(st.modelOptions.options)) ? st.modelOptions.options.map((o) => ({ id: o.id, title: (o.display && o.display.title) || o.id, disabled: !!o.disabled })) : [],
    usage: {
      progressText: u.progressText || '',
      resetAt: u.resetAt || '',
      items: (u.breakdown && Array.isArray(u.breakdown.items) ? u.breakdown.items : []).map((i) => ({
        key: i.key, usedPercent: i.usedPercent, title: (i.display && i.display.title) || i.key
      }))
    }
  };
}

function sendJson(res, code, obj) {
  const buf = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'content-length': buf.length });
  res.end(buf);
}

// 绑定后让缓存失效，立即用新账号
function invalidate(userV2Id) { ACCOUNTS.delete(acctKeyFor(userV2Id)); ACCOUNTS.delete('global'); }

module.exports = {
  configured, isTodayModel, publicModels, listModels, handleChat,
  ensureJwt, ensureModel, resolveOption,
  sendOtp, verifyLogin, invalidate, loadAccount, usage
};
