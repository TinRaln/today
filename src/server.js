/**
 * your-domain.example.com —— TodayAI 独立站点（面板 + API Key 网关）
 *
 * 结构：
 *   浏览器/客户端  →  本服务(7867)  →  todayai.js  →  todayai.cn / api.todayai.cn
 *
 * 职责：
 *   1. 面板登录（管理员口令 + 签名 session cookie）
 *   2. 账号池管理（代理 upstream2api 的 /admin/api/*，附加 ADMIN_TOKEN）
 *   3. 一键签到（批量刷新所有账号额度）
 *   4. API Key 分发（多 Key，各自可禁用，记录用量）
 *   5. /v1/* 网关转发（用我们的 Key 换上游的 UPSTREAM_API_KEY，流式透传）
 *
 * 依赖：仅 Node 内置模块，无 npm 依赖。
 */

'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const toolbridge = require('./toolbridge');
const v2db = require('./v2db');
const v2routes = require('./v2routes');
const upstreamDirect = require('./upstream-direct');
const upstreamAccount = require('./upstream-account-node');
const todayai = require('./todayai');

// ==================== 配置 ====================

const PORT         = Number(process.env.PORT || 7867);
const UPSTREAM     = process.env.UPSTREAM || 'http://127.0.0.1:7868';
const UPSTREAM_KEY    = process.env.UPSTREAM_API_KEY || '';
const ADMIN_TOKEN  = process.env.ADMIN_TOKEN || '';
const ADMIN_PASS   = process.env.ADMIN_PASS || '';
const SESSION_SEC  = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

const DATA_DIR   = path.join(__dirname, 'data');
const KEYS_FILE  = path.join(DATA_DIR, 'keys.json');
const STATS_FILE = path.join(DATA_DIR, 'stats.json');

fs.mkdirSync(DATA_DIR, { recursive: true });

// ==================== 简易存储 ====================

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return fallback;
  }
}

let writeLock = Promise.resolve();
function writeJson(file, data) {
  // 串行化写入，避免并发覆盖
  writeLock = writeLock.then(() => new Promise((resolve) => {
    const tmp = file + '.tmp';
    fs.writeFile(tmp, JSON.stringify(data, null, 2), (err) => {
      if (!err) {
        try { fs.renameSync(tmp, file); } catch (e) { /* ignore */ }
      }
      resolve();
    });
  }));
  return writeLock;
}

let keys  = readJson(KEYS_FILE, []);   // [{key,label,enabled,createdAt,lastUsedAt,calls}]
let stats = readJson(STATS_FILE, { total: 0, byKey: {} });

// ==================== session ====================

function sign(payload) {
  const h = crypto.createHmac('sha256', SESSION_SEC).update(payload).digest('base64url');
  return payload + '.' + h;
}

function verify(token) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const idx = token.lastIndexOf('.');
  const payload = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  const expect = crypto.createHmac('sha256', SESSION_SEC).update(payload).digest('base64url');
  if (sig.length !== expect.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data.exp || data.exp < Date.now()) return null;
    return data;
  } catch (e) {
    return null;
  }
}

function makeSession() {
  const payload = Buffer.from(JSON.stringify({
    u: 'admin',
    exp: Date.now() + 3650 * 24 * 3600 * 1000
  })).toString('base64url');
  return sign(payload);
}

function getSession(req) {
  const cookie = req.headers.cookie || '';
  const m = cookie.match(/(?:^|;\s*)upstream_sess=([^;]+)/);
  return m ? verify(decodeURIComponent(m[1])) : null;
}

// ==================== 工具 ====================

function send(res, code, body, headers) {
  const h = Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  }, headers || {});
  res.writeHead(code, h);
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

function readBody(req, limit = 2 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function clientIp(req) {
  return req.socket.remoteAddress || '';
}

// ==================== 上游调用 ====================

function upstreamRequest(method, pathname, body, extraHeaders, timeoutMs) {
  return new Promise((resolve, reject) => {
    const url = new URL(UPSTREAM);
    const headers = Object.assign({
      'Host': url.host,
      'X-Admin-Token': ADMIN_TOKEN
    }, extraHeaders || {});

    let payload = null;
    if (body !== undefined && body !== null) {
      payload = Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body));
      headers['Content-Type'] = headers['Content-Type'] || 'application/json';
      headers['Content-Length'] = payload.length;
    }

    const req = http.request({
      host: url.hostname,
      port: url.port,
      path: pathname,
      method,
      headers,
      timeout: timeoutMs || 30000
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let parsed = null;
        try { parsed = JSON.parse(raw); } catch (e) { parsed = null; }
        resolve({ status: res.statusCode, headers: res.headers, raw, json: parsed });
      });
    });

    req.on('timeout', () => { req.destroy(new Error('upstream timeout')); });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// ==================== Upstream 官方接口（手机号登录） ====================

const UPSTREAM_WEB = 'https://upstream.xunfei.cn/web';

function upstreamRequest(method, pathname, body, cookie) {
  return new Promise((resolve, reject) => {
    const payload = body ? Buffer.from(JSON.stringify(body)) : null;
    const headers = {
      'Content-Type': 'application/json;charset=UTF-8',
      'Origin': 'https://upstream.xunfei.cn',
      'Referer': 'https://upstream.xunfei.cn/web/login',
      'Accept': 'application/json, text/plain, */*',
      'Accept-Language': 'zh-CN,zh;q=0.9',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
    };
    if (payload) headers['Content-Length'] = payload.length;
    if (cookie) headers['Cookie'] = cookie;

    const req = https.request({
      host: 'upstream.xunfei.cn',
      port: 443,
      path: pathname,
      method,
      headers,
      timeout: 20000
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(raw); } catch (e) { json = null; }
        resolve({ status: res.statusCode, headers: res.headers, json, raw });
      });
    });

    req.on('timeout', () => req.destroy(new Error('upstream 请求超时')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// ==================== 路由：面板 API ====================

async function handleApi(req, res, pathname) {
  const sess = getSession(req);
  if (!sess) return send(res, 401, { ok: false, msg: '未登录' });

  const m = req.method;

  // ---- Upstream 手机号登录 ----
  if (pathname === '/api/upstream/sms-code' && m === 'POST') {
    const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
    const phone = String(body.phone || '').trim();
    if (!/^1[3-9]\d{9}$/.test(phone)) {
      return send(res, 400, { ok: false, msg: '手机号格式不正确' });
    }
    const r = await upstreamRequest('POST', '/web/api/auth/sms-code', { phone });
    if (r.json && r.json.success) {
      return send(res, 200, { ok: true, messageId: r.json.data && r.json.data.messageId });
    }
    return send(res, r.status === 200 ? 400 : r.status, {
      ok: false,
      msg: (r.json && (r.json.error || r.json.message)) || '发送验证码失败'
    });
  }

  if (pathname === '/api/upstream/login' && m === 'POST') {
    const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
    const phone      = String(body.phone || '').trim();
    const code       = String(body.code || '').trim();
    const messageId  = String(body.messageId || '');

    if (!/^1[3-9]\d{9}$/.test(phone)) return send(res, 400, { ok: false, msg: '手机号格式不正确' });
    if (!code) return send(res, 400, { ok: false, msg: '请输入验证码' });

    // 选号规则：显式指定 > 按手机号后4位命中已有账号 > 新建
    // （绝不能 fallback 到「第一个账号」，否则会把别人的凭证覆盖掉）
    const phoneTail = String(phone).replace(/\D/g, '').slice(-4);
    let accountId = String(body.accountId || '');

    try {
      const list = await upstreamRequest('GET', '/admin/api/accounts');
      const accs = (list.json && list.json.accounts) || [];
      const labels = getAccountLabels();

      const explicitOk = accountId && accs.some((a) => a.id === accountId);

      if (!explicitOk) {
        // 找一个标签等于本手机号后4位的账号，同时兼容上游自身的 label
        const matched = accs.find((a) => {
          const id = a.id || '';
          const lab = String(labels[id] || a.label || '').trim();
          return lab === phoneTail;
        });

        if (matched) {
          accountId = matched.id;
        } else {
          const created = await upstreamRequest('POST', '/admin/api/accounts', { label: phoneTail });
          accountId = (created.json && created.json.account && created.json.account.id) || '';
          if (!accountId) {
            return send(res, 500, { ok: false, msg: '创建账号失败: ' + (created.raw || '').slice(0, 120) });
          }
        }
      }
    } catch (e) {
      return send(res, 502, { ok: false, msg: '无法连接上游账号池: ' + e.message });
    }

    const r = await upstreamRequest('POST', '/web/api/auth/login', {
      phone,
      code,
      messageId,
      channel: '',
      visitedId: '',
      deviceId: crypto.randomUUID()
    });

    if (!(r.json && r.json.success)) {
      return send(res, r.status === 200 ? 400 : r.status, {
        ok: false,
        msg: (r.json && (r.json.error || r.json.message)) || '登录失败，验证码可能已过期'
      });
    }

    // 提取 Set-Cookie
    const setCookie = r.headers['set-cookie'] || [];
    const cookie = setCookie.map((c) => String(c).split(';')[0]).join('; ');
    if (!cookie) {
      return send(res, 500, { ok: false, msg: '登录成功但未拿到 Cookie' });
    }

    // 写入 upstream2api 账号池
    let writeOk = false;
    let writeMsg = '';
    try {
      const w = await upstreamRequest('POST', `/admin/api/accounts/${encodeURIComponent(accountId)}/cookie`, { cookie });
      writeOk = w.status >= 200 && w.status < 300;
      writeMsg = (w.json && (w.json.msg || w.json.error)) || '';
    } catch (e) {
      writeMsg = e.message;
    }

    if (!writeOk) {
      return send(res, 502, { ok: false, msg: '登录成功，但写入账号池失败: ' + writeMsg });
    }

    // 账号显示名 = 手机号后 4 位
    setAccountLabel(accountId, phone);
    const tail = String(phone).replace(/\D/g, '').slice(-4);

    // 若一并提供了客户端 session，则同时落盘（签到/积分用）
    let sessBound = false;
    let sessMsg = '';
    const sess = String(body.session || '').trim();
    if (/^[a-f0-9]{32}$/i.test(sess)) {
      const p = await fetchAccountPoints(sess);
      if (p.ok) {
        await setAccountSession(accountId, sess);
        sessBound = true;
      } else {
        sessMsg = '（session 未通过校验，未绑定）';
      }
    }

    return send(res, 200, {
      ok: true,
      accountId,
      label: tail,
      sessionBound: sessBound,
      msg: '已绑定账号 ****' + tail + (sessBound ? '，凭证与 session 均已保存' : ' ' + sessMsg)
    });
  }

  // ---- 账号池 ----
  if (pathname === '/api/accounts' && m === 'GET') {
    const q3 = new URL(req.url, 'http://localhost').searchParams;
    const forcePoints = q3.get('fresh') === '1';
    const r = await upstreamRequest('GET', '/admin/api/accounts');
    if (r.json && Array.isArray(r.json.accounts)) {
      r.json.accounts = decorateAccounts(r.json.accounts);
      // 只读本地缓存（访问面板不查上游，点「刷额度」才刷新）
      for (const a of r.json.accounts) {
        const tri = readQuotaTriple(a.id);
        if (tri.quota !== undefined) {
          a.quota = tri.quota;
          a.totalConsumed = tri.consumed;
          a.accountPoints = {
            available: tri.available,
            daily: tri.daily,
            consumed: tri.consumed,
            balance: tri.balance
          };
        }
      }
    }
    return send(res, r.status, r.json || { ok: false, msg: '上游返回异常', raw: r.raw.slice(0, 300) });
  }

  if (pathname === '/api/accounts' && m === 'POST') {
    const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
    const r = await upstreamRequest('POST', '/admin/api/accounts', { label: body.label || '未命名' });
    return send(res, r.status, r.json || { ok: false, msg: '失败' });
  }

  if (pathname === '/api/refresh' && m === 'POST') {
    const r = await upstreamRequest('POST', '/admin/api/refresh', {});
    return send(res, r.status, r.json || { ok: false, msg: '刷新失败' });
  }

  let mm;
  if ((mm = pathname.match(/^\/api\/accounts\/([^/]+)\/enabled$/)) && m === 'POST') {
    const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
    const r = await upstreamRequest('POST', `/admin/api/accounts/${encodeURIComponent(mm[1])}/enabled`, { enabled: !!body.enabled });
    return send(res, r.status, r.json || { ok: false, msg: '失败' });
  }

  if ((mm = pathname.match(/^\/api\/accounts\/([^/]+)\/cookie$/)) && m === 'POST') {
    const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
    if (!body.cookie) return send(res, 400, { ok: false, msg: '缺少 cookie' });
    const r = await upstreamRequest('POST', `/admin/api/accounts/${encodeURIComponent(mm[1])}/cookie`, { cookie: body.cookie });
    return send(res, r.status, r.json || { ok: false, msg: '写入失败' });
  }

  if ((mm = pathname.match(/^\/api\/accounts\/([^/]+)\/refresh$/)) && m === 'POST') {
    const r = await upstreamRequest('POST', `/admin/api/accounts/${encodeURIComponent(mm[1])}/refresh`, {});
    return send(res, r.status, r.json || { ok: false, msg: '刷新失败' });
  }

  if ((mm = pathname.match(/^\/api\/accounts\/([^/]+)$/)) && m === 'DELETE') {
    const r = await upstreamRequest('DELETE', `/admin/api/accounts/${encodeURIComponent(mm[1])}`);
    return send(res, r.status, r.json || { ok: true });
  }

  // ---- Key 管理 ----
  if (pathname === '/api/keys' && m === 'GET') {
    return send(res, 200, { ok: true, keys, stats });
  }

  if (pathname === '/api/keys' && m === 'POST') {
    const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
    const key = 'lm-' + crypto.randomBytes(20).toString('hex');
    const item = {
      key,
      label: (body.label || '').slice(0, 60) || '未命名',
      enabled: true,
      createdAt: Date.now(),
      lastUsedAt: 0,
      calls: 0
    };
    keys.unshift(item);
    await writeJson(KEYS_FILE, keys);
    return send(res, 200, { ok: true, item });
  }

  if ((mm = pathname.match(/^\/api\/keys\/([^/]+)\/enabled$/)) && m === 'POST') {
    const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
    const k = keys.find((x) => x.key === mm[1]);
    if (!k) return send(res, 404, { ok: false, msg: 'Key 不存在' });
    k.enabled = !!body.enabled;
    await writeJson(KEYS_FILE, keys);
    return send(res, 200, { ok: true });
  }

  if ((mm = pathname.match(/^\/api\/keys\/([^/]+)$/)) && m === 'DELETE') {
    const before = keys.length;
    keys = keys.filter((x) => x.key !== mm[1]);
    await writeJson(KEYS_FILE, keys);
    return send(res, 200, { ok: keys.length < before });
  }

  // ---- 积分（客户端侧接口）----
  if (pathname === '/api/points' && m === 'GET') {
    // 只读本地缓存，不查上游（点「刷额度」才刷新）
    const sessions = getAccountSessions();
    const entries = Object.entries(sessions).filter(([, v]) => v);
    if (!entries.length) {
      return send(res, 200, { ok: false, msg: '尚未绑定任何客户端 session' });
    }

    const results = entries.map(([id]) => {
      const tri = readQuotaTriple(id);
      const ok = tri.available !== undefined;
      return ok
        ? { id, ok: true, availableBalance: tri.available, dailyBalance: tri.daily, balance: tri.balance, consumed: tri.consumed }
        : { id, ok: false, msg: '尚未刷额度（点「刷额度」拉取）' };
    });

    const good = results.filter((x) => x.ok);
    if (!good.length) {
      return send(res, 200, {
        ok: false,
        msg: (results[0] && results[0].msg) || '全部账号查询失败',
        needLogin: (results[0] && results[0].code) === '100002',
        accounts: results
      });
    }

    const sum = (k) => good.reduce((n, x) => n + (Number(x[k]) || 0), 0);
    const triples = entries.map(([id]) => readQuotaTriple(id)).filter((t) => t.quota !== undefined);
    const quotaSum = triples.reduce((n, t) => n + (Number(t.quota) || 0), 0);
    const consumedSum = triples.reduce((n, t) => n + (Number(t.consumed) || 0), 0);

    return send(res, 200, {
      ok: true,
      total: good.length,
      failed: results.length - good.length,
      quota: triples.length ? quotaSum : undefined,
      consumed: triples.length ? consumedSum : undefined,
      balance: sum('balance'),
      dailyBalance: sum('dailyBalance'),
      dailyConsumed: sum('dailyConsumed'),
      dailyQuota: sum('dailyQuota'),
      availableBalance: sum('availableBalance'),
      accounts: results.map((x) => ({
        id: x.id,
        ok: x.ok,
        available: x.availableBalance,
        daily: x.dailyBalance,
        consumed: x.dailyConsumed,
        balance: x.balance,
        msg: x.msg
      }))
    });
  }

  // ---- 签到（幂等，每日 5000）----
  if (pathname === '/api/points/checkin' && m === 'POST') {
    let body = {};
    try { body = JSON.parse((await readBody(req)).toString('utf8') || '{}'); } catch (e) { body = {}; }
    const sessions = getAccountSessions();
    const accId = String(body.accountId || '');
    // 指定账号优先；不指定则对所有已绑账号签到
    const targets = accId
      ? [[accId, sessions[accId]]]
      : Object.entries(sessions);

    if (!targets.length || !targets.some(([, v]) => v)) {
      return send(res, 200, { ok: false, msg: '该账号未绑定 session' });
    }

    const results = [];
    for (const [id, sess] of targets) {
      if (!sess) { results.push({ id, ok: false, msg: '未绑定 session' }); continue; }
      try {
        const r = await upstreamPointsRequest('/points/first-login', sess, 'POST', {});
        const code = r.json && r.json.code;
        if (code && code !== '000000') {
          results.push({ id, ok: false, code, msg: (r.json && r.json.desc) || '签到失败' });
          continue;
        }
        const d = (r.json && r.json.data) || {};
        results.push({
          id, ok: true,
          alreadyProcessed: !!d.alreadyProcessed,
          availableBalance: d.currentBalance,
          msg: d.alreadyProcessed ? '今日已签到' : '签到成功'
        });
        // 签到可能增加额度，顺手刷新额度三件套
        await fetchTotalConsumed(id, sess, true);
      } catch (e) {
        results.push({ id, ok: false, msg: e.message });
      }
    }

    const good = results.filter((x) => x.ok);
    const one = results[0];
    return send(res, 200, {
      ok: good.length > 0,
      results,
      alreadyProcessed: results.every((x) => x.alreadyProcessed),
      msg: good.length
        ? (good.length === results.length
            ? (results.every((x) => x.alreadyProcessed) ? '今日已签到' : '签到成功')
            : `${good.length}/${results.length} 个账号签到成功`)
        : (one && one.msg) || '签到失败'
    });
  }

  // ---- 绑定账号 session ----
  if (pathname === '/api/points/bind' && m === 'POST') {
    const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
    const accId = String(body.accountId || '');
    const sess = String(body.session || '').trim();
    if (!accId || !sess) return send(res, 400, { ok: false, msg: '缺少 accountId 或 session' });
    if (!/^[a-f0-9]{32}$/i.test(sess)) return send(res, 400, { ok: false, msg: 'session 格式不对（应为 32 位十六进制）' });

    // 先验证有效性再落盘
    const p = await fetchAccountPoints(sess);
    if (!p.ok) {
      return send(res, 200, { ok: false, msg: '该 session 无效或已过期: ' + (p.msg || '') });
    }
    await setAccountSession(accId, sess);
    return send(res, 200, { ok: true, points: p, msg: '绑定成功' });
  }

  // ---- 保存/更新 session ----
  if (pathname === '/api/points/session' && m === 'POST') {
    const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
    if (!body.session) return send(res, 400, { ok: false, msg: '缺少 session' });
    await saveUpstreamSession(String(body.session), { nickname: body.nickname || '' });
    return send(res, 200, { ok: true });
  }

  // ---- 积分流水 ----
  if (pathname === '/api/points/records' && m === 'GET') {
    const q2 = new URL(req.url, 'http://localhost').searchParams;
    const accId = q2.get('accountId') || '';
    const page = Number(q2.get('page') || 1);
    const sess = getAccountSessions()[accId] || getUpstreamSession();
    if (!sess) return send(res, 200, { ok: false, msg: '该账号未绑定 session' });
    try {
      const r = await fetchRecords(sess, page, 50);
      if (!r.ok) return send(res, 200, r);
      const cc = readJson(CONSUME_CACHE, {})[accId] || {};
      return send(res, 200, {
        ok: true, total: r.total, page, list: r.list,
        totalConsumed: cc.consumed
      });
    } catch (e) {
      return send(res, 200, { ok: false, msg: e.message });
    }
  }

  // ---- 刷新某账号累计消耗 ----
  if (pathname === '/api/points/consume' && m === 'POST') {
    const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
    const accId = String(body.accountId || '');
    const sess = getAccountSessions()[accId];
    if (!sess) return send(res, 200, { ok: false, msg: '该账号未绑定 session' });
    return send(res, 200, await fetchTotalConsumed(accId, sess, true));
  }

  // ---- 健康状态 ----
  if (pathname === '/api/health') {
    try {
      const r = await upstreamRequest('GET', '/health');
      return send(res, 200, { ok: true, upstream: r.json || r.raw });
    } catch (e) {
      return send(res, 200, { ok: false, upstream: null, msg: e.message });
    }
  }

  return send(res, 404, { ok: false, msg: '未知接口' });
}

// ==================== 登录 ====================

async function handleLogin(req, res) {
  const ip = clientIpOf(req);
  if (isIpBanned(ip)) {
    return send(res, 429, { ok: false, msg: '该 IP 因多次失败已被临时封禁' });
  }
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const pass = String(body.password || '');

  // 简单防爆破：同一 IP 1 分钟内仅 5 次
  const now = Date.now();
  loginFails[ip] = (loginFails[ip] || []).filter((t) => now - t < 60000);
  if (loginFails[ip].length >= 5) {
    return send(res, 429, { ok: false, msg: '尝试过于频繁，请 1 分钟后再试' });
  }

  const ok = ADMIN_PASS && pass.length === ADMIN_PASS.length &&
             crypto.timingSafeEqual(Buffer.from(pass), Buffer.from(ADMIN_PASS));

  if (!ok) {
    loginFails[ip].push(now);
    noteAuthResult(ip, false);
    return send(res, 401, { ok: false, msg: '密码错误' });
  }

  noteAuthResult(ip, true);
  const token = makeSession();
  send(res, 200, { ok: true }, {
    'Set-Cookie': `upstream_sess=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${3650 * 24 * 3600}`
  });
}

const loginFails = {};

// ==================== 网关转发 ====================

// 账号实际可用的模型（2026-10-26 逐个实测，与 Upstream 官方 /web/api/models 对齐）。
// 不可用：spark-x、spark-x2.6（MODEL_UNAVAILABLE 422）；deepseek-v4-flash-0731（上游已改名）
const ALLOWED_MODELS = [
  'DeepSeek-V4.1-Flash',
  'MiniMax-M3',
  'Kimi-k2.6',
  'qwen-3.8-max',
  'qwen3.8-flash',
  'qwen3.5-flash',
  'GLM-5.3-Flash',
  'doubao-seed-2.0-mini',
  'mimo-v2.5',
  'auto'
];
const ALLOWED_SET = new Set(ALLOWED_MODELS);

// ==================== 防御：Key 限流 + IP 封禁 ====================

// Key 速率限制（内存计数，重启清零；可用 env 覆盖）
const KEY_RATE_PER_MIN = Number(process.env.KEY_RATE_PER_MIN || 60);     // 每 Key 每分钟
const KEY_DAILY_LIMIT  = Number(process.env.KEY_DAILY_LIMIT || 2000);    // 每 Key 每日
const IP_FAIL_BAN      = Number(process.env.IP_FAIL_BAN || 5);            // 连续失败达此数（现直接永久拉黑）
    const IP_FAIL_BAN_PERM  = Number(process.env.IP_FAIL_BAN_PERM || 5);        // 阈值同左：失败 5 次即永久
const IP_BAN_MINUTES   = Number(process.env.IP_BAN_MINUTES || 10);

const keyRateMap = {};   // key -> [timestamp...]（近 60 秒）
const keyDailyMap = {};  // key -> {date, count}
const ipFailMap = {};    // ip -> [{t, ok}]
const ipBanMap = {};     // ip -> banUntil

function clientIpOf(req) {
  return req.headers['x-forwarded-for']
    ? String(req.headers['x-forwarded-for']).split(',')[0].trim()
    : (req.socket.remoteAddress || '');
}

// 永久黑名单：持久化到文件（重启不丢）
const BLOCKLIST_FILE = path.join(DATA_DIR, 'ip-blocklist.json');

function getBlocklist() {
  try { return JSON.parse(fs.readFileSync(BLOCKLIST_FILE, 'utf8')) || {}; }
  catch (e) { return {}; }
}

function isIpBanned(ip) {
  if (IP_WHITELIST.has(String(ip))) return false;   // 白名单永远放行
  // 永久黑名单
  if (getBlocklist()[ip]) return true;
  // 临时封禁
  const until = ipBanMap[ip];
  if (until && until > Date.now()) return true;
  if (until) delete ipBanMap[ip];
  return false;
}

function isIpPermanent(ip) {
  return !!getBlocklist()[ip];
}

function banIpPermanent(ip, reason) {
  const list = getBlocklist();
  list[ip] = { reason: reason || '恶意攻击', at: Date.now() };
  try {
    fs.writeFileSync(BLOCKLIST_FILE, JSON.stringify(list, null, 2));
  } catch (e) { /* ignore */ }
  console.log('[安全] 永久拉黑 IP:', ip, reason);
}

function banIp(ip, minutes = IP_BAN_MINUTES) {
  ipBanMap[ip] = Date.now() + minutes * 60 * 1000;
}

/** 记录一次鉴权结果（成功/失败），连续失败触发封禁 */
// 白名单：本机/服务器自身/运维 IP，永远不计数、不封禁
const IP_WHITELIST = new Set([
  '127.0.0.1', '::1', '::ffff:127.0.0.1',
  'YOUR_SERVER_IP',
  '113.122.200.204'
].concat((process.env.IP_WHITELIST || '').split(',').map((x) => x.trim()).filter(Boolean)));

function noteAuthResult(ip, ok) {
  if (IP_WHITELIST.has(String(ip))) return;   // 白名单不计数
  const arr = ipFailMap[ip] || (ipFailMap[ip] = []);
  const now = Date.now();
  arr.push({ t: now, ok });
  // 只保留最近 10 分钟
  while (arr.length && now - arr[0].t > 10 * 60 * 1000) arr.shift();
  if (!ok) {
    const fails = arr.filter((x) => !x.ok).length;
    // 直接永久拉黑（不再走临时封禁）
    if (fails >= IP_FAIL_BAN_PERM) {
      banIpPermanent(ip, '爆破/渗透：连续鉴权失败 ' + fails + ' 次');
      arr.length = 0;
    }
  }
}

/** Key 限流：返回 null=放行，字符串=被限的原因 */
function checkKeyRate(key) {
  const now = Date.now();
  // 每分钟
  const arr = keyRateMap[key] || (keyRateMap[key] = []);
  while (arr.length && now - arr[0] > 60 * 1000) arr.shift();
  if (arr.length >= KEY_RATE_PER_MIN) return '请求过于频繁（每分钟 ' + KEY_RATE_PER_MIN + ' 次上限）';
  arr.push(now);

  // 每日
  const d = new Date().toISOString().slice(0, 10);
  const daily = keyDailyMap[key] || (keyDailyMap[key] = { date: d, count: 0 });
  if (daily.date !== d) { daily.date = d; daily.count = 0; }
  if (daily.count >= KEY_DAILY_LIMIT) return '今日调用已达上限（' + KEY_DAILY_LIMIT + ' 次）';
  daily.count++;
  return null;
}

function findKey(raw) {
  const k = String(raw || '').trim();
  return keys.find((x) => x.key === k) || null;
}

function authGateway(req, res) {
  const ip = clientIpOf(req);

  // IP 封禁检查：一律返回永久拉黑格式
  if (isIpBanned(ip)) {
    send(res, 403, { '你的IP': '已被永久拉黑' });
    return null;
  }

  const auth = req.headers['authorization'] || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();

  if (!token) {
    noteAuthResult(ip, false);
    send(res, 401, { error: { message: '缺少 API Key（Authorization: Bearer <key>）', type: 'invalid_request_error' } });
    return null;
  }

  // v2：查多用户 DB（每用户专属 Key）
  if (v2db.udb) {
    const v2u = v2db.getUserByKey(token);
    if (v2u) {
      const rateErr = checkKeyRate(token);
      if (rateErr) {
        send(res, 429, { error: { message: rateErr, type: 'rate_limit_error' } });
        return null;
      }
      v2db.bumpKeyCalls(token);
      noteAuthResult(ip, true);
      return v2u;
    }
  }

  // 旧版：全局 lm- Key（管理员用）
  // v2：每用户专属 Key
  if (v2db.udb) {
    const v2u = v2db.getUserByKey(token);
    if (v2u) {
      const rateErr = checkKeyRate(token);
      if (rateErr) {
        send(res, 429, { error: { message: rateErr, type: 'rate_limit_error' } });
        return null;
      }
      v2db.bumpKeyCalls(token);
      noteAuthResult(ip, true);
      return v2u;
    }
  }

  const item = findKey(token);
  if (!item) {
    noteAuthResult(ip, false);
    send(res, 401, { error: { message: 'API Key 无效', type: 'invalid_request_error' } });
    return null;
  }
  if (!item.enabled) {
    noteAuthResult(ip, false);
    send(res, 403, { error: { message: 'API Key 已被禁用', type: 'invalid_request_error' } });
    return null;
  }

  // Key 限流
  const rateErr = checkKeyRate(item.key);
  if (rateErr) {
    send(res, 429, { error: { message: rateErr, type: 'rate_limit_error' } });
    return null;
  }

  noteAuthResult(ip, true);
  return item;
}

/** 从 item 里提取 user_id / apiKey（兼容 v2 的 {user,keyRow} 和旧版的扁平结构） */
function uidOf(item) {
  if (!item) return undefined;
  if (item.user_id) return item.user_id;
  if (item.user && item.user.id) return item.user.id;
  return undefined;
}
function keyOf(item) {
  if (!item) return undefined;
  if (item.key) return item.key;
  if (item.keyRow && item.keyRow.key) return item.keyRow.key;
  return undefined;
}

function recordUsage(item) {
  item.calls = (item.calls || 0) + 1;
  item.lastUsedAt = Date.now();
  stats.total = (stats.total || 0) + 1;
  stats.byKey[item.key] = (stats.byKey[item.key] || 0) + 1;
  writeJson(KEYS_FILE, keys);
  writeJson(STATS_FILE, stats);
}

/** 从响应文本里解析 usage（兼容非流式 JSON 和流式 SSE 末帧） */
function parseUsageFromText(text) {
  if (!text) return null;
  // 流式：逐行找 data: 里的 usage
  const lines = text.split('\n');
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i].trim();
    if (!line.startsWith('data:')) continue;
    const payload = line.slice(5).trim();
    if (!payload || payload === '[DONE]') continue;
    try {
      const obj = JSON.parse(payload);
      if (obj && obj.usage) return obj.usage;
    } catch (e) { /* continue */ }
  }
  // 非流式：整体 JSON
  try {
    const obj = JSON.parse(text);
    if (obj && obj.usage) return obj.usage;
  } catch (e) { /* ignore */ }
  return null;
}

/** 把请求转发到上游（可传入已读取的 body）。返回 Promise，成功与否由调用方决定是否重试。 */
/**
 * 以「流式」方式调用上游，边收 SSE 边聚合成完整结果。
 *
 * 为什么必须这样：上游对「长时间无响应的非流式请求」约 60 秒就返回 504，
 * 而同一模型的流式调用能跑几分钟。所以凡是内部需要完整结果的场景
 * （非流式请求、工具调用判定），都改用流式调、聚合后再对外呈现。
 *
 * @returns {Promise<{content, toolCalls, finishReason, usage, id, model}>}
 */
function callUpstreamStreaming(upstreamBody, timeoutMs = 300000) {
  return new Promise((resolve, reject) => {
    const url = new URL(UPSTREAM);
    const payload = Buffer.from(JSON.stringify(Object.assign({}, upstreamBody, { stream: true })));

    const acc = {
      content: '',
      toolCalls: new Map(),
      finishReason: null,
      usage: null,
      id: null,
      model: null,
      chunks: 0
    };

    const req = http.request({
      host: url.hostname,
      port: url.port,
      path: '/v1/chat/completions',
      method: 'POST',
      headers: {
        'Host': url.host,
        'Authorization': `Bearer ${UPSTREAM_KEY}`,
        'Content-Type': 'application/json',
        'Accept': 'text/event-stream',
        'Content-Length': payload.length
      },
      timeout: timeoutMs
    }, (res) => {
      if (res.statusCode >= 400) {
        const bufs = [];
        res.on('data', (c) => bufs.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(bufs).toString('utf8');
          let parsed = null;
          try { parsed = JSON.parse(raw); } catch (e) { /* ignore */ }
          const err = new Error('upstream ' + res.statusCode);
          err.status = res.statusCode;
          err.body = parsed || raw.slice(0, 500);
          reject(err);
        });
        return;
      }

      let buf = '';
      let finished = false;
      const finish = () => {
        if (finished) return;
        finished = true;
        resolve(acc);
      };

      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        buf += chunk;
        let nl;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          if (!line || !line.startsWith('data:')) continue;
          const data = line.slice(5).trim();
          if (data === '[DONE]') { finish(); return; }
          let obj;
          try { obj = JSON.parse(data); } catch (e) { continue; }
          acc.chunks++;
          if (obj.id) acc.id = obj.id;
          if (obj.model) acc.model = obj.model;
          if (obj.usage) acc.usage = obj.usage;

          const ch = (obj.choices || [])[0];
          if (!ch) continue;
          if (ch.finish_reason) acc.finishReason = ch.finish_reason;

          const d = ch.delta || {};
          if (typeof d.content === 'string' && d.content) acc.content += d.content;

          if (Array.isArray(d.tool_calls)) {
            for (const tc of d.tool_calls) {
              const i = typeof tc.index === 'number' ? tc.index : 0;
              if (!acc.toolCalls.has(i)) {
                acc.toolCalls.set(i, {
                  id: tc.id || '',
                  type: 'function',
                  function: { name: '', arguments: '' }
                });
              }
              const e = acc.toolCalls.get(i);
              if (tc.id) e.id = tc.id;
              if (tc.function && tc.function.name) e.function.name = tc.function.name;
              if (tc.function && typeof tc.function.arguments === 'string') {
                e.function.arguments += tc.function.arguments;
              }
            }
          }
        }
      });
      res.on('end', finish);
      res.on('error', (e) => { if (!finished) reject(e); });
    });

    req.on('timeout', () => { try { req.destroy(); } catch (e) {} reject(new Error('upstream timeout')); });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

/** 把聚合结果转成 OpenAI 非流式响应体 */
function aggregatedToCompletion(acc, fallbackModel, toolCallsOverride) {
  const toolCalls = toolCallsOverride !== undefined
    ? toolCallsOverride
    : Array.from(acc.toolCalls.values()).filter((t) => t.function.name);

  const message = {
    role: 'assistant',
    content: toolCalls.length ? null : (acc.content || '')
  };
  if (toolCalls.length) message.tool_calls = toolCalls;

  return {
    id: acc.id || 'chatcmpl-' + Date.now().toString(36),
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: acc.model || fallbackModel || 'upstream',
    choices: [{
      index: 0,
      message,
      finish_reason: toolCalls.length ? 'tool_calls' : (acc.finishReason || 'stop')
    }],
    usage: acc.usage || { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
  };
}

function forwardOnce(req, res, preBody) {
  return new Promise((resolve) => {
    const url = new URL(UPSTREAM);
    const headers = Object.assign({}, req.headers, {
      host: url.host,
      authorization: `Bearer ${UPSTREAM_KEY}`,
      'x-forwarded-for': req.headers['x-forwarded-for'] || clientIp(req)
    });
    delete headers['cookie'];
    if (preBody) {
      headers['content-length'] = preBody.length;
      delete headers['transfer-encoding'];
    }

    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };

    const up = http.request({
      host: url.hostname,
      port: url.port,
      path: req.url,
      method: req.method,
      headers,
      timeout: 300000
    }, (upRes) => {
      // 上游 5xx 且尚未给客户端发送任何东西 → 可安全重试
      if (upRes.statusCode >= 500 && !res.headersSent) {
        upRes.resume();
        return done({ ok: false, status: upRes.statusCode });
      }
      if (res.headersSent) { upRes.resume(); return done({ ok: true }); }   // 已发过头，丢弃
      res.writeHead(upRes.statusCode, upRes.headers);
      // 旁路收集响应尾部，用于解析 usage（只留最后 8KB，usage 在末尾）
      let tail = '';
      const origWrite = res.write.bind(res);
      res.write = function (chunk, ...rest) {
        try {
          const t = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk);
          tail = (tail + t).slice(-8192);
        } catch (e) { /* ignore */ }
        return origWrite(chunk, ...rest);
      };
      upRes.pipe(res);
      upRes.on('end', () => {
        res.write = origWrite;
        done({ ok: true, usage: parseUsageFromText(tail) });
      });
      upRes.on('error', () => {
        res.write = origWrite;
        done({ ok: true, usage: parseUsageFromText(tail) });
      });
    });

    up.on('timeout', () => { try { up.destroy(); } catch (e) {} done({ ok: false, error: 'timeout' }); });
    up.on('error', (e) => done({ ok: false, error: e.message }));

    if (preBody) {
      up.end(preBody);
    } else {
      req.pipe(up);
    }
  });
}

/**
 * 带重试的转发。
 * 上游偶发 ConnectTimeout（表现为 500），重试即可恢复；一旦响应头已发给客户端就不能再试。
 */
async function forward(req, res, preBody) {
  let last = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    last = await forwardOnce(req, res, preBody);
    if (last.ok || res.headersSent) return last;
    if (attempt < 3) {
      await new Promise((r) => setTimeout(r, 300 * attempt));
    }
  }
  if (!res.headersSent) {
    send(res, 502, {
      error: {
        message: '上游连续失败（已重试 3 次）：' + (last && (last.status || last.error) || 'unknown'),
        type: 'server_error'
      }
    });
  }
}

// ==================== Upstream 客户端侧积分接口 ====================

const UPSTREAMAD = 'https://upstreamad.xunfei.cn/api/v1';
const SESSION_FILE = path.join(DATA_DIR, 'upstream-session.json');

function getUpstreamSession() {
  const d = readJson(SESSION_FILE, {});
  return d && d.session ? d.session : '';
}

function saveUpstreamSession(session, extra) {
  return writeJson(SESSION_FILE, Object.assign({ session, savedAt: Date.now() }, extra || {}));
}

// 账号 -> 客户端 session 绑定（签到/积分用；与 Web cookie 是两套凭证）
const ACC_SESSIONS_FILE = path.join(DATA_DIR, 'account-sessions.json');

function getAccountSessions() {
  return readJson(ACC_SESSIONS_FILE, {});
}

function setAccountSession(accountId, session) {
  if (!accountId || !session) return;
  const m = getAccountSessions();
  m[accountId] = String(session).trim();
  writeJson(ACC_SESSIONS_FILE, m);
}

/** 查某个账号的积分；失败返回 {ok:false} */
const _pointsCache = {};   // session -> {at, data}
const POINTS_CACHE_MS = 60 * 1000;   // 积分缓存 60 秒

async function fetchAccountPoints(session, force = false) {
  if (!session) return { ok: false, msg: '未绑定 session' };

  const hit = _pointsCache[session];
  if (!force && hit && Date.now() - hit.at < POINTS_CACHE_MS) {
    return Object.assign({ ok: true, cached: true }, hit.data);
  }

  try {
    // 用签到接口取数：它幂等，且返回字段最全（含 dailyConsumed / dailyQuota）
    const r = await upstreamPointsRequest('/points/first-login', session, 'POST', {});
    const code = r.json && r.json.code;
    if (code && code !== '000000') {
      return { ok: false, code, msg: (r.json && r.json.desc) || '查询失败' };
    }
    const d = (r.json && r.json.data) || {};
    const quota = Number(d.dailyQuota) || 0;
    const dailyBal = Number(d.dailyBalance) || 0;
    const consumed = (d.dailyConsumed === undefined || d.dailyConsumed === null)
      ? Math.max(0, quota - dailyBal)
      : Number(d.dailyConsumed);
    const out = {
      dailyBalance: dailyBal,
      dailyConsumed: consumed,
      dailyQuota: quota,
      balance: d.permanentBalance !== undefined ? Number(d.permanentBalance) : undefined,
      availableBalance: d.currentBalance !== undefined ? Number(d.currentBalance) : undefined,
      alreadyProcessed: !!d.alreadyProcessed
    };
    // 顺带把 available/daily/balance 也写进 CONSUME_CACHE（供面板只读显示）
    try {
      const c = readJson(CONSUME_CACHE, {});
      const rec = c[accountId] || {};
      rec.available = out.availableBalance;
      rec.daily = out.dailyBalance;
      rec.balance = out.balance;
      c[accountId] = rec;
      writeJson(CONSUME_CACHE, c);
    } catch (e) { /* 写缓存失败不影响主流程 */ }
    _pointsCache[session] = { at: Date.now(), data: out };
    return Object.assign({ ok: true }, out);
  } catch (e) {
    return { ok: false, msg: e.message };
  }
}

// ==================== 账号统计与流水 ====================

const CONSUME_CACHE = path.join(DATA_DIR, 'account-consume.json');

/** 拉某个账号的积分流水（单页） */
async function fetchRecords(session, page = 1, size = 50) {
  const qs = `?record_type=all&pageNo=${page}&pageSize=${size}`;
  const r = await upstreamPointsRequest('/points/records' + qs, session);
  const code = r.json && r.json.code;
  if (code && code !== '000000') {
    return { ok: false, code, msg: (r.json && r.json.desc) || '查询失败' };
  }
  const d = (r.json && r.json.data) || {};
  return {
    ok: true,
    total: d.total || 0,
    list: d.list || [],
    balance: d.balance,
    dailyBalance: d.dailyBalance,
    availableBalance: d.availableBalance
  };
}

/** 累计消耗：遍历全部流水求和（debit 加、credit 减），结果缓存 30 分钟 */
async function fetchTotalConsumed(accountId, session, force = false) {
  const cache = readJson(CONSUME_CACHE, {});
  const hit = cache[accountId];
  if (!force && hit && Date.now() - hit.at < 30 * 60 * 1000) {
    return { ok: true, consumed: hit.consumed, total: hit.total, cached: true };
  }
  // 额度基准法：一次额度查询即可，不遍历流水（避免高频请求被上游风控）
  //   额度 quota     = 基准，首次记录后固定
  //   可用 available = 当前可用
  //   已用 consumed  = quota - available
  try {
    const p = await fetchAccountPoints(session);
    if (!p.ok) return { ok: false, msg: p.msg };
    const cur = Number(p.availableBalance) || 0;
    const rec = cache[accountId] || {};

    // 首次记录额度基准
    if (rec.quota === undefined) {
      rec.quota = cur;
    } else if (cur > rec.quota) {
      // 额度涨了（签到/任务/充值）：说明是新增而非消耗，同步抬高基准
      rec.quota = cur;
    }

    rec.available = cur;
    rec.consumed = Math.max(0, rec.quota - cur);
    rec.at = Date.now();

    cache[accountId] = rec;
    writeJson(CONSUME_CACHE, cache);
    return { ok: true, quota: rec.quota, available: cur, consumed: rec.consumed, cached: false };
  } catch (e) {
    return { ok: false, msg: e.message };
  }
}

/** 读缓存的额度信息（不请求上游） */
function readQuotaTriple(accountId) {
  const c = readJson(CONSUME_CACHE, {})[accountId] || {};
  return {
    quota: c.quota,
    consumed: c.consumed,
    available: c.available,
    daily: c.daily,
    balance: c.balance
  };
}

// 账号显示名映射：accountId -> 手机号后 4 位（upstream2api 无改 label 接口）
const LABELS_FILE = path.join(DATA_DIR, 'account-labels.json');

function getAccountLabels() {
  return readJson(LABELS_FILE, {});
}

function setAccountLabel(accountId, phone) {
  if (!accountId || !phone) return;
  const digits = String(phone).replace(/\D/g, '');
  const tail = digits.slice(-4);
  if (!tail) return;
  const m = getAccountLabels();
  m[accountId] = tail;
  writeJson(LABELS_FILE, m);
}

/** 把映射合并进上游返回的账号列表 */
function decorateAccounts(accounts) {
  const labels = getAccountLabels();
  return (accounts || []).map((a) => {
    const id = a.id || a.account_id || a.accountId || '';
    const tail = labels[id];
    return tail ? Object.assign({}, a, { displayLabel: tail }) : a;
  });
}

/** 调 upstreamad 接口：必须三头齐全 + 双写 token，缺 traceparent 会挂到超时 */
function upstreamPointsRequest(pathname, session, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const tp = '00-' + crypto.randomBytes(16).toString('hex')
             + '-' + crypto.randomBytes(8).toString('hex') + '-01';
    const payload = body ? Buffer.from(JSON.stringify(body)) : null;
    const headers = {
      'Authorization': 'Bearer ' + session,
      'token': session,
      'traceparent': tp,
      'upstream-version': '0.9.38',
      'Accept': 'application/json'
    };
    if (payload) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = payload.length;
    }

    const req = https.request({
      host: 'upstreamad.xunfei.cn',
      port: 443,
      path: '/api/v1' + pathname,
      method,
      headers,
      timeout: 25000
    }, (res) => {
      const bufs = [];
      res.on('data', (c) => bufs.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(bufs).toString('utf8');
        let json = null;
        try { json = JSON.parse(raw); } catch (e) { /* ignore */ }
        resolve({ status: res.statusCode, json, raw });
      });
    });
    req.on('timeout', () => { req.destroy(new Error('upstreamad timeout')); });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// ==================== upstreamad 直连快通道 ====================
// upstreamad.xunfei.cn/api/v1 是原生 OpenAI 兼容接口（session 鉴权，首字 ~0.7s），
// 优先走它；失败时由调用方回退到 upstream2api。

const UPSTREAMAD_CHAT = 'https://upstreamad.xunfei.cn/api/v1/chat/completions';

function upstreamadHeaders(session) {
  return {
    'Authorization': 'Bearer ' + session,
    'token': session,
    'traceparent': '00-' + crypto.randomBytes(16).toString('hex') + '-' + crypto.randomBytes(8).toString('hex') + '-01',
    'upstream-version': '0.9.38',
    'Accept': 'text/event-stream'
  };
}

/** 取一个可用的客户端 session（账号绑定优先，兼容旧的单 session） */
function pickUpstreamSession() {
  const sessions = getAccountSessions();
  const entries = Object.entries(sessions).filter(([, v]) => v);
  if (entries.length) return entries[0][1];
  return getUpstreamSession();
}

/** 非流式：缓冲完整响应后返回 */
function upstreamadChat(body, session, timeoutMs = 120000) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(body));
    const headers = Object.assign({ 'Content-Type': 'application/json', 'Content-Length': payload.length }, upstreamadHeaders(session));
    const req = https.request({
      host: 'upstreamad.xunfei.cn', port: 443,
      path: '/api/v1/chat/completions', method: 'POST', headers, timeout: timeoutMs
    }, (res) => {
      const bufs = [];
      res.on('data', (c) => bufs.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(bufs).toString('utf8');
        let json = null;
        try { json = JSON.parse(raw); } catch (e) { /* ignore */ }
        resolve({ status: res.statusCode, json, raw });
      });
    });
    req.on('timeout', () => req.destroy(new Error('upstreamad timeout')));
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

/** 流式：把请求转发到 upstreamad 并 pipe 回客户端（保首字速度） */
function upstreamadStream(req, res, body, session, timeoutMs = 300000) {
  return new Promise((resolve, reject) => {
    // 注入 include_usage，让上游末尾带 usage（统计 token）
    if (body && body.stream === true) {
      body.stream_options = Object.assign({}, body.stream_options, { include_usage: true });
    }
    const payload = Buffer.from(JSON.stringify(body));
    const headers = Object.assign({ 'Content-Type': 'application/json', 'Content-Length': payload.length }, upstreamadHeaders(session));

    const up = https.request({
      host: 'upstreamad.xunfei.cn', port: 443,
      path: '/api/v1/chat/completions', method: 'POST', headers, timeout: timeoutMs
    }, (upRes) => {
      // upstreamad 非 2xx：交给调用方决定是否回退
      if (upRes.statusCode >= 400) {
        const bufs = [];
        upRes.on('data', (c) => bufs.push(c));
        upRes.on('end', () => {
          reject({ status: upRes.statusCode, body: Buffer.concat(bufs).toString('utf8') });
        });
        return;
      }
      if (res.headersSent) { upRes.resume(); return resolve({ ok: true }); }   // 已发过头，丢弃
      res.writeHead(upRes.statusCode, upRes.headers);
      let tail = '';
      const origWrite = res.write.bind(res);
      res.write = function (chunk, ...rest) {
        try {
          const t = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk);
          tail = (tail + t).slice(-8192);
        } catch (e) { /* ignore */ }
        return origWrite(chunk, ...rest);
      };
      upRes.pipe(res);
      upRes.on('end', () => { res.write = origWrite; resolve({ ok: true, usage: parseUsageFromText(tail) }); });
      upRes.on('error', () => { res.write = origWrite; resolve({ ok: true, usage: parseUsageFromText(tail) }); });
    });

    up.on('timeout', () => { try { up.destroy(); } catch (e) {} reject(new Error('upstreamad stream timeout')); });
    up.on('error', reject);
    up.write(payload);
    up.end();
  });
}

/** 回退到 upstream2api 路径（原逻辑） */
async function fallbackToOld(req, res, body, item, raw, wasTruncated) {
  if (Array.isArray(body.tools) && body.tools.length > 0) {
    return handleToolChat(req, res, body, item, wasTruncated);
  }
  if (Array.isArray(body.functions) && body.functions.length > 0) {
    body.tools = body.functions.map((f) => ({ type: 'function', function: f }));
    return handleToolChat(req, res, body, item, wasTruncated);
  }
  // 流式请求注入 include_usage，让上游末尾返回 usage（用于统计 token）
  if (body.stream === true) {
    body.stream_options = Object.assign({}, body.stream_options, { include_usage: true });
    raw = Buffer.from(JSON.stringify(body));
  }
  if (!body.stream) {
    return handleNonStreamAggregated(req, res, body, item, wasTruncated);
  }
  recordUsage(item);
  const fwd = await forward(req, res, raw);
  try { if (fwd && fwd.usage) v2db.addUsage(uidOf(item), fwd.usage, keyOf(item)); } catch (e) {}
  return fwd;
}

/** 尝试走 upstreamad 快通道；失败返回 false 让调用方回退 */
async function tryUpstreamadChat(req, res, body, item, raw, wasTruncated, sessionOverride) {
  const session = sessionOverride || pickUpstreamSession();
  if (!session) return false;

  try {
    if (body.stream) {
      // 流式：直接透传（首字 ~0.7s）
      const lsr = await upstreamadStream(req, res, body, session);
      try { if (lsr && lsr.usage) v2db.addUsage(uidOf(item), lsr.usage, keyOf(item)); } catch (e) {}
      return true;
    }
    // 非流式：缓冲完整（upstreamad 整包 ~1s）
    // 兼容：客户端写死小 max_tokens 时，DeepSeek 思考会吃光 token 导致 content 为空。
    // 小 max_tokens → 自动抬到 128 并关思考（reasoning_effort:none），保证一定有回复。
    const compatBody = Object.assign({}, body);
    if (!compatBody.max_tokens || compatBody.max_tokens < 128) {
      compatBody.max_tokens = 128;
      if (!compatBody.reasoning_effort) compatBody.reasoning_effort = 'none';
    }
    const r = await upstreamadChat(compatBody, session);
    if (r.status >= 400) {
      return false;
    }
    recordUsage(item);
    try { if (r.json && r.json.usage) v2db.addUsage(uidOf(item), r.json.usage, keyOf(item)); } catch (e) {}
    res.setHeader('X-Upstream-Fast', 'upstreamad');
    send(res, r.status, r.json || r.raw, wasTruncated ? { 'X-Upstream-Truncated': '1' } : {});
    return true;
  } catch (e) {
    // 已向客户端发包就不能回退（否则重复写响应头 → ERR_HTTP_HEADERS_SENT）
    if (res.headersSent) {
      try { res.end(); } catch (err) {}
      return true;
    }
    return false;   // 未发包 → 安全回退旧通道
  }
}

/** 中转站工具调用：把 tools 翻译成提示词发给上游，再把 <tool_call> 解析回标准 tool_calls。
 */
async function handleToolChat(req, res, body, item, wasTruncated) {
  const { messages, toolNames } = toolbridge.buildUpstreamMessages(body.messages, body.tools);

  // 拼接工具协议后可能再次超过 32KB，再检查一次
  const lim = toolbridge.enforceMessageLimits(messages);
  if (lim.truncated) wasTruncated = true;

  // 上游对非流式长任务约 60 秒就 504，流式则能跑几分钟。
  // 因此内部一律用流式调用，拿到完整结果后再对外按原样（非流式）返回。
  const upstreamBody = Object.assign({}, body, { messages: lim.messages });
  delete upstreamBody.tools;
  delete upstreamBody.tool_choice;
  delete upstreamBody.functions;
  delete upstreamBody.function_call;

  let acc = null;
  let lastErr = null;

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      acc = await callUpstreamStreaming(upstreamBody, 240000);
      break;
    } catch (e) {
      lastErr = e;
      acc = null;
      // 4xx 是业务错误（模型不存在、消息过长等），重试无意义
      if (e.status && e.status >= 400 && e.status < 500) break;
    }
    if (attempt < 3) {
      await new Promise((r) => setTimeout(r, 400 * attempt));
    }
  }

  if (!acc) {
    const status = (lastErr && lastErr.status) || 502;
    return send(res, status, {
      error: {
        message: '上游请求失败: ' + (lastErr ? lastErr.message : 'unknown'),
        type: 'server_error',
        ...(lastErr && lastErr.body ? { upstream: lastErr.body } : {})
      }
    });
  }

  const { toolCalls, cleaned } = toolbridge.parseToolCalls(acc.content || '', toolNames);

  const completion = aggregatedToCompletion(acc, body.model, toolCalls);
  if (completion.choices[0].message.content !== null) {
    completion.choices[0].message.content = cleaned;
  }

  recordUsage(item);
  try { if (acc && acc.usage) v2db.addUsage(uidOf(item), acc.usage, keyOf(item)); } catch (e) {}

  if (body.stream) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-store',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
      ...(wasTruncated ? { 'X-Upstream-Truncated': '1' } : {})
    });
    const chunks = toolbridge.buildSSEChunks(completion);
    for (const c of chunks) {
      res.write('data: ' + JSON.stringify(c) + '\n\n');
    }
    res.write('data: [DONE]\n\n');
    return res.end();
  }

  return send(res, 200, completion, wasTruncated ? { 'X-Upstream-Truncated': '1' } : {});
}

/**
 * 非流式请求：内部改用流式调上游，聚合后仍按非流式格式返回。
 * 目的是绕开上游对「非流式长任务」约 60 秒的 504 硬超时。
 */
async function handleNonStreamAggregated(req, res, body, item, wasTruncated) {
  const upstreamBody = Object.assign({}, body);
  delete upstreamBody.stream;
  delete upstreamBody.stream_options;

  let acc = null;
  let lastErr = null;

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      acc = await callUpstreamStreaming(upstreamBody, 240000);
      break;
    } catch (e) {
      lastErr = e;
      acc = null;
      if (e.status && e.status >= 400 && e.status < 500) break;
    }
    if (attempt < 3) {
      await new Promise((r) => setTimeout(r, 400 * attempt));
    }
  }

  if (!acc) {
    const status = (lastErr && lastErr.status) || 502;
    return send(res, status, {
      error: {
        message: '上游请求失败: ' + (lastErr ? lastErr.message : 'unknown'),
        type: 'server_error',
        ...(lastErr && lastErr.body ? { upstream: lastErr.body } : {})
      }
    });
  }

  recordUsage(item);
  try { if (acc && acc.usage) v2db.addUsage(uidOf(item), acc.usage, keyOf(item)); } catch (e) {}

  const completion = aggregatedToCompletion(acc, body.model);
  return send(res, 200, completion, wasTruncated ? { 'X-Upstream-Truncated': '1' } : {});
}

async function handleGateway(req, res) {
  const item = authGateway(req, res);
  if (!item) return;

  if (!UPSTREAM_KEY) {
    return send(res, 500, { error: { message: '服务端未配置上游密钥', type: 'server_error' } });
  }

  const pathOnly = req.url.split('?')[0];

  // ---- /v1/models：只下发账号实际可用的模型 ----
  if (req.method === 'GET' && /^\/?(v1\/)?models\/?$/.test(pathOnly)) {
    recordUsage(item);
    try {
      const r = await upstreamRequest('GET', '/v1/models', null, { authorization: `Bearer ${UPSTREAM_KEY}` });
      const all = [];   // 本站不使用任何 upstream 上游模型清单
      const filtered = all.filter((m) => ALLOWED_SET.has(m.id));
      // 若上游暂时异常但白名单非空，仍按白名单返回，避免下游拿不到模型
      const data = [];   // 模型清单完全由 TodayAI 上游实时提供
      // todayai 通道模型（独立上游 todayai.cn）：与 Upstream 模型并列下发
      if (todayai.configured()) {
        try { await todayai.listModels(); } catch (e) { console.log('[todayai] 拉取模型失败:', e.message); }
        try { data.push(...todayai.publicModels()); } catch (e) {}
      }
      return send(res, 200, { object: 'list', data });
    } catch (e) {
      const list = [];   // 上游异常时也不回退本地常量
      if (todayai.configured()) {
        try { list.push(...todayai.publicModels()); } catch (e2) {}
      }
      return send(res, 200, { object: 'list', data: list });
    }
  }

  // ---- /v1/chat/completions：校验模型后转发 ----
  if (req.method === 'POST' && /\/chat\/completions\/?$/.test(pathOnly)) {
    let raw;
    try {
      raw = await readBody(req, 20 * 1024 * 1024);
    } catch (e) {
      return send(res, 413, { error: { message: '请求体过大', type: 'invalid_request_error' } });
    }

    let body = null;
    try { body = JSON.parse(raw.toString('utf8')); } catch (e) { body = null; }

    // 诊断日志：记录消息角色序列，用于判断客户端是否正确回传工具结果
    if (body && Array.isArray(body.messages)) {
      const roles = body.messages.map((m) => {
        if (m && Array.isArray(m.tool_calls) && m.tool_calls.length) return 'assistant(tool_calls)';
        if (m && m.role === 'tool') return 'tool(result)';
        return (m && m.role) || '?';
      });
      const hasToolResult = roles.includes('tool(result)');
      console.log(
        `[chat] model=${body.model} stream=${!!body.stream} tools=${body.tools ? body.tools.length : 0} ` +
        `msgs=${body.messages.length} hasToolResult=${hasToolResult} roles=[${roles.join(' > ')}]`
      );
    }

    // ---- todayai 通道（独立上游 todayai.cn）：todayai-* 模型直接走本通道，不依赖 Upstream 账号 ----
    if (body && todayai.isTodayModel(body.model)) {
      recordUsage(item);
      return todayai.handleChat(req, res, body, { userV2Id: uidOf(item) || null });
    }

    // 本站是 TodayAI 独立站点：只接受 todayai-* 模型
    if (body && body.model && !todayai.isTodayModel(body.model)) {
      return send(res, 404, {
        error: { message: '模型 ' + body.model + ' 不存在：本站仅提供 TodayAI 模型（' + todayai.publicModels().map((m) => m.id).join(', ') + '）', type: 'invalid_request_error', code: 'model_not_found' }
      });
    }

    if (body && body.model && !ALLOWED_SET.has(body.model)) {
      return send(res, 400, {
        error: {
          message: `模型「${body.model}」当前不可用。可用模型：${ALLOWED_MODELS.join(', ')}`,
          type: 'invalid_request_error',
          code: 'model_not_found'
        }
      });
    }

    // v2 用户：优先用他自己的 session 走快通道（upstreamad 0.7s），无 session 才用 cookie 直连
    if (body && item && item.user) {
      // 按 Key 绑定的账号池轮询选号（未绑定时用该用户全部启用账号）
      const keyRow0 = item.keyRow || {};
      const acc = v2db.pickAccountForKey(item.user.id, keyRow0.account_ids, keyRow0.calls);
      if (acc) console.log('[pick] key=' + String(keyRow0.key || '').slice(0, 10) + ' → account#' + acc.id + ' (池 ' + acc._poolSize + ' 个, 用第 ' + (acc._idx + 1) + ')');
      if (acc) {
        acc.session = v2db.decryptCred(acc.session);
        acc.cookie = v2db.decryptCred(acc.cookie);
      }
      if (!acc) {
        return send(res, 403, { error: { message: '请先在用户中心绑定 Upstream 账号', type: 'account_required' } });
      }
      // 有 session：走 upstreamad 快通道
      if (acc.session) {
        const fast = await tryUpstreamadChat(req, res, body, item, raw, false, acc.session);
        if (fast) return;
      }
      // 无 session 或快通道失败：用 cookie 直连 Web 接口
      if (!acc.cookie) {
        return send(res, 403, { error: { message: '账号缺少凭证', type: 'account_required' } });
      }
      try {
        if (body.stream) {
          await upstreamDirect.upstreamDirectStream(req, res, body, acc.cookie);
        } else {
          const r = await upstreamDirect.upstreamDirectNonStream(body, acc.cookie);
          recordUsage(item);
          return send(res, r.status, r.json);
        }
        recordUsage(item);
        return;
      } catch (e) {
        const st = e.status || 502;
        return send(res, st, { error: { message: 'Upstream 直连失败: ' + (e.message || e.body || ''), type: 'upstream_error' } });
      }
    }

    // 优先 upstreamad 直连快通道（原生 OpenAI，首字 0.7s、原生工具调用）
    if (body) {
      const fast = await tryUpstreamadChat(req, res, body, item, raw, false);
      if (fast || res.headersSent) return;   // 已回包就不能再走旧通道（否则重复写头）
    }

    // 上游单条消息上限 32KB：超了先本地截断，避免直接抛 INVALID_MESSAGE_TOO_LARGE
    let wasTruncated = false;
    if (body && Array.isArray(body.messages)) {
      const lim = toolbridge.enforceMessageLimits(body.messages);
      if (lim.truncated) {
        body.messages = lim.messages;
        raw = Buffer.from(JSON.stringify(body));
        wasTruncated = true;
      }
    }
    if (wasTruncated) {
      res.setHeader('X-Upstream-Truncated', '1');
    }

    // 带 tools 的请求走「中转站工具协议」：本地翻译成提示词，再把输出解析回 tool_calls
    if (body && Array.isArray(body.tools) && body.tools.length > 0) {
      return handleToolChat(req, res, body, item, wasTruncated);
    }
    // 兼容旧式 functions 参数
    if (body && Array.isArray(body.functions) && body.functions.length > 0) {
      body.tools = body.functions.map((f) => ({ type: 'function', function: f }));
      return handleToolChat(req, res, body, item, wasTruncated);
    }

    // 非流式请求：内部转流式聚合，绕过上游 60 秒 504
    if (!body || body.stream !== true) {
      return handleNonStreamAggregated(req, res, body || {}, item, wasTruncated);
    }

    recordUsage(item);
    return forward(req, res, raw);
  }

  // ---- 其余路径直接转发 ----
  recordUsage(item);
  return forward(req, res, null);
}

// ==================== 静态文件 ====================

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function serveStatic(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('404');
    }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream',
      'Cache-Control': 'no-store'
    });
    res.end(data);
  });
}

// ==================== 主服务 ====================

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;

  res.setHeader('X-Content-Type-Options', 'nosniff');

  try {
    // 旧版接口已废弃（多用户 v2 迁移），一律 410
    if (pathname === '/api/login' || pathname === '/api/logout' ||
        pathname === '/api/accounts' || pathname === '/api/refresh' ||
        pathname === '/api/keys' || pathname === '/api/points' ||
        pathname === '/api/health' || pathname.startsWith('/api/upstream/')) {
      return send(res, 410, { ok: false, msg: '接口已废弃，请使用 v2 用户接口（/api/user/*、/api/my/*、/api/captcha、/api/register）' });
    }

    // 网关：兼容 /v1/* 与根路径两种写法（有些客户端 baseURL 不带 /v1）
    if (pathname.startsWith('/v1/') || pathname === '/v1' ||
        pathname === '/models' || pathname === '/v1/models' ||
        /^\/chat\/completions\/?$/.test(pathname)) {
      return handleGateway(req, res);
    }

    // v2 用户 API（注册/验证码/我的 Key/账号）
    if (pathname === '/api/captcha' || pathname === '/api/register' ||
        pathname === '/api/user/login' || pathname === '/api/user/logout' || pathname === '/api/me' ||
        pathname.startsWith('/api/my/')) {
      return await v2routes.handle(req, res, pathname);
    }

    // v2 用户 API
    if (pathname === '/api/captcha' || pathname === '/api/register' ||
        pathname === '/api/user/login' || pathname === '/api/user/logout' || pathname === '/api/me' ||
        pathname.startsWith('/api/my/')) {
      return await v2routes.handle(req, res, pathname);
    }

    // 登录（管理员）
    if (pathname === '/api/login' && req.method === 'POST') {
      return await handleLogin(req, res);
    }

    // 登出
    if (pathname === '/api/logout') {
      return send(res, 200, { ok: true }, {
        'Set-Cookie': 'upstream_sess=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
      });
    }

    // 面板 API
    if (pathname.startsWith('/api/')) {
      return await handleApi(req, res, pathname);
    }

    // 静态
    if (pathname === '/' || pathname === '/index.html') {
      return serveStatic(res, path.join(__dirname, 'public', 'index.html'));
    }
    if (/^\/[\w.-]+$/.test(pathname)) {
      const f = path.join(__dirname, 'public', pathname.slice(1));
      if (f.startsWith(path.join(__dirname, 'public'))) {
        return serveStatic(res, f);
      }
    }

    send(res, 404, { ok: false, msg: 'not found' });
  } catch (e) {
    if (!res.headersSent) {
      send(res, 500, { ok: false, msg: e.message });
    }
  }
});

v2routes.init({
  send, readBody, sign, verify, upstreamRequest, noteAuthResult, clientIpOf, crypto, v2db,
  upstreamAccount, upstreamPoints: upstreamPointsRequest,
  todayai,
  isIpBanned, isIpPermanent,
  fs, path, DATA_DIR
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[today-gateway] listening on 127.0.0.1:${PORT}`);
  console.log(`[today-gateway] upstream = ${UPSTREAM}`);
  console.log(`[today-gateway] admin pass set = ${!!ADMIN_PASS}`);
  console.log(`[today-gateway] keys loaded = ${keys.length}`);
});
