'use strict';

/**
 * v2 多用户路由（独立模块，依赖注入避免循环引用）。
 * 由 server.js 调 init() 注入共享工具，然后 handle(req, res, pathname)。
 */

let S = null;   // { send, readBody, sign, verify, upstreamRequest, noteAuthResult, clientIpOf, crypto, v2db }
const regTimes = {};   // ip -> [注册时间戳]，防刷注册

function init(deps) {
  S = deps;
}

function userSession(req) {
  const cookie = req.headers.cookie || '';
  const m = cookie.match(/(?:^|;\s*)upstream_u=([^;]+)/);
  if (!m) return null;
  const data = S.verify(decodeURIComponent(m[1]));
  if (!data || !data.u) return null;
  return { uid: Number(String(data.u).replace(/^u/, '')) || 0 };
}

function sendUserSession(res, userId) {
  const payload = Buffer.from(JSON.stringify({
    u: 'u' + userId, exp: Date.now() + 3650 * 24 * 3600 * 1000
  })).toString('base64url');
  const token = S.sign(payload);
  S.send(res, 200, { ok: true, token }, {
    'Set-Cookie': 'upstream_u=' + encodeURIComponent(token) + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + (3650 * 24 * 3600)
  });
}

async function handle(req, res, pathname) {
  try {
    return await _handle(req, res, pathname);
  } catch (e) {
    console.log('[v2routes] 错误:', e && e.stack ? e.stack.split('\n').slice(0,3).join(' | ') : String(e));
    return S.send(res, 500, { ok: false, msg: '内部错误: ' + (e && e.message) });
  }
}

async function _handle(req, res, pathname) {
  const m = req.method;

  // ---- 图形验证码 ----
  if (pathname === '/api/captcha' && m === 'GET') {
    const c = S.v2db.genCaptcha();
    res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'no-store' });
    res.end(c.svg + '<!--TOKEN:' + c.token + '-->');
    return;
  }

  // ---- 注册 ----
  if (pathname === '/api/register' && m === 'POST') {
    const banIp_ = S.clientIpOf(req);
    if (S.isIpBanned(banIp_)) {
      S.noteAuthResult(banIp_, false);
      return S.send(res, 403, { '你的IP': '已被永久拉黑' });
    }
    if (!S.v2db.udb) return S.send(res, 500, { ok: false, msg: '数据库不可用' });

    // 注册频率限制：同 IP 10 分钟内最多 3 次
    const ip = S.clientIpOf(req);
    const now = Date.now();
    regTimes[ip] = (regTimes[ip] || []).filter((t) => now - t < 10 * 60 * 1000);
    if (regTimes[ip].length >= 3) {
      return S.send(res, 429, { ok: false, msg: '注册过于频繁，请 10 分钟后再试' });
    }
    regTimes[ip].push(now);
    const body = JSON.parse((await S.readBody(req)).toString('utf8') || '{}');
    const username = String(body.username || '').trim();
    const pass = String(body.password || '');
    const regcode = String(body.regcode || '').trim();
    const capTok = String(body.captchaToken || '');
    const cap = String(body.captcha || '').trim();

    // 一次性注册码：文件里的码用后即销毁
    const codeFile = S.path.join(S.DATA_DIR, 'regcodes.json');
    let codes = {};
    try { codes = JSON.parse(S.fs.readFileSync(codeFile, 'utf8')) || {}; } catch (e) { codes = {}; }
    if (!codes[regcode] || codes[regcode].used) {
      return S.send(res, 400, { ok: false, msg: '注册码无效或已使用' });
    }

    // 用户名 6-12 位
    if (!/^[A-Za-z0-9_]{6,12}$/.test(username)) {
      return S.send(res, 400, { ok: false, msg: '用户名需 6-12 位（仅字母/数字/下划线）' });
    }

    // 密码强度：≥6 位且含大小写 + 数字 + 符号
    if (pass.length < 6 || pass.length > 64) {
      return S.send(res, 400, { ok: false, msg: '密码长度需 6-64 位' });
    }
    if (!/[a-z]/.test(pass)) return S.send(res, 400, { ok: false, msg: '密码需包含小写字母' });
    if (!/[A-Z]/.test(pass)) return S.send(res, 400, { ok: false, msg: '密码需包含大写字母' });
    if (!/\d/.test(pass)) return S.send(res, 400, { ok: false, msg: '密码需包含数字' });
    if (!/[^A-Za-z0-9]/.test(pass)) return S.send(res, 400, { ok: false, msg: '密码需包含符号（如 !@#$%^&*）' });

    if (!S.v2db.verifyCaptcha(capTok, cap)) return S.send(res, 400, { ok: false, msg: '验证码错误或已过期' });

    const exists = S.v2db.udb.prepare('SELECT id FROM users WHERE username=?').get(username);
    if (exists) return S.send(res, 400, { ok: false, msg: '该用户名已注册' });

    try {
      const uid = S.v2db.createUser(username, pass);
      // 用后销毁
      codes[regcode] = { used: true, usedBy: username, usedAt: Date.now(), createdAt: codes[regcode].createdAt };
      try { S.fs.writeFileSync(codeFile, JSON.stringify(codes, null, 2)); } catch (e) { /* ignore */ }
      console.log('[注册码] 已使用并销毁:', regcode, '→', username);
      return sendUserSession(res, uid);
    } catch (e) {
      return S.send(res, 500, { ok: false, msg: '注册失败: ' + e.message });
    }
  }

  // ---- 用户登录 ----
  if (pathname === '/api/user/login' && m === 'POST') {
    const banIp_ = S.clientIpOf(req);
    if (S.isIpBanned(banIp_)) {
      S.noteAuthResult(banIp_, false);
      return S.send(res, 403, { '你的IP': '已被永久拉黑' });
    }
    if (!S.v2db.udb) return S.send(res, 500, { ok: false, msg: '数据库不可用' });
    const body = JSON.parse((await S.readBody(req)).toString('utf8') || '{}');
    const username = String(body.username || '').trim();
    const pass = String(body.password || '');
    const u = S.v2db.verifyUser(username, pass);
    if (!u) {
      S.noteAuthResult(S.clientIpOf(req), false);
      return S.send(res, 401, { ok: false, msg: '用户名或密码错误' });
    }
    S.noteAuthResult(S.clientIpOf(req), true);
    return sendUserSession(res, u.id);
  }

  // ---- 用户登出（销毁本地登录记录）----
  if (pathname === '/api/user/logout' && m === 'POST') {
    return S.send(res, 200, { ok: true }, {
      'Set-Cookie': 'upstream_u=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
    });
  }

  // ---- 用户信息 ----
  if (pathname === '/api/me' && m === 'GET') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const u = S.v2db.udb.prepare('SELECT id, username, created_at FROM users WHERE id=?').get(sess.uid);
    if (!u) return S.send(res, 401, { ok: false, msg: '用户不存在' });
    const keyCount = S.v2db.udb.prepare('SELECT COUNT(*) c FROM keys WHERE user_id=?').get(u.id).c;
    const accCount = S.v2db.udb.prepare('SELECT COUNT(*) c FROM upstream_accounts WHERE user_id=?').get(u.id).c;
    return S.send(res, 200, {
      ok: true,
      user: { id: u.id, username: u.username, createdAt: u.created_at },
      stats: { keys: keyCount, accounts: accCount }
    });
  }

  // ---- 我的 Key ----
  // 个人统计：今日/累计 请求数 + token
  if (pathname === '/api/my/stats' && m === 'GET') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const st = S.v2db.getUserStats(sess.uid);
    return S.send(res, 200, { ok: true, ...st });
  }

  if (pathname === '/api/my/keys' && m === 'GET') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const keys = S.v2db.udb.prepare('SELECT key, label, enabled, account_ids, calls, last_used_at, created_at FROM keys WHERE user_id=? ORDER BY created_at DESC').all(sess.uid);
    keys.forEach((k) => { try { k.accountIds = JSON.parse(k.account_ids || '[]'); } catch (e) { k.accountIds = []; } });
    return S.send(res, 200, { ok: true, keys });
  }

  if (pathname === '/api/my/keys' && m === 'POST') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const body = JSON.parse((await S.readBody(req)).toString('utf8') || '{}');
    const n = S.v2db.udb.prepare('SELECT COUNT(*) c FROM keys WHERE user_id=?').get(sess.uid).c;
    if (n >= 10) return S.send(res, 400, { ok: false, msg: '最多 10 个 Key' });
    const accountIds = Array.isArray(body.accountIds) ? body.accountIds.map((x) => Number(x)).filter((x) => Number.isFinite(x)) : [];
    const key = S.v2db.createUserKey(sess.uid, String(body.label || '').slice(0, 60), accountIds);
    return S.send(res, 200, { ok: true, key });
  }

  let m2;
  // 更新 Key 的账号绑定
  if ((m2 = pathname.match(/^\/api\/my\/keys\/([^/]+)\/accounts$/)) && m === 'POST') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const body = JSON.parse((await S.readBody(req)).toString('utf8') || '{}');
    const ids = Array.isArray(body.accountIds) ? body.accountIds.map((x) => Number(x)).filter((x) => Number.isFinite(x)) : [];
    // 校验这些账号确实属于本用户
    if (ids.length) {
      const ph = ids.map(() => '?').join(',');
      const owned = S.v2db.udb.prepare('SELECT id FROM upstream_accounts WHERE user_id=? AND id IN (' + ph + ')').all(sess.uid, ...ids).map((r) => r.id);
      const bad = ids.filter((x) => !owned.includes(x));
      if (bad.length) return S.send(res, 400, { ok: false, msg: '账号不属于你: ' + bad.join(',') });
    }
    const newLabel = (body.label === undefined) ? null : String(body.label).slice(0, 60);
    let r;
    if (newLabel !== null) {
      r = S.v2db.udb.prepare('UPDATE keys SET account_ids=?, label=? WHERE key=? AND user_id=?').run(JSON.stringify(ids), newLabel, m2[1], sess.uid);
    } else {
      r = S.v2db.udb.prepare('UPDATE keys SET account_ids=? WHERE key=? AND user_id=?').run(JSON.stringify(ids), m2[1], sess.uid);
    }
    return S.send(res, 200, { ok: r.changes > 0, accountIds: ids });
  }

  if ((m2 = pathname.match(/^\/api\/my\/keys\/([^/]+)\/enabled$/)) && m === 'POST') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const body = JSON.parse((await S.readBody(req)).toString('utf8') || '{}');
    const r = S.v2db.udb.prepare('UPDATE keys SET enabled=? WHERE key=? AND user_id=?').run(body.enabled ? 1 : 0, m2[1], sess.uid);
    return S.send(res, 200, { ok: r.changes > 0 });
  }

  if ((m2 = pathname.match(/^\/api\/my\/keys\/([^/]+)$/)) && m === 'DELETE') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const r = S.v2db.udb.prepare('DELETE FROM keys WHERE key=? AND user_id=?').run(m2[1], sess.uid);
    return S.send(res, 200, { ok: r.changes > 0 });
  }

  // ---- 我的 TodayAI 账号（独立上游 todayai.cn，与 Upstream 账号完全隔离）----
  if (pathname === '/api/my/todayai' && m === 'GET') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const rows = S.v2db.udb.prepare('SELECT id, label, phone, enabled, created_at FROM todayai_accounts WHERE user_id=? ORDER BY created_at DESC').all(sess.uid);
    const mask = (p) => String(p || '').replace(/^\+?86/, '').replace(/(\d{3})\d{4}(\d{4})/, '$1****$2');
    let fallback = false;
    try { fallback = !!(S.todayai && S.todayai.loadAccount && S.todayai.loadAccount(null).source === 'global'); } catch (e) {}
    return S.send(res, 200, { ok: true, accounts: rows.map((a) => Object.assign({}, a, { phone: mask(a.phone) })), fallback });
  }

  // ---- TodayAI 账号额度/套餐（用户中心展示）----
  if (pathname === '/api/my/todayai/usage' && m === 'GET') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    try {
      const u = await S.todayai.usage(sess.uid);
      return S.send(res, 200, { ok: true, usage: u });
    } catch (e) {
      return S.send(res, 502, { ok: false, msg: '查询失败: ' + e.message });
    }
  }

  // ---- 发 TodayAI 短信验证码（绑定时用）----
  if (pathname === '/api/my/todayai/sms' && m === 'POST') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const body = JSON.parse((await S.readBody(req)).toString('utf8') || '{}');
    const phone = String(body.phone || '').trim();
    if (!/^1[3-9]\d{9}$/.test(phone)) return S.send(res, 400, { ok: false, msg: '手机号格式不正确' });
    const r = await S.todayai.sendOtp(phone);
    if (!r.ok) return S.send(res, 400, { ok: false, msg: r.msg || '发送失败' });
    return S.send(res, 200, { ok: true, msg: '验证码已发送（TodayAI 官方短信）' });
  }

  // ---- 绑定 TodayAI 账号（短信登录；绑定后 todayai-* 模型走你自己的额度）----
  if (pathname === '/api/my/todayai/bind' && m === 'POST') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const body = JSON.parse((await S.readBody(req)).toString('utf8') || '{}');
    const phone = String(body.phone || '').trim();
    const code = String(body.code || '').trim();
    if (!/^1[3-9]\d{9}$/.test(phone)) return S.send(res, 400, { ok: false, msg: '手机号格式不正确' });
    if (!/^\d{4,8}$/.test(code)) return S.send(res, 400, { ok: false, msg: '验证码格式不正确' });
    const r = await S.todayai.verifyLogin(phone, code);
    if (!r.ok) {
      const raw = String(r.msg || '');
      const msg = /OTP not found|invalid/i.test(raw) ? '验证码错误或已过期，请重新获取' : (raw || '登录失败');
      return S.send(res, 400, { ok: false, msg });
    }
    const tail = phone.slice(-4);
    const enc = S.v2db.encryptCred(r.cookie);
    const old = S.v2db.udb.prepare('SELECT id FROM todayai_accounts WHERE user_id=? AND phone=?').get(sess.uid, r.phone);
    if (old) {
      S.v2db.udb.prepare('UPDATE todayai_accounts SET label=?, cookie=?, jwt=?, jwt_exp=?, upstream_user_id=?, enabled=1, created_at=? WHERE id=?')
        .run('****' + tail, enc, r.jwt, r.jwtExp, r.userId, Date.now(), old.id);
    } else {
      S.v2db.udb.prepare('INSERT INTO todayai_accounts (user_id, label, phone, cookie, jwt, jwt_exp, upstream_user_id, selected_option, enabled, created_at) VALUES (?,?,?,?,?,?,?,?,1,?)')
        .run(sess.uid, '****' + tail, r.phone, enc, r.jwt, r.jwtExp, r.userId, '', Date.now());
    }
    if (S.todayai.invalidate) S.todayai.invalidate(sess.uid);
    const masked = String(r.phone).replace(/^\+?86/, '').replace(/(\d{3})\d{4}(\d{4})/, '$1****$2');
    return S.send(res, 200, { ok: true, msg: '已绑定 TodayAI 账号 ' + masked + '（todayai-* 模型将使用你自己的额度）' });
  }

  // ---- 解绑 TodayAI 账号 ----
  let tad;
  if ((tad = pathname.match(/^\/api\/my\/todayai\/(\d+)$/)) && m === 'DELETE') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const r = S.v2db.udb.prepare('DELETE FROM todayai_accounts WHERE id=? AND user_id=?').run(tad[1], sess.uid);
    if (S.todayai.invalidate) S.todayai.invalidate(sess.uid);
    return S.send(res, 200, { ok: r.changes > 0, msg: r.changes > 0 ? '已解绑' : '记录不存在' });
  }

  // ---- 我的 Upstream 账号（隔离）----
  if (pathname === '/api/my/accounts' && m === 'GET') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const accs = S.v2db.udb.prepare('SELECT id, label, enabled, created_at FROM upstream_accounts WHERE user_id=? ORDER BY created_at DESC').all(sess.uid);
    return S.send(res, 200, { ok: true, accounts: accs });
  }

  // ---- 发短信验证码（客户端侧，用于拿 session 走快通道）----
  if (pathname === '/api/my/accounts/sms' && m === 'POST') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 400, { ok: false, msg: '请先登录' });
    const body = JSON.parse((await S.readBody(req)).toString('utf8') || '{}');
    const phone = String(body.phone || '').trim();
    if (!/^1[3-9]\d{9}$/.test(phone)) return S.send(res, 400, { ok: false, msg: '手机号格式不正确' });
    const r = await S.upstreamAccount.sendSms(phone);
    if (!r.ok) return S.send(res, 400, { ok: false, msg: r.msg || '发送失败' });
    return S.send(res, 200, { ok: true, msgid: r.msgid });
  }

  // ---- 绑 Upstream 账号（客户端短信登录 → session，快通道）----
  if (pathname === '/api/my/accounts/bind' && m === 'POST') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const body = JSON.parse((await S.readBody(req)).toString('utf8') || '{}');
    const phone = String(body.phone || '').trim();
    const code = String(body.code || '').trim();
    const msgid = String(body.msgid || '');

    if (!/^1[3-9]\d{9}$/.test(phone)) return S.send(res, 400, { ok: false, msg: '手机号格式不正确' });
    if (!code || !msgid) return S.send(res, 400, { ok: false, msg: '缺少验证码或会话' });

    const r = await S.upstreamAccount.checkCode(phone, code, msgid);
    if (!r.ok) return S.send(res, 400, { ok: false, msg: r.msg || '登录失败' });

    const tail = phone.replace(/\D/g, '').slice(-4);
    // 去重：同手机号重复绑定 → 覆盖旧记录（不新增一堆）
    const old = S.v2db.udb.prepare('SELECT id FROM upstream_accounts WHERE user_id=? AND label=?').get(sess.uid, tail);
    if (old) {
      S.v2db.udb.prepare('UPDATE upstream_accounts SET session=?, enabled=1, created_at=? WHERE id=?')
         .run(S.v2db.encryptCred(r.session), Date.now(), old.id);
      return S.send(res, 200, { ok: true, msg: '已重新绑定 Upstream 账号 ****' + tail + '（覆盖旧记录，快通道已更新）' });
    }
    S.v2db.udb.prepare('INSERT INTO upstream_accounts (user_id, label, session, enabled, created_at) VALUES (?,?,?,1,?)')
       .run(sess.uid, tail, S.v2db.encryptCred(r.session), Date.now());
    return S.send(res, 200, { ok: true, msg: '已绑定 Upstream 账号 ****' + tail + '（快通道已启用）' });
  }

  // ---- 单账号签到 ----
  let ci;
  if ((ci = pathname.match(/^\/api\/my\/accounts\/([^/]+)\/checkin$/)) && m === 'POST') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const acc = S.v2db.udb.prepare('SELECT id, session FROM upstream_accounts WHERE id=? AND user_id=?').get(ci[1], sess.uid);
    if (!acc || !acc.session) return S.send(res, 400, { ok: false, msg: '该账号未绑定或缺少 session' });
    acc.session = S.v2db.decryptCred(acc.session);
    try {
      const r = await S.upstreamPoints('/points/first-login', acc.session, 'POST', {});
      const d = (r.json && r.json.data) || {};
      const code = r.json && r.json.code;
      if (code && code !== '000000') return S.send(res, 400, { ok: false, msg: (r.json && r.json.desc) || '签到失败' });
      return S.send(res, 200, {
        ok: true,
        accountId: ci[1],
        alreadyProcessed: !!d.alreadyProcessed,
        dailyQuota: d.dailyQuota,
        dailyBalance: d.dailyBalance,
        dailyConsumed: d.dailyConsumed,
        currentBalance: d.currentBalance,
        permanentBalance: d.permanentBalance,
        msg: d.alreadyProcessed ? '今日已签到' : '签到成功'
      });
    } catch (e) {
      return S.send(res, 502, { ok: false, msg: '签到失败: ' + e.message });
    }
  }

  // ---- 一键签到（所有账号）----
  if (pathname === '/api/my/checkin-all' && m === 'POST') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const accs = S.v2db.udb.prepare('SELECT id, session FROM upstream_accounts WHERE user_id=? AND enabled=1').all(sess.uid).map((a) => Object.assign(a, { session: S.v2db.decryptCred(a.session) }));
    if (!accs.length) return S.send(res, 400, { ok: false, msg: '还没有绑定 Upstream 账号' });

    const results = [];
    for (const a of accs) {
      if (!a.session) { results.push({ id: a.id, ok: false, msg: '无 session' }); continue; }
      try {
        const r = await S.upstreamPoints('/points/first-login', a.session, 'POST', {});
        const d = (r.json && r.json.data) || {};
        if (r.json && r.json.code && r.json.code !== '000000') {
          results.push({ id: a.id, ok: false, msg: (r.json && r.json.desc) || '失败' });
        } else {
          results.push({ id: a.id, ok: true, alreadyProcessed: !!d.alreadyProcessed });
        }
      } catch (e) {
        results.push({ id: a.id, ok: false, msg: e.message });
      }
    }
    const good = results.filter((x) => x.ok).length;
    return S.send(res, 200, {
      ok: true,
      results,
      msg: good === results.length ? (results.every((x) => x.alreadyProcessed) ? '全部今日已签到' : '全部签到成功')
           : good + '/' + results.length + ' 签到成功'
    });
  }

  // ---- 账号额度统计（额度 / 可用额度 / 数量）----
  if (pathname === '/api/my/points' && m === 'GET') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const accs = S.v2db.udb.prepare('SELECT id, session FROM upstream_accounts WHERE user_id=? AND enabled=1').all(sess.uid).map((a) => Object.assign(a, { session: S.v2db.decryptCred(a.session) }));

    let totalBalance = 0, totalAvailable = 0, okCount = 0;
    const accounts = [];
    for (const a of accs) {
      const entry = { id: a.id, ok: false };
      if (!a.session) { accounts.push(entry); continue; }
      try {
        const r = await S.upstreamPoints('/points/balance', a.session);
        const d = (r.json && r.json.data) || {};
        if (r.json && r.json.code && r.json.code !== '000000') {
          accounts.push(entry);
        } else {
          const bal = Number(d.balance) || 0;
          const avail = Number(d.availableBalance) || 0;
          entry.ok = true;
          entry.balance = bal;
          entry.available = avail;
          totalBalance += bal;
          totalAvailable += avail;
          okCount++;
          // 顺带查邀请码激活状态
          try {
            const ar = await S.upstreamPoints('/points/activation', a.session, 'GET');
            const ad = (ar.json && ar.json.data) || {};
            entry.activated = !!ad.activated;
            entry.appliedInvitationCode = ad.appliedInvitationCode || '';
          } catch (e) { /* 忽略 */ }
          accounts.push(entry);
        }
      } catch (e) { accounts.push(entry); }
    }
    return S.send(res, 200, {
      ok: true,
      accountCount: accs.length,
      okCount,
      balance: totalBalance,
      availableBalance: totalAvailable,
      accounts
    });
  }

  // ---- 删除绑定的 Upstream 账号 ----
  let d2;
  if ((d2 = pathname.match(/^\/api\/my\/accounts\/([^/]+)$/)) && m === 'DELETE') {
    const sess = userSession(req);
    if (!sess) return S.send(res, 401, { ok: false, msg: '未登录' });
    const r = S.v2db.udb.prepare('DELETE FROM upstream_accounts WHERE id=? AND user_id=?').run(d2[1], sess.uid);
    return S.send(res, 200, { ok: r.changes > 0 });
  }

  return S.send(res, 404, { ok: false, msg: 'not found' });
}

module.exports = { init, handle };
