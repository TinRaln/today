'use strict';

/**
 * v2 多用户系统 —— 独立模块（零转义风险，server.js 只需 require 一行）。
 * 数据模型：users / keys / upstream_accounts（SQLite, node:sqlite）
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, 'data');
const USER_DB = path.join(DATA_DIR, 'upstream-user.db');
const { DatabaseSync } = require('node:sqlite');

let udb = null;
try {
  udb = new DatabaseSync(USER_DB);
  udb.exec(
    'CREATE TABLE IF NOT EXISTS users (' +
    ' id INTEGER PRIMARY KEY AUTOINCREMENT,' +
    ' username TEXT UNIQUE NOT NULL,' +
    ' pass_hash TEXT NOT NULL,' +
    ' salt TEXT NOT NULL,' +
    ' created_at INTEGER NOT NULL);' +
    'CREATE TABLE IF NOT EXISTS keys (' +
    ' key TEXT PRIMARY KEY,' +
    ' user_id INTEGER NOT NULL,' +
    ' label TEXT DEFAULT "",' +
    ' enabled INTEGER DEFAULT 1,' +
    ' account_ids TEXT DEFAULT "[]",' +
    ' calls INTEGER DEFAULT 0,' +
    ' last_used_at INTEGER DEFAULT 0,' +
    ' created_at INTEGER NOT NULL,' +
    ' FOREIGN KEY(user_id) REFERENCES users(id));' +
    'CREATE TABLE IF NOT EXISTS usage_daily (' +
    ' user_id INTEGER NOT NULL,' +
    ' date TEXT NOT NULL,' +
    ' calls INTEGER DEFAULT 0,' +
    ' prompt_tokens INTEGER DEFAULT 0,' +
    ' completion_tokens INTEGER DEFAULT 0,' +
    ' points_consumed INTEGER DEFAULT 0,' +
    ' PRIMARY KEY (user_id, date));' +
    'CREATE TABLE IF NOT EXISTS upstream_accounts (' +
    ' id INTEGER PRIMARY KEY AUTOINCREMENT,' +
    ' user_id INTEGER NOT NULL,' +
    ' label TEXT DEFAULT "",' +
    ' cookie TEXT DEFAULT "",' +
    ' phone TEXT DEFAULT "",' +
    ' session TEXT DEFAULT "",' +
    ' enabled INTEGER DEFAULT 1,' +
    ' created_at INTEGER NOT NULL,' +
    ' FOREIGN KEY(user_id) REFERENCES users(id));' +
    'CREATE INDEX IF NOT EXISTS idx_keys_user ON keys(user_id);' +
    'CREATE INDEX IF NOT EXISTS idx_accounts_user ON upstream_accounts(user_id);' +
    'CREATE TABLE IF NOT EXISTS todayai_accounts (' +
    ' id INTEGER PRIMARY KEY AUTOINCREMENT,' +
    ' user_id INTEGER NOT NULL,' +
    ' label TEXT DEFAULT \'\',' +
    ' phone TEXT DEFAULT \'\',' +
    ' cookie TEXT DEFAULT \'\',' +
    ' jwt TEXT DEFAULT \'\',' +
    ' jwt_exp INTEGER DEFAULT 0,' +
    ' upstream_user_id TEXT DEFAULT \'\',' +
    ' selected_option TEXT DEFAULT \'\',' +
    ' enabled INTEGER DEFAULT 1,' +
    ' created_at INTEGER NOT NULL,' +
    ' FOREIGN KEY(user_id) REFERENCES users(id));' +
    'CREATE INDEX IF NOT EXISTS idx_todayai_user ON todayai_accounts(user_id);'
  );

  // 增量迁移：老库给 keys 补 account_ids 列
  try {
    const cols = udb.prepare('PRAGMA table_info(keys)').all().map((c) => c.name);
    if (!cols.includes('account_ids')) {
      udb.exec('ALTER TABLE keys ADD COLUMN account_ids TEXT DEFAULT "[]"');
      console.log('[v2db] 已为 keys 表新增 account_ids 列');
    }
  } catch (e) { /* ignore */ }
} catch (e) {
  console.log('[v2db] SQLite 初始化失败:', e.message);
  udb = null;
}

// ---------- 密码 ----------
function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, 64).toString('hex');
}

function createUser(username, password) {
  const salt = crypto.randomBytes(16).toString('hex');
  udb.prepare('INSERT INTO users (username, pass_hash, salt, created_at) VALUES (?,?,?,?)')
     .run(username, hashPassword(password, salt), salt, Date.now());
  return udb.prepare('SELECT id FROM users WHERE username=?').get(username).id;
}

/** 累加一次调用统计（供网关在每次成功转发后调用） */
function addUsage(userId, usage, apiKey) {
  // 兼容：item 来自旧 keys.json 时没有 user_id，用 apiKey 反查
  if (!userId && apiKey) {
    try {
      const row = udb.prepare('SELECT user_id FROM keys WHERE key=?').get(apiKey);
      if (row) userId = row.user_id;
    } catch (e) { /* ignore */ }
  }
  if (!userId) return;
  const d = new Date();
  const date = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  const pt = Number(usage && usage.prompt_tokens) || 0;
  const ct = Number(usage && usage.completion_tokens) || 0;
  const pc = Number(usage && usage.points_consumed) || 0;
  udb.prepare(
    'INSERT INTO usage_daily (user_id, date, calls, prompt_tokens, completion_tokens, points_consumed) ' +
    'VALUES (?,?,1,?,?,?) ' +
    'ON CONFLICT(user_id, date) DO UPDATE SET ' +
    'calls = calls + 1, prompt_tokens = prompt_tokens + ?, completion_tokens = completion_tokens + ?, points_consumed = points_consumed + ?'
  ).run(userId, date, pt, ct, pc, pt, ct, pc);
}

/** 读用户统计：今日 + 累计 */
function getUserStats(userId) {
  const d = new Date();
  const today = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  const t = udb.prepare('SELECT calls, prompt_tokens, completion_tokens, points_consumed FROM usage_daily WHERE user_id=? AND date=?').get(userId, today) || {};
  const a = udb.prepare('SELECT COALESCE(SUM(calls),0) calls, COALESCE(SUM(prompt_tokens),0) pt, COALESCE(SUM(completion_tokens),0) ct, COALESCE(SUM(points_consumed),0) pc FROM usage_daily WHERE user_id=?').get(userId) || {};
  return {
    today: { calls: t.calls || 0, promptTokens: t.prompt_tokens || 0, completionTokens: t.completion_tokens || 0, totalTokens: (t.prompt_tokens || 0) + (t.completion_tokens || 0), points: t.points_consumed || 0 },
    total: { calls: a.calls || 0, promptTokens: a.pt || 0, completionTokens: a.ct || 0, totalTokens: (a.pt || 0) + (a.ct || 0), points: a.pc || 0 }
  };
}

function verifyUser(username, password) {
  const u = udb.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!u) return null;
  if (hashPassword(password, u.salt) !== u.pass_hash) return null;
  return u;
}

// ---------- 图形验证码 ----------
const captchaStore = {};
const CAPTCHA_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function genCaptcha() {
  let text = '';
  for (let i = 0; i < 4; i++) text += CAPTCHA_CHARS[Math.floor(Math.random() * CAPTCHA_CHARS.length)];
  const token = crypto.randomBytes(16).toString('hex');
  captchaStore[token] = { answer: text, at: Date.now() };

  const size = 120, h = 44;
  const xs = [12, 38, 64, 90];
  const parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="' + size + '" height="' + h + '" viewBox="0 0 ' + size + ' ' + h + '">'];
  parts.push('<rect width="100%" height="100%" fill="#1a1f27"/>');
  for (let i = 0; i < 5; i++) {
    parts.push('<line x1="' + Math.floor(Math.random() * size) + '" y1="' + Math.floor(Math.random() * h) + '" x2="' + Math.floor(Math.random() * size) + '" y2="' + Math.floor(Math.random() * h) + '" stroke="#3a4250" stroke-width="1"/>');
  }
  for (let i = 0; i < 4; i++) {
    const rot = (Math.random() * 40 - 20).toFixed(0);
    const dy = Math.floor(Math.random() * 6);
    parts.push('<text x="' + xs[i] + '" y="' + (28 + dy) + '" fill="#e8eaed" font-size="24" font-family="monospace" transform="rotate(' + rot + ' ' + (xs[i] + 8) + ' 20)">' + text[i] + '</text>');
  }
  parts.push('</svg>');
  return { token, svg: parts.join(''), answer: text };
}

function verifyCaptcha(token, input) {
  const c = captchaStore[token];
  if (!c) return false;
  delete captchaStore[token];
  if (Date.now() - c.at > 5 * 60 * 1000) return false;
  return String(input).toUpperCase() === c.answer;
}

setInterval(() => {
  const now = Date.now();
  for (const k of Object.keys(captchaStore)) {
    if (now - captchaStore[k].at > 5 * 60 * 1000) delete captchaStore[k];
  }
}, 60 * 60 * 1000);

// ---------- Key ----------
function createUserKey(userId, label, accountIds) {
  const key = 'lm-' + crypto.randomBytes(20).toString('hex');
  const accJson = JSON.stringify(Array.isArray(accountIds) ? accountIds : []);
  udb.prepare('INSERT INTO keys (key, user_id, label, account_ids, created_at) VALUES (?,?,?,?,?)')
     .run(key, userId, label || '', accJson, Date.now());
  return key;
}

/** 按 Key 绑定关系挑账号（支持轮询）：返回 {cookie, session, id} 或 null */
function pickAccountForKey(userId, accountIdsJson, callsCount) {
  let ids = [];
  try { ids = JSON.parse(accountIdsJson || '[]'); } catch (e) { ids = []; }
  let rows;
  if (Array.isArray(ids) && ids.length > 0) {
    const ph = ids.map(() => '?').join(',');
    rows = udb.prepare(
      'SELECT id, cookie, session FROM upstream_accounts WHERE user_id=? AND enabled=1 AND id IN (' + ph + ') ORDER BY id'
    ).all(userId, ...ids);
  } else {
    // 未绑定：用该用户全部启用账号（轮询）
    rows = udb.prepare(
      'SELECT id, cookie, session FROM upstream_accounts WHERE user_id=? AND enabled=1 ORDER BY id'
    ).all(userId);
  }
  if (!rows || !rows.length) return null;
  // 轮询：按调用次数取模
  const idx = Math.abs(Number(callsCount) || 0) % rows.length;
  const r = rows[idx];
  return { id: r.id, cookie: decryptCred(r.cookie), session: decryptCred(r.session), _poolSize: rows.length, _idx: idx };
}

function getUserByKey(key) {
  const k = udb.prepare('SELECT * FROM keys WHERE key=?').get(String(key || ''));
  if (!k || !k.enabled) return null;
  const u = udb.prepare('SELECT * FROM users WHERE id=?').get(k.user_id);
  if (!u) return null;
  return { user: u, keyRow: k };
}

function bumpKeyCalls(key) {
  try {
    udb.prepare('UPDATE keys SET calls = calls + 1, last_used_at = ? WHERE key = ?').run(Date.now(), key);
  } catch (e) { /* ignore */ }
}

// ---------- 凭证加密（AES-256-GCM）----------
// 密钥来自 env CRED_KEY（64 位 hex = 32 字节），与数据库分离存储。
const CRED_KEY_HEX = process.env.CRED_KEY || '';
let CRED_KEY = null;
if (CRED_KEY_HEX && CRED_KEY_HEX.length === 64) {
  try { CRED_KEY = Buffer.from(CRED_KEY_HEX, 'hex'); } catch (e) { CRED_KEY = null; }
}
if (!CRED_KEY) {
  console.log('[v2db] 警告：CRED_KEY 未配置或格式错误，凭证将以明文存储');
}

const ENC_PREFIX = 'enc:v1:';

function encryptCred(plain) {
  if (!plain) return '';
  if (!CRED_KEY) return plain;              // 无密钥则明文（兼容）
  if (String(plain).startsWith(ENC_PREFIX)) return plain;   // 已加密跳过
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', CRED_KEY, iv);
    const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return ENC_PREFIX + Buffer.concat([iv, tag, enc]).toString('base64');
  } catch (e) {
    console.log('[v2db] 加密失败:', e.message);
    return plain;
  }
}

function decryptCred(stored) {
  if (!stored) return '';
  if (!String(stored).startsWith(ENC_PREFIX)) return stored;   // 明文（存量）
  if (!CRED_KEY) return '';                                     // 有密文但无密钥
  try {
    const raw = Buffer.from(String(stored).slice(ENC_PREFIX.length), 'base64');
    const iv = raw.slice(0, 12);
    const tag = raw.slice(12, 28);
    const data = raw.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', CRED_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
  } catch (e) {
    console.log('[v2db] 解密失败（密钥变更?）:', e.message);
    return '';
  }
}

module.exports = {
  encryptCred,
  decryptCred,
  udb,
  hashPassword,
  createUser,
  verifyUser,
  addUsage,
  getUserStats,
  genCaptcha,
  verifyCaptcha,
  createUserKey,
  getUserByKey,
  pickAccountForKey,
  bumpKeyCalls
};
