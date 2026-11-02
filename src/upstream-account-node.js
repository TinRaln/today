'use strict';

/**
 * upstream-account —— Node 实现客户端账号服务（account.xfinfr.com）签名 + 短信登录。
 * 用于：用户绑定 Upstream 账号时，一条短信验证码 → session → 快通道（upstreamad）。
 *
 * 签名算法（HMAC-SHA1，stringToSign 固定 9 行）逆向自开源项目。
 */

const https = require('https');
const crypto = require('crypto');

const AK_ID = '2thryby66wxi53sk';
const AK_SECRET = 'zsak6eadrbawz683wf5r3m2snrwj868r';
const ACCOUNT_HOST = 'account.xfinfr.com';

function escapePath(p) {
  let s = p.startsWith('/') ? p : '/' + p;
  if (s.length > 1 && s.endsWith('/')) s = s.slice(0, -1);
  return s.split('/').map(seg => encodeURIComponent(seg)).join('/');
}

function contentMd5(body) {
  if (!body) return '';
  return crypto.createHash('md5').update(body).digest('base64');
}

function buildStringToSign(method, path, body, contentType, date, nonce) {
  const lines = [
    method.toUpperCase(),
    escapePath(path),
    '',
    contentMd5(body),
    contentType,
    date,
    nonce,
    '',
    ''
  ];
  return lines.join('\n');
}

function buildHeaders(method, path, body) {
  const date = new Date().toUTCString();
  const nonce = crypto.randomUUID();
  const ctype = 'application/json';
  const sts = buildStringToSign(method, path, body, ctype, date, nonce);
  const sig = crypto.createHmac('sha1', AK_SECRET).update(sts).digest('base64');
  const headers = {
    'Authorization': 'hmac ' + AK_ID + ':' + sig,
    'Date': date,
    'Nonce': nonce,
    'Content-Type': ctype,
    'Accept': 'application/json',
    'User-Agent': 'Upstream/0.9.38'
  };
  const md5s = contentMd5(body);
  if (md5s) headers['Content-MD5'] = md5s;
  return headers;
}

function envelope(param) {
  return JSON.stringify({
    base: {
      appid: 'GM3UPSTREAM',
      modelid: 'Web',
      version: '1.0.0',
      devid: 'web',
      ua: 'Upstream|Desktop|Electron|macOS',
      traceid: crypto.randomBytes(16).toString('hex')
    },
    param
  });
}

function accountRequest(path, param, timeoutMs = 25000) {
  return new Promise((resolve, reject) => {
    const body = envelope(param);
    const headers = buildHeaders('POST', path, body);
    headers['Content-Length'] = Buffer.byteLength(body);

    const req = https.request({
      host: ACCOUNT_HOST, port: 443, path, method: 'POST', headers, timeout: timeoutMs
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
    req.on('timeout', () => req.destroy(new Error('account timeout')));
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/** 发送短信验证码 → { ok, msgid } */
async function sendSms(phone) {
  const r = await accountRequest('/login/phone/sendMsgCode', {
    ccode: '86', phone: String(phone), expire: 300
  });
  const code = r.json && r.json.code;
  if (code !== '000000') {
    return { ok: false, msg: (r.json && r.json.desc) || '发送失败' };
  }
  return { ok: true, msgid: r.json.data.msgid };
}

/** 校验验证码 → { ok, session, nickname } */
async function checkCode(phone, code, msgid) {
  const r = await accountRequest('/login/phone/checkCode', {
    ccode: '86', phone: String(phone), mcode: String(code), msgid: String(msgid)
  });
  const j = r.json;
  if (!j || j.code !== '000000') {
    return { ok: false, msg: (j && j.desc) || '校验失败' };
  }
  const d = j.data || {};
  return { ok: true, session: d.session, nickname: d.nickname, userId: d.userid };
}

module.exports = { sendSms, checkCode, accountRequest };
