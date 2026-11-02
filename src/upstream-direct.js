'use strict';

/**
 * upstream-direct —— 用用户的 Web cookie 直连 Upstream Web 聊天接口。
 *
 * 关键事实（实测）：
 *  - Upstream Web 接口 https://upstream.xunfei.cn/web/api/chat/completions 的 SSE
 *    本身就是 OpenAI 格式（data: {"choices":[{"delta":{"content":...}}]}）
 *  - 请求需带 messageId，格式 "cloud-user-<序号>"
 *  - 请求体：{ conversationId:"", messageId, model, content }
 *  - 响应额外带 upstream 元数据（conversationId 等），可透传或剥离
 */

const https = require('https');
const crypto = require('crypto');

const UPSTREAM_WEB = 'https://upstream.xunfei.cn/web/api/chat/completions';

/** 把 OpenAI messages 转成 Upstream content（取最后一条 user 文本） */
function openaiToUpstreamContent(messages) {
  const users = (messages || []).filter((m) => m.role === 'user' && m.content);
  return users.length ? String(users[users.length - 1].content) : '';
}

/** 从 OpenAI 请求构造 Upstream 请求体 */
function buildUpstreamPayload(body) {
  return {
    conversationId: '',
    messageId: 'cloud-user-' + (Date.now() % 999999),
    model: body.model || 'DeepSeek-V4.1-Flash',
    content: openaiToUpstreamContent(body.messages)
  };
}

/**
 * 直连 Upstream（流式透传）。
 * @returns Promise<boolean> true=已处理
 */
function upstreamDirectStream(req, res, body, cookie, timeoutMs = 300000) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(buildUpstreamPayload(body)));
    const up = https.request({
      host: 'upstream.xunfei.cn', port: 443,
      path: '/web/api/chat/completions', method: 'POST',
      headers: {
        'Cookie': cookie,
        'Content-Type': 'application/json',
        'Origin': 'https://upstream.xunfei.cn',
        'Referer': 'https://upstream.xunfei.cn/web',
        'Accept': 'text/event-stream',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
        'Content-Length': payload.length
      },
      timeout: timeoutMs
    }, (upRes) => {
      if (upRes.statusCode >= 400) {
        const bufs = [];
        upRes.on('data', (c) => bufs.push(c));
        upRes.on('end', () => reject({ status: upRes.statusCode, body: Buffer.concat(bufs).toString('utf8') }));
        return;
      }
      // SSE 已是 OpenAI 格式，直接透传
      const headers = Object.assign({}, upRes.headers);
      delete headers['set-cookie'];
      if (res.headersSent) { upRes.resume(); return resolve(true); }
      res.writeHead(upRes.statusCode, headers);
      upRes.pipe(res);
      upRes.on('end', () => resolve(true));
      upRes.on('error', () => resolve(true));
    });
    up.on('timeout', () => { try { up.destroy(); } catch (e) {} reject(new Error('upstream direct timeout')); });
    up.on('error', reject);
    up.write(payload);
    up.end();
  });
}

/** 直连 Upstream（非流式：缓冲 SSE 聚合成 OpenAI completion） */
function upstreamDirectNonStream(body, cookie, timeoutMs = 180000) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(buildUpstreamPayload(body)));
    const up = https.request({
      host: 'upstream.xunfei.cn', port: 443,
      path: '/web/api/chat/completions', method: 'POST',
      headers: {
        'Cookie': cookie, 'Content-Type': 'application/json',
        'Origin': 'https://upstream.xunfei.cn', 'Referer': 'https://upstream.xunfei.cn/web',
        'Accept': 'text/event-stream',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
        'Content-Length': payload.length
      },
      timeout: timeoutMs
    }, (upRes) => {
      if (upRes.statusCode >= 400) {
        const bufs = [];
        upRes.on('data', (c) => bufs.push(c));
        upRes.on('end', () => reject({ status: upRes.statusCode, body: Buffer.concat(bufs).toString('utf8') }));
        return;
      }
      let buf = '';
      let text = '';
      let id = null;
      let model = null;
      let finished = false;

      upRes.setEncoding('utf8');
      upRes.on('data', (chunk) => {
        buf += chunk;
        let nl;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          if (!line.startsWith('data:')) continue;
          const data = line.slice(5).trim();
          if (data === '[DONE]') { finished = true; continue; }
          let obj;
          try { obj = JSON.parse(data); } catch (e) { continue; }
          if (obj.id) id = obj.id;
          if (obj.model) model = obj.model;
          const ch = (obj.choices || [])[0];
          if (ch && ch.delta && typeof ch.delta.content === 'string') text += ch.delta.content;
          if (ch && ch.finish_reason) finished = true;
        }
      });
      upRes.on('end', () => {
        resolve({
          status: 200,
          json: {
            id: id || ('chatcmpl-' + crypto.randomBytes(8).toString('hex')),
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: model || body.model,
            choices: [{ index: 0, message: { role: 'assistant', content: text || null }, finish_reason: 'stop' }]
          }
        });
      });
      upRes.on('error', reject);
    });
    up.on('timeout', () => { try { up.destroy(); } catch (e) {} reject(new Error('upstream direct timeout')); });
    up.on('error', reject);
    up.write(payload);
    up.end();
  });
}

module.exports = { upstreamDirectStream, upstreamDirectNonStream, openaiToUpstreamContent };
