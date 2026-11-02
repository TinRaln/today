'use strict';

/**
 * toolbridge —— 中转站的 function calling 支持。
 *
 * 上游（Upstream Web API）不认识 OpenAI 的 tools 协议，只接受单个 content 字符串。
 * 这里做协议转换：
 *
 *   出站：tools 定义 → 注入提示词，要求模型输出纯 JSON
 *         {"tool_calls":[{"name":"...","arguments":{...}}]}
 *   入站：从模型输出里提取 JSON → 还原成标准 tool_calls
 *
 * 实现参考 xtekky/gpt4free 的 g4f/providers/tool_support.py（ToolSupportProvider），
 * 关键点：纯 JSON 协议、多层容错解析、平衡括号提取、结构化多轮降级。
 */

// ==================== 协议提示词 ====================

function buildToolPrompt(tools) {
  const names = tools
    .map((t) => ((t && t.function) || t || {}).name)
    .filter(Boolean);

  const lines = [
    'You have access to the following tools and you are REQUIRED to use them.',
    '',
    'CRITICAL RULES — violating these is a task failure:',
    '1. If the task needs any information or action a tool can provide, you MUST call that',
    '   tool IN THIS VERY REPLY. Not next turn. Not after asking the user.',
    '2. NEVER ask the user for information a tool could obtain (file paths, existence of a',
    '   file, directory contents, system state). If unsure whether something exists or where',
    '   it is, CALL A TOOL to check. Do not assume, do not ask.',
    '3. NEVER claim you cannot do something, and never end your reply with a question, when',
    '   a tool call could move the task forward.',
    '4. How to reply when calling tools: write ONE short sentence saying what you are doing,',
    '   then on its own line output exactly this JSON object:',
    '   {"tool_calls": [{"name": "TOOL_NAME", "arguments": {}}]}',
    '   Multiple calls may go in the array. `arguments` MUST be a JSON object matching that',
    '   tool\'s parameter schema. Never send JSON-only with no sentence, and never send the',
    '   sentence without the JSON.',
    '5. Only when the task is FULLY answerable with no tool at all, reply with plain text',
    '   and no JSON.',
    '',
    'IMPORTANT: You have no internet access and cannot read files on your own.',
    'Any realtime fact or file/system access MUST go through a tool call.',
    'Do not fabricate such data from memory.',
    '',
    `Available tools: ${names.join(', ')}`
  ];

  for (const t of tools) {
    const fn = (t && t.function) || t || {};
    if (!fn.name) continue;
    let line = `- Tool \`${fn.name}\``;
    if (fn.description) line += `: ${fn.description}`;
    lines.push(line);
    if (fn.parameters) {
      let schema;
      try {
        schema = JSON.stringify(fn.parameters);
      } catch (e) {
        schema = '{}';
      }
      if (schema.length > 2000) schema = schema.slice(0, 2000) + '…';
      lines.push(`  Parameter Schema: ${schema}`);
    }
  }

  return lines.join('\n');
}

// ==================== 解析工具函数 ====================

/** 去掉 markdown 代码围栏 */
function stripCodeFences(text) {
  if (!text) return text;
  let t = String(text).trim();
  let m = t.match(/^```(?:json|JSON)?\s*\n?([\s\S]*?)\n?```\s*$/);
  if (m) return m[1].trim();
  m = t.match(/^```(?:json|JSON)?\s*\n?([\s\S]*)$/);
  if (m) return m[1].trim();
  return t;
}

/** 从起点提取平衡的 JSON 对象/数组（正确处理字符串内的括号与转义） */
function extractBalancedJson(s, start) {
  if (start >= s.length) return ['', start];
  const openCh = s[start];
  if (openCh !== '{' && openCh !== '[') {
    let end = s.indexOf('\n', start);
    if (end === -1) end = s.length;
    return [s.slice(start, end).trim(), end];
  }
  const closeCh = openCh === '{' ? '}' : ']';
  let depth = 0;
  let inStr = false;
  let escape = false;
  let i = start;
  while (i < s.length) {
    const ch = s[i];
    if (inStr) {
      if (escape) escape = false;
      else if (ch === '\\') escape = true;
      else if (ch === '"') inStr = false;
    } else {
      if (ch === '"') inStr = true;
      else if (ch === openCh) depth++;
      else if (ch === closeCh) {
        depth--;
        if (depth === 0) return [s.slice(start, i + 1), i + 1];
      }
    }
    i++;
  }
  return [s.slice(start).trim(), s.length];
}

/** 多级容错地解析 JSON */
function parseJsonMaybe(input) {
  if (!input) return null;
  let s = stripCodeFences(String(input)).trim();
  if (!s) return null;

  // 补全未闭合的右括号
  if (s.startsWith('{') && !s.endsWith('}')) s += '}';

  try {
    return JSON.parse(s);
  } catch (e) {
    /* 继续尝试 */
  }

  // 从混杂文本里抠出 JSON
  let candidate = null;
  const objMatch = s.match(/\{[\s\S]*\}/);
  if (objMatch) candidate = objMatch[0];

  if (!candidate) {
    const arrMatch = s.match(/\[[\s\S]*\]/);
    if (arrMatch) candidate = arrMatch[0];
  }
  if (!candidate) return null;

  try {
    return JSON.parse(candidate);
  } catch (e) {
    // 去掉尾逗号再试
    try {
      const fixed = candidate.replace(/,\s*([}\]])/g, '$1');
      return JSON.parse(fixed);
    } catch (e2) {
      return null;
    }
  }
}

function normalizeArgs(args) {
  if (args == null) return '{}';
  if (typeof args === 'string') {
    const t = args.trim();
    if (!t) return '{}';
    // 若本身就是合法 JSON 字符串，原样保留
    try {
      JSON.parse(t);
      return t;
    } catch (e) {
      return JSON.stringify({ value: t });
    }
  }
  try {
    return JSON.stringify(args);
  } catch (e) {
    return '{}';
  }
}

let callSeq = 0;

/**
 * 从模型输出中提取 tool_calls。
 * 兼容多种格式：
 *   {"tool_calls":[{"name":..,"arguments":{..}}]}
 *   {"name":..,"arguments":{..}}            （单个）
 *   [{"name":..,"arguments":{..}}, ...]      （裸数组）
 */
function parseToolCalls(text, validNames) {
  if (typeof text !== 'string' || !text.trim()) {
    return { toolCalls: [], cleaned: text || '' };
  }

  const nameSet = Array.isArray(validNames) && validNames.length
    ? new Set(validNames)
    : null;

  const cleanedText = stripCodeFences(text);
  const parsed = parseJsonMaybe(cleanedText);

  let rawCalls = null;

  if (parsed && typeof parsed === 'object') {
    if (Array.isArray(parsed.tool_calls)) rawCalls = parsed.tool_calls;
    else if (Array.isArray(parsed.tools)) rawCalls = parsed.tools;
    else if (Array.isArray(parsed)) rawCalls = parsed;
    else if (parsed.name || parsed.tool) rawCalls = [parsed];
    else if (parsed.function && parsed.function.name) rawCalls = [parsed.function];
  }

  if (!rawCalls) {
    return { toolCalls: [], cleaned: String(text).trim() };
  }

  const toolCalls = [];
  for (const c of rawCalls) {
    if (!c || typeof c !== 'object') continue;
    const fn = c.function || c;
    let name = fn.name || fn.tool || c.name || '';
    if (!name) continue;
    name = String(name).trim();
    // 有白名单时过滤掉不存在的工具名（避免模型编造）
    if (nameSet && !nameSet.has(name)) continue;

    const args = normalizeArgs(fn.arguments ?? fn.args ?? fn.parameters ?? fn.input ?? {});

    callSeq++;
    toolCalls.push({
      id: 'call_' + Date.now().toString(36) + '_' + callSeq,
      type: 'function',
      function: { name, arguments: args }
    });
  }

  if (!toolCalls.length) {
    return { toolCalls: [], cleaned: String(text).trim() };
  }

  // 纯 JSON 协议下，命中了 tool_calls 就不再保留正文（避免把 JSON 当答案发给用户）
  return { toolCalls, cleaned: '' };
}

// ==================== 消息降级 ====================

function extractText(content) {
  if (content == null) return '';
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .map((p) => {
        if (typeof p === 'string') return p;
        if (p && typeof p.text === 'string') return p.text;
        if (p && p.type === 'image_url') return '[image]';
        return '';
      })
      .filter(Boolean)
      .join('\n');
  }
  try {
    return JSON.stringify(content);
  } catch (e) {
    return String(content);
  }
}

/** 把 assistant 的 tool_calls 渲染成可读文本 */
function stringifyToolCalls(toolCalls) {
  return toolCalls
    .map((tc) => {
      const fn = tc.function || tc;
      const name = fn.name || 'unknown';
      const args = typeof fn.arguments === 'string' ? fn.arguments : JSON.stringify(fn.arguments || {});
      return `[Tool call: ${name}]\nArguments: ${args}`;
    })
    .join('\n\n');
}

/** 把 role=tool 的结果渲染成可读文本 */
function stringifyToolResponse(msg) {
  const name = msg.name || msg.tool_call_id || 'tool';
  const text = extractText(msg.content);
  return `[Tool response: ${name}]\n${text}`;
}

/**
 * 把 OpenAI 消息序列降级成上游能理解的纯文本消息。
 * system 暂存后拼到紧随的消息前面；tool/tool_calls 转成结构化文本。
 */
function downgradeMessages(messages) {
  const out = [];
  let pendingSystem = [];
  let toolTurnCount = 0;

  const flushSystem = () => {
    if (pendingSystem.length) {
      out.push({ role: 'user', content: '[System]\n' + pendingSystem.join('\n') });
      pendingSystem = [];
    }
  };

  for (const msg of messages || []) {
    if (!msg || typeof msg !== 'object') continue;
    const role = String(msg.role || 'user');
    const content = msg.content;

    if (role === 'system' || role === 'developer') {
      const t = extractText(content);
      if (t) pendingSystem.push(t);
      continue;
    }

    if (role === 'assistant' && Array.isArray(msg.tool_calls) && msg.tool_calls.length) {
      flushSystem();
      const text = extractText(content);
      const rendered = stringifyToolCalls(msg.tool_calls);
      out.push({
        role: 'assistant',
        content: [text, rendered].filter(Boolean).join('\n\n')
      });
      continue;
    }

    if (role === 'tool' || role === 'function') {
      toolTurnCount++;
      const rendered = stringifyToolResponse(msg);
      flushSystem();
      out.push({ role: 'user', content: rendered });
      continue;
    }

    if (role === 'user') {
      flushSystem();
      out.push({ role: 'user', content: extractText(content) });
      continue;
    }

    if (role === 'assistant') {
      flushSystem();
      out.push({ role: 'assistant', content: extractText(content) });
      continue;
    }

    flushSystem();
    out.push({ role: 'user', content: extractText(content) });
  }

  flushSystem();
  return { messages: out, toolTurnCount };
}

/**
 * 组装发往上游的 messages。
 *
 * Upstream 只接受单个 content，upstream2api 只取「最后一条 user 文本」，system 会被丢弃。
 * 因此工具协议必须由我们自己拼进最后一条 user 消息。
 */
function buildUpstreamMessages(messages, tools) {
  const { messages: downgraded, toolTurnCount } = downgradeMessages(messages);
  const toolPrompt = Array.isArray(tools) && tools.length ? buildToolPrompt(tools) : '';

  if (!toolPrompt) {
    return { messages: downgraded, hasTools: false, toolTurnCount, toolNames: [] };
  }

  const toolNames = tools
    .map((t) => ((t && t.function) || t || {}).name)
    .filter(Boolean);

  let lastUserIdx = -1;
  for (let i = downgraded.length - 1; i >= 0; i--) {
    if (downgraded[i].role === 'user') { lastUserIdx = i; break; }
  }

  if (lastUserIdx >= 0) {
    downgraded[lastUserIdx] = {
      role: 'user',
      content: toolPrompt + '\n\n---\n\nUser message:\n' + downgraded[lastUserIdx].content
    };
  } else {
    downgraded.push({ role: 'user', content: toolPrompt });
  }

  return { messages: downgraded, hasTools: true, toolTurnCount, toolNames };
}

// ==================== 响应组装 ====================

function buildCompletion({ id, model, content, toolCalls, usage }) {
  const message = { role: 'assistant', content: toolCalls.length ? null : content };
  if (toolCalls.length) message.tool_calls = toolCalls;

  return {
    id: id || 'chatcmpl-' + Date.now().toString(36),
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: model || 'upstream',
    choices: [{
      index: 0,
      message,
      finish_reason: toolCalls.length ? 'tool_calls' : 'stop'
    }],
    usage: usage || { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
  };
}

function buildSSEChunks(completion) {
  const { id, model, created } = completion;
  const choice = completion.choices[0];
  const msg = choice.message;
  const chunks = [];

  const frame = (delta, finish) => ({
    id, object: 'chat.completion.chunk', created, model,
    choices: [{ index: 0, delta, finish_reason: finish || null }]
  });

  chunks.push(frame({ role: 'assistant' }));

  if (msg.tool_calls && msg.tool_calls.length) {
    msg.tool_calls.forEach((tc, i) => {
      chunks.push(frame({
        tool_calls: [{
          index: i, id: tc.id, type: 'function',
          function: { name: tc.function.name, arguments: '' }
        }]
      }));
      chunks.push(frame({
        tool_calls: [{ index: i, function: { arguments: tc.function.arguments } }]
      }));
    });
    chunks.push(frame({}, 'tool_calls'));
  } else {
    const text = msg.content || '';
    for (let i = 0; i < text.length; i += 8) {
      chunks.push(frame({ content: text.slice(i, i + 8) }));
    }
    chunks.push(frame({}, 'stop'));
  }

  return chunks;
}

// ==================== 长度限制 ====================

// Upstream 上游硬限制：单条消息不能超过 32KB（Upstream HTTP 422 INVALID_MESSAGE_TOO_LARGE）。
// 上游还会在正文前拼接 IDENTITY_DIRECTIVE（约 500 字符），带 tools 时我们自己也注入
// 1~2KB 协议，因此阈值必须留足余量，否则 30000+包装 正好压线 32KB 会偶发 422。
const MAX_CONTENT_BYTES = 26000;

/**
 * 按字节安全切片，并回退到最近的换行，避免切断多字节字符或代码块。
 */
function safeSliceByBytes(text, budgetBytes, fromEnd) {
  const buf = Buffer.from(text, 'utf8');
  if (buf.length <= budgetBytes) return text;

  let slice;
  if (fromEnd) {
    slice = buf.slice(buf.length - budgetBytes);
  } else {
    slice = buf.slice(0, budgetBytes);
  }

  let s = slice.toString('utf8');

  // 去掉可能被切断的首尾残字（U+FFFD）
  if (fromEnd) s = s.replace(/^\uFFFD+/, '');
  else s = s.replace(/\uFFFD+$/, '');

  // 回退到换行边界，视觉上更干净；找不到就退回按 200 字节粗略截
  const nl = fromEnd ? s.indexOf('\n') : s.lastIndexOf('\n');
  if (nl > 0 && nl < s.length - 1) {
    s = fromEnd ? s.slice(nl + 1) : s.slice(0, nl);
  }

  return s;
}

/**
 * 若单条内容超过上游限制，做「保头保尾」截断。
 * @returns {{text: string, truncated: boolean, originalBytes: number, keptBytes: number}}
 */
function truncateContent(text, limitBytes = MAX_CONTENT_BYTES) {
  if (typeof text !== 'string' || !text) {
    return { text: text || '', truncated: false, originalBytes: 0, keptBytes: 0 };
  }

  const originalBytes = Buffer.byteLength(text, 'utf8');
  if (originalBytes <= limitBytes) {
    return { text, truncated: false, originalBytes, keptBytes: originalBytes };
  }

  // 头部留 60%：通常包含任务描述、代码开头；尾部留 40%：最近的上下文和问题
  const headBudget = Math.floor(limitBytes * 0.6);
  const tailBudget = Math.max(1000, limitBytes - headBudget - 220);

  const head = safeSliceByBytes(text, headBudget, false);
  const tail = safeSliceByBytes(text, tailBudget, true);

  const keptBytes = Buffer.byteLength(head, 'utf8') + Buffer.byteLength(tail, 'utf8');
  const omitted = originalBytes - keptBytes;

  const marker =
    `\n\n...[内容过长已截断：原文 ${originalBytes} 字节，` +
    `此处省略中间 ${omitted} 字节，仅保留开头与结尾]...\n\n`;

  return {
    text: head + marker + tail,
    truncated: true,
    originalBytes,
    keptBytes
  };
}

/**
 * 对整组 messages 做长度限制：只截断超过限制的消息（通常是最后一条 user 或超长工具结果）。
 * @returns {{messages: Array, truncated: boolean, details: Array}}
 */
function enforceMessageLimits(messages, limitBytes = MAX_CONTENT_BYTES) {
  const details = [];
  let truncated = false;

  const out = (messages || []).map((m, i) => {
    if (!m || typeof m.content !== 'string') return m;
    const r = truncateContent(m.content, limitBytes);
    if (r.truncated) {
      truncated = true;
      details.push({ index: i, role: m.role, from: r.originalBytes, to: r.keptBytes });
      return Object.assign({}, m, { content: r.text });
    }
    return m;
  });

  return { messages: out, truncated, details };
}

module.exports = {
  buildToolPrompt,
  stripCodeFences,
  extractBalancedJson,
  parseJsonMaybe,
  parseToolCalls,
  downgradeMessages,
  buildUpstreamMessages,
  buildCompletion,
  buildSSEChunks,
  stringifyToolCalls,
  stringifyToolResponse,
  truncateContent,
  enforceMessageLimits,
  MAX_CONTENT_BYTES
};
