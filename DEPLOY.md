# OpenAI 兼容中转网关 —— 部署文档（脱敏版）

> 一个零依赖的 Node.js 网关：把「会话型上游助手 API」转换成**标准 OpenAI 接口**（`/v1/models`、`/v1/chat/completions`，支持流式与 function calling），并自带多用户、注册邀请码、独立 Key、按用户绑定上游账号。
>
> **本包已脱敏**：域名、IP、手机号、API Key、密码、会话密钥全部替换为占位符，需你自行填写。

---

## 1. 架构

```
浏览器 / 客户端 (OpenAI SDK、Cherry Studio、Cline …)
        │  HTTPS
        ▼
      nginx  (your-domain.example.com)
        ├── /admin | /login | /auth  → 127.0.0.1:7868  可选的管理容器（自带界面 + Basic Auth）
        └── 其它                      → 127.0.0.1:7867  本网关（SSE 不缓冲）
                                            │
                                            ├── todayai-* 模型 → todayai.js → 上游助手 API（会话型）
                                            └── 其它模型      → 127.0.0.1:7868 上游容器（可选通道）
```

- 网关进程：`pm2` 托管，监听 `127.0.0.1:7867`
- 网关→上游的两种适配都在服务端完成，客户端只看到标准 OpenAI 协议

## 2. 目录结构

```
src/
├── server.js                 主网关：HTTP 服务、鉴权、限流、OpenAI 路由、SSE 转发
├── todayai.js                上游适配层（会话型助手 API ⇄ OpenAI 协议，含多账号/JWT 续期/tools）
├── toolbridge.js             tools/function calling ⇄ 提示词 协议桥（零依赖）
├── v2db.js                   多用户数据层（SQLite / node:sqlite）：用户、Key、绑定账号、用量
├── v2routes.js               注册 / 登录 / 我的 Key / 账号绑定 / 额度 路由
├── upstream-direct.js        备用通道：用户自带 cookie 直连上游 Web
├── upstream-account-node.js  上游账号工具（Node 版）
├── tools-upstream-account.py 上游账号工具（Python 版，可选）
├── index.html                控制台前端（旧版残留，服务实际使用 public/index.html）
├── public/index.html         控制台前端（单页，用户中心 + Key 管理 + 账号绑定）
└── ecosystem.config.js       pm2 配置（**密钥需你填写**）
deploy/
├── nginx-today.conf          nginx vhost 模板（改域名/证书/htpasswd 路径）
├── docker-compose.yml        可选：上游容器（若你的上游需要独立容器）
├── config_override.py        可选：上游容器配置覆盖（模型清单等）
├── app_override.py           可选：上游容器应用覆盖
└── upstream_client_override.py 可选：上游容器客户端覆盖
```

## 3. 环境要求

| 组件 | 版本 | 说明 |
|---|---|---|
| Node.js | **≥ 20（建议 22 LTS）** | 用到 `node:sqlite`（22 内置，实验特性会有 warning） |
| pm2 | 任意 | 进程守护 |
| nginx | 任意 | TLS + SSE 反代 |
| docker + compose | 可选 | 仅当你需要 `deploy/` 里的上游容器 |

**无 npm 依赖**，不需要 `npm install`。

## 4. 部署步骤

### 4.1 上传源码

```bash
mkdir -p /www/today-gateway/data
# 把 src/ 下所有文件上传到 /www/today-gateway/
cp -r src/* /www/today-gateway/
chmod 600 /www/today-gateway/*.js
cd /www/today-gateway && node --check server.js && node --check todayai.js && echo OK
```

### 4.2 生成密钥并填写配置

```bash
openssl rand -hex 24   # → UPSTREAM_API_KEY（调用上游容器/接口用）
openssl rand -hex 24   # → ADMIN_TOKEN
openssl rand -hex 32   # → CRED_KEY（用户绑定凭证的 AES-256-GCM 密钥，**长度必须 64 hex**）
openssl rand -hex 32   # → SESSION_SECRET（登录会话签名）
```

编辑 `ecosystem.config.js`：

| 变量 | 必填 | 说明 |
|---|---|---|
| `PORT` | ✅ | 网关端口，默认 `7867` |
| `UPSTREAM` | ✅ | 上游容器地址，默认 `http://127.0.0.1:7868` |
| `UPSTREAM_API_KEY` | ✅ | 调上游用的 Key（占位符 `REPLACE_WITH_UPSTREAM_API_KEY`） |
| `ADMIN_TOKEN` | ✅ | 管理接口令牌 |
| `ADMIN_PASS` | ✅ | 控制台/管理密码 |
| `REGCODE` | ⬜ | 兼容用固定注册码（邀请码以 `data/regcodes.json` 为准） |
| `CRED_KEY` | ✅ | 64 位 hex；**丢失会导致已绑定的账号凭证无法解密** |
| `SESSION_SECRET` | ✅ | 会话签名密钥 |

> ⚠️ 三个密钥一旦上线不要改（改 `CRED_KEY` 会让用户已绑定的上游账号失效；改 `SESSION_SECRET` 会让所有用户掉线）。

### 4.3 初始化邀请码

```bash
node -e 'const fs=require("fs");const f="/www/today-gateway/data/regcodes.json";
const A="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
let k="";for(let i=0;i<10;i++)k+=A[Math.floor(Math.random()*A.length)];
let c={};try{c=JSON.parse(fs.readFileSync(f))}catch(e){}
c[k]={used:false,usedBy:null,usedAt:null,createdAt:Date.now()};
fs.writeFileSync(f,JSON.stringify(c,null,2));console.log("邀请码:",k)'
```

### 4.4 启动

```bash
cd /www/today-gateway
pm2 start ecosystem.config.js
pm2 save
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:7867/   # 期望 200
```

### 4.5 nginx（TLS + SSE）

`deploy/nginx-today.conf` 是模板，按下表替换后放到 `/www/server/panel/vhost/nginx/`（或你的 sites 目录）：

| 模板里的值 | 改成 |
|---|---|
| `your-domain.example.com` | 你的域名 |
| `your-domain.example.com.crt` / `.key` | 你的证书路径 |
| `htpasswd 文件路径` | 你给管理面板生成的 htpasswd |

关键点（SSE 流式必须）：

```nginx
location / {
    proxy_pass http://127.0.0.1:7867;
    proxy_http_version 1.1;
    proxy_buffering off;          # ← 不关会导致流式被缓冲
    proxy_cache off;
    proxy_read_timeout 300s;
    proxy_send_timeout 300s;
    chunked_transfer_encoding on;
}
```

证书（acme.sh 示例）：

```bash
acme.sh --issue -d your-domain.example.com --webroot /www/wwwroot/your-domain.example.com --keylength ec-256
acme.sh --install-cert -d your-domain.example.com --ecc \
  --key-file       /www/server/panel/vhost/cert/your-domain.example.com/privkey.pem \
  --fullchain-file /www/server/panel/vhost/cert/your-domain.example.com/fullchain.pem \
  --reloadcmd      "nginx -s reload"
nginx -t && nginx -s reload
```

### 4.6 可选：上游容器

```bash
mkdir -p /opt/upstream2api/data
cd /opt/upstream2api && cp <本包>/deploy/{docker-compose.yml,config_override.py,app_override.py,upstream_client_override.py} .
vi .env            # UPSTREAM_API_KEY / ADMIN_TOKEN / PUBLIC_HOST 等（compose 用 env_file 读取）
docker compose up -d
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:7868/health
```

> compose 里的 `image:` 请改成你自己构建的镜像名（本包脱敏后不指向任何具体镜像）。

## 5. 上游适配层（`todayai.js`）——接别的上游看这节

网关对上游只做两类事：**认证换取令牌** 与 **发消息 + 轮询取回**。当前实现针对一类「会话型助手 API」：

| 步骤 | 请求 |
|---|---|
| 换 JWT | `POST https://<上游站点>/api/token`，body `{"audience":"<上游 API 域>"}`，带登录 Cookie → `{token}`（注意 `audience` 通常要求带 `https://` 前缀） |
| 发消息 | `POST https://<上游 API 域>/v1/messages`，`Authorization: Bearer <JWT>`，body `{"content":"..."}` → `{threadId, conversationId}`（HTTP 202 也算成功） |
| 取回复 | `GET /v1/conversations/messages?conversationId=<账号ID>&limit=5` → `data.items[]`，筛 `threadId` + `role=assistant`，正文在 `body.parts[].content.text`，`state=completed && isFinal=true` 表示结束 |
| 模型清单 | `GET /v1/pricing/status` → `data.status.modelOptions.options[]` |
| 切模型 | `PUT /v1/pricing/model-option`，body `{"optionId":"..."}`（**账号级偏好**，非每请求参数） |

**换成通用 OpenAI 兼容上游**：把 `todayai.js` 里 `handleChat()` 的“发消息+轮询”两段替换成一次 `POST <上游>/v1/chat/completions` 透传（含 `stream`）即可，其余（用户体系、Key、限流、SSE 转发）无需改。

## 6. 对外接口

| 接口 | 说明 |
|---|---|
| `POST /api/register` | 注册（需邀请码，一次性、用后销毁） |
| `POST /api/user/login` | 登录（图形验证码） |
| `GET /api/me`、`GET /api/my/keys`、`POST /api/my/keys`、`DELETE /api/my/keys/:key` | 用户中心 / Key 管理 |
| `GET /api/my/todayai`、`POST /api/my/todayai/sms`、`POST /api/my/todayai/bind`、`DELETE /api/my/todayai/:id` | 绑定上游账号（手机号 + 短信验证码）；改上游时改这几个路由即可 |
| `GET /api/my/todayai/usage` | 账号额度/套餐 |
| `GET /v1/models` | OpenAI 模型列表（**实时从上游拉取**；上游失败时回退到内置别名，不会伪造模型） |
| `POST /v1/chat/completions` | OpenAI 对话，支持 `stream` 与 `tools` |

鉴权：`Authorization: Bearer <用户 Key>`。

## 7. 运维

```bash
pm2 restart gateway                 # 重启
pm2 logs gateway --lines 100        # 日志
tail -f /root/.pm2/logs/gateway-out.log

# 加邀请码（同 4.3）
# 备份（务必包含 data/：用户库 + 邀请码 + 绑定凭证）
tar czf /root/gateway-backup-$(date +%F).tgz -C /www today-gateway
```

## 8. 已知限制（上游产品决定，非网关 bug）

1. **上游会话不可新建**：`conversationId` 固定为上游账号 ID，一个账号一份历史 → 不要用同一个上游账号服务多个用户（会互相看到上下文/档案）。**建议每个用户绑自己的账号**。
2. **模型可能带“人格”与账号档案**：若上游是消费级助手产品，它会把自己的身份（昵称/设备/已连接服务）注入模型上下文，被问到身份类问题时可能吐出来，网关无法关闭。要干净行为请接通用模型 API（见第 5 节）。
3. **tools 受上游会话记忆影响**：同一账号在同一话题重复请求时，上游可能直接作答而不触发工具调用。
4. 上游若为“整段返回”，流式首个内容块 ≈ 生成完成时间。
5. `CRED_KEY` 与 `SESSION_SECRET` 改动的后果见 4.2。

## 9. 脱敏对照表

| 本包中的占位符 | 原值类型 | 你需要填 |
|---|---|---|
| `your-domain.example.com` | 站点域名 | 你的域名 |
| `YOUR_SERVER_IP` | 服务器 IP | 你的服务器 |
| `other-site.example.com` | 另一站点域名（注释中） | 可忽略/删除 |
| `REPLACE_WITH_UPSTREAM_API_KEY` | 上游调用 Key | 新生成 |
| `REPLACE_WITH_ADMIN_PASSWORD` | 管理员密码 | 自定 |
| `REPLACE_WITH_RANDOM_HEX` | 管理令牌 / 会话密钥 | 新生成 |
| `REPLACE_WITH_64HEX_CRED_KEY` | 凭证加密密钥（64 hex） | 新生成 |
| `REPLACE_WITH_INVITE_CODE` | 兼容固定邀请码 | 可自定 |
| `YOUR_PHONE_NUMBER` | 测试用手机号 | 删除即可 |
