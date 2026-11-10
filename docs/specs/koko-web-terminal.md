# KoKo Web 终端与 Cookie 认证

## 目标

为 `jumpctl` 增加一条不依赖 JumpServer SSH 2222 端口的连接路径：使用浏览器已登录的 Cookie，申请连接令牌，通过 KoKo 的 HTTP WebSocket 终端协议进入已授权 Linux 资产的交互式 Shell。

范围是 `jumpctl` 的 `auth import-cookie` 与 `webssh` 两个命令，以及支撑它们的认证、连接令牌和 WebSocket 协议实现。KoKo 与 JumpServer 服务端不做任何修改。

不在本方案范围：SSH `ProxyCommand`、SFTP、端口转发、桌面 GUI 入口、OAuth 行为变更。终端流上的 ZMODEM 文件传输（`rz` / `sz`）复用 `internal/zmodem` 与 `internal/clitransfer`，交互与直接 SSH 相同。GUI 入口按用户明确限定的最小交付暂不实现，后续如需开放，复用本文的认证与协议核心。

## 目标环境

| 项 | 值 |
| --- | --- |
| JumpServer | v4.0.2，脚本化安装，`http://172.16.251.2` |
| 终端组件 | KoKo v4.0.2（`/koko` 反向代理路径） |
| 用户 | 普通 LDAP/AD 用户，无管理员权限 |
| 现状 | HTTP 80 可达；SSH 2222 超时；OAuth Discovery 返回 404；网页 Web 终端可用 |

## 方案要点

1. 新增 Cookie 会话凭据，与 OAuth Token 并列存放，按 Profile 隔离，只用于该 Profile 的 JumpServer Origin。
2. Profile 没有 OAuth 凭据时使用 Cookie 会话；存在 OAuth 凭据的 Profile 行为保持不变。
3. Cookie 模式下的写请求补充 `X-CSRFToken`，因为 JumpServer v4 的 Session 认证会校验 CSRF。
4. 用连接令牌 ID 连接 `/koko/ws/terminal/?token=<连接令牌 ID>`，按 KoKo 消息协议完成初始化与终端数据转发。
5. 终端输出按 WebSocket Binary Frame 原样写出，输入按 Binary Frame 发回，窗口变化用 `TERMINAL_RESIZE`。

## 认证与连接令牌

### Cookie 会话

- `import-cookie` 从终端隐藏读取浏览器 Cookie 串，解析为名值对，交给 `GET /api/v1/users/profile/` 当场验证；验证失败直接报错且不保存。
- 凭据写入现有私有凭据后端（文件后端或系统密钥环），键为 `cookie/<profile>`，不写入 `config.toml`。
- 保存字段：Profile 的站点 URL、全部 Cookie、CSRF Token、导入时间与最近一次校验时间。Cookie 值只用于 HTTP/WebSocket 请求头，不打印、不写日志。
- 站点绑定：保存时记录 Profile URL，使用时要求与当前 Profile URL 归一化后一致；不按 Cookie 自身的 Domain 发送，也不跨 Profile 复用。
- 不做 OAuth Refresh；Cookie 失效时命令报错并提示重新执行 `import-cookie`。
- `auth logout` 一并删除该 Profile 的 Cookie 会话。

### CSRF

JumpServer v4 的 DRF 认证链包含 `authentication.backends.drf.SessionAuthentication`（`apps/jumpserver/settings/libs.py`），它继承 DRF `SessionAuthentication` 并在 CSRF 校验失败时**不报错而是返回未认证**（`apps/authentication/backends/drf.py`）。因此纯 Cookie 的 `POST` 若缺少 `X-CSRFToken`，会表现为权限不足而不是明确的 CSRF 错误。

实现上从导入的 Cookie 中取名称以 `csrftoken` 结尾的值（JumpServer 默认名为 `jms_csrftoken`，见 `apps/jumpserver/settings/base.py` 的 `SESSION_COOKIE_NAME_PREFIX` 逻辑），在所有非安全方法上带 `X-CSRFToken`。浏览器 Cookie 串通常同时包含 `jms_sessionid` 与 `jms_csrftoken`；缺失时提示用户复制完整 Cookie。

### 连接令牌

`POST /api/v1/authentication/connection-token/` 的字段来自 `ConnectionTokenSerializer`（`apps/authentication/serializers/connection_token.py`）：

| 字段 | 取值 |
| --- | --- |
| `asset` | 资产 ID |
| `account` | 账号名（`account.alias`，如 `root`）；不是账号 ID，发送 ID 会得到 400 `perm_account_invalid` |
| `protocol` | `ssh` |
| `connect_method` | `web_cli` |
| `connect_options` | `{"file_name_conflict_resolution":"replace","terminal_theme_name":"Default"}`，兼容提交 |

`web_cli` 是 KoKo 组件对 `ssh` 协议提供的 Web 方式（`apps/terminal/connect_methods.py` 的 `ConnectMethodUtil.components()`）。响应 `201` 返回含 `id` 的对象；WebSocket 使用该 `id`。

## WebSocket 协议

### 路由与握手

| 项 | 事实 | 来源（KoKo v4.0.2） |
| --- | --- | --- |
| 路径 | `GET /koko/ws/terminal/` | `pkg/httpd/webrouter.go:69-70` |
| 认证 | `HTTPMiddleSessionAuth`：把请求全部 Cookie 交给 `GET /api/v1/users/profile/`，失败返回 302 到 `/core/auth/login/` | `pkg/auth/http.go:14`、`pkg/jms-sdk-go/service/jms_user.go:7` |
| 令牌参数 | Query `token`，值为**连接令牌 ID**；KoKo 以 `POST {"id": token}` 调服务端换取完整令牌 | `pkg/httpd/userwebsocket.go:43`、`pkg/jms-sdk-go/service/jms_token.go:9` |
| Origin | 不校验，`CheckOrigin` 恒为 true | `pkg/httpd/webserver.go:35` |
| 子协议 | 服务端声明 `JMS-KOKO`；客户端声明时握手返回同值 | `pkg/httpd/webserver.go:34` |

客户端 URL 由 Profile 站点 URL 决定：`http` → `ws`，`https` → `wss`，路径 `/koko/ws/terminal/?token=<ID>`。握手请求带 Cookie 头与 `Sec-WebSocket-Protocol: JMS-KOKO`。

### 消息信封

文本帧统一为 JSON：

```json
{"id":"<WebSocket 连接 ID>","type":"<类型>","data":"<JSON 字符串>","err":""}
```

`data` 是**字符串化的 JSON**，需要二次解析。二进制帧不套信封，内容即终端字节流。

| 类型 | 方向 | 编码 | 作用 |
| --- | --- | --- | --- |
| `CONNECT` | 服务端 → 客户端 | 文本 | 连接就绪，`id` 为服务端生成的 WebSocket 连接 ID，`data` 为 `{"user":{...},"setting":{...}}` |
| `TERMINAL_INIT` | 客户端 → 服务端 | 文本 | `{"id":"<CONNECT 的 id>","type":"TERMINAL_INIT","data":"{\"cols\":130,\"rows\":36}"}`，只接受一次，`id` 不匹配则丢弃 |
| `TERMINAL_SESSION` | 服务端 → 客户端 | 文本 | 资产会话建立成功，`data` 为 `{"session":{...},"permission":{"actions":[...]},"backspaceAsCtrlH":false,"ctrlCAsCtrlZ":false,"themeName":"Default"}` |
| `TERMINAL_DATA` | 客户端 → 服务端 | 文本 | 键盘输入，`data` 为字符串内容 |
| `TERMINAL_BINARY` | 双向 | **二进制帧** | 服务端：PTY 输出原始字节；客户端：输入原始字节（与 `TERMINAL_DATA` 等价） |
| `TERMINAL_RESIZE` | 客户端 → 服务端 | 文本 | `{"cols":N,"rows":N}` |
| `PING` | 双向 | 文本 | 服务端在空闲约 30 秒后发送；客户端每 25 秒发送一次保活，KoKo 收到后忽略，但会重置 5 分钟读取期限 |
| `CLOSE` | 双向 | 文本 | 会话结束；客户端发送时关闭后端连接 |
| `ERROR` | 服务端 → 客户端 | 文本 | `err` 字段为错误文本 |

### 关键源码位置

- 消息常量与 `WindowSize`：`pkg/httpd/message.go`。
- 升级与读写循环：`pkg/httpd/webserver.go:28-36`、`pkg/httpd/userwebsocket.go:118-215`。
- `CONNECT` 生成：`pkg/httpd/userwebsocket.go:167-181`。
- `TERMINAL_INIT` 处理与代理启动：`pkg/httpd/tty.go:59-115`。
- 输入与窗口变化：`pkg/httpd/tty.go:138-153`。
- 输出封装：`pkg/httpd/client.go:41-75`（1 毫秒防抖后合并为单条 Binary Frame）。
- `TERMINAL_SESSION`：`pkg/proxy/server.go:1033-1051` 与 `pkg/httpd/tty.go:375-378`；结构体 `pkg/proxy/server.go:162-170`。
- 空闲与超时：`pkg/httpd/userwebsocket.go:120-137`、`pkg/httpd/message.go` 的 `maxReadTimeout` / `maxWriteTimeOut`。

### 流程

```text
jumpctl                         JumpServer API            KoKo
  | GET /api/v1/users/profile/  ->   |
  | POST /authentication/connection-token/ (web_cli) -> |
  | <- 连接令牌 id                |
  | WS GET /koko/ws/terminal/?token=<id> (Cookie)      -> |
  | <- CONNECT {id: ws-id}                              |
  | TERMINAL_INIT {cols,rows} (id=ws-id)               -> |
  |                    资产 SSH 建立                     |
  | <- TERMINAL_SESSION {session,permission,...}         |
  | <- TERMINAL_BINARY (PTY 输出字节)                    |
  | TERMINAL_BINARY / TERMINAL_DATA (输入)              -> |
  | TERMINAL_RESIZE {cols,rows}                         -> |
  | CLOSE                                              -> |
  | <- CLOSE                                             |
```

## 交互行为

- 连接前提示 `Connecting to JumpServer via WebSocket...`；收到 `TERMINAL_SESSION` 后输出 `Connected: <资产> / <账号>`，随后远端提示符由 PTY 输出自然出现。
- 本地终端进入 Raw 模式，退出、断开、报错、Ctrl+D 后必须恢复原始终端状态；Raw 模式下 Ctrl+C 作为字节发给远端。
- 窗口变化通过 `SIGWINCH` 触发（Windows 用定时查询尺寸），发送 `TERMINAL_RESIZE`。
- 心跳：客户端每 25 秒发送协议内 `PING`（KoKo 忽略内容，但接收即重置其 5 分钟读取期限）；服务端发来的 JSON `PING` 直接忽略。
- 服务端返回 302、401、403 或非 101 状态时，报错并提示 Cookie 失效的处理方式，不重试。
- 终端数据不写入任何日志或调试输出。
- `webssh` 默认识别 ZMODEM：远端 `rz` 上传、`sz` 下载，`--download-dir` 指定下载目录；传输由远端命令发起，不提供 SFTP。

## 已知限制与风险

- 目标环境是 HTTP 80，Cookie 与终端数据经 VPN 内网明文传输。VPN 只保证链路可达与隧道加密，**不能替代** HTTPS，链路上任何中间设备都能读取会话 Cookie 与终端内容。启用 HTTPS 后本方案无需改动。
- Cookie 会话是浏览器会话，服务端过期、退出登录或在别处重新登录都可能导致失效；本方案不做自动续期。
- 会话数据是终端字节流，不是 TCP 隧道；不能承载端口转发或任意二进制协议。
- 连接令牌由服务端按其自身规则校验资产与账号权限，本方案只使用当前用户的合法授权。
- JumpServer 的 `connect_method` 是否在创建令牌时进一步限制为已启用的 Web 方式，尚未在真实环境验证；`web_cli` 是 KoKo 对 SSH 的默认 Web 方式，正常部署下可用。

## 验收标准

1. 有效 Cookie 能读取当前用户资料，无效 Cookie 立即报错且不保存。
2. 能列出授权资产，并为指定资产与账号申请 `web_cli` 连接令牌。
3. `TERMINAL_INIT` 使用 `CONNECT` 返回的 id，`TERMINAL_SESSION` 能被解析并展示资产与账号。
4. 键盘输入与远端输出双向可用，窗口调整生效，退出后本地终端状态恢复。
5. WebSocket 握手失败、Cookie 失效、令牌失效都给出明确错误，不泄露 Cookie 或令牌。
6. 现有 OAuth 与 SSH 命令行为不变。

## 当前状态

- 已实现：Cookie 会话的导入、按需校验（`jumpctl auth check`）与删除；JumpServer API 客户端的 Bearer／Cookie 双模式与 CSRF 头；`connect`、`resources` 使用统一认证解析；`jumpctl webssh` 的令牌申请、WebSocket 消息处理、窗口变化与终端恢复。
- 测试：`internal/credential`、`internal/jumpserver`、`internal/application/auth`、`internal/application/connect`、`internal/webterminal` 和 `internal/cli` 覆盖 Cookie 解析与存储、CSRF 写请求、认证方式选择、`web_cli` 令牌申请，以及用本地 WebSocket 服务模拟的完整消息交互。`internal/application/agentmcp` 的 ZMODEM 回退用例在本机因缺少 `sz`／`rz` 失败，改动前同样失败，与本次无关。
- 已用目标地址 `http://172.16.251.2` 做只读探测（2026-11-10）：`/koko/health/` 返回 200；匿名访问 `GET /api/v1/users/profile/` 返回 401；匿名 WebSocket 握手返回 302 到 `/core/auth/login/`；`POST` 连接令牌接口返回 401 而不是 404，确认路由存在；登录页下发的 Cookie 名为 `jms_sessionid` 与 `jms_csrftoken`。用伪造 Cookie 运行 `jumpctl asset list`、`jumpctl webssh` 和 `auth import-cookie`，均得到 `cookie session is invalid or expired ... run jumpctl auth import-cookie`，且导入失败不落盘。
- 未验证：使用真实浏览器 Cookie 的 `web_cli` 令牌申请和端到端终端会话。需要用户在已登录 JumpServer 网页的机器上按[命令参考](../cli.md#web-终端koko)完成验收。
- GUI：本次按用户限定的最小交付只实现 CLI。共享认证、资源和连接服务已支持 Cookie，GUI 如需开放 Web 终端可复用。
- MCP：`agentmcp` 的身份绑定仍以 OAuth 登录标识为准，Cookie 会话的 Profile 暂不能通过 MCP 连接。
