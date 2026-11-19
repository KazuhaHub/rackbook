# Rackbook 控制平面设计（草案，待 owner 确认，2026-11-19）

状态：只是设计，尚未实现。确认后由新的对话按本文实现；交接要点见文末。

一句话：Rackbook 从“台账”变成“台账 + 管理中心”。每台服务器跑一个 `rackbook-agent`，经 Tailscale 主动连回 Rackbook；所有动作都由模块完成，模块是带清单的签名插件，在沙箱里运行，只能做清单上写明并经管理员批准的事。

## 1. rackbook-agent（每台服务器一个）

- **怎么连**：Rackbook 用 tsnet 以自己的身份加入 tailnet（沿用 infra-hub 方案：固定地址、只认登记过的节点），agent 主动连过去并保持一条长连接，服务器上不开任何入站端口。
- **怎么认人**：Rackbook 对每个连接用 WhoIs 查出对方的 Tailscale 稳定节点 ID，再到台账 devices 里对号入座；agent 也核对对方确实是 Rackbook 那个节点。双方都不用令牌、密码或每模块密钥，身份就是 Tailscale 机器身份。
- **新机器**：一行命令（`tailscale up` 加上从 Rackbook 经 tailnet 下载并安装 agent）。装好后 agent 自动出现在「待批准」里；管理员确认（需二次验证）后，节点 ID 写进台账 devices，从此放行。未批准的机器只能出现在列表里，什么操作都收不到。
- **权限，root 尽量小**：agent 主体以普通用户 `rackbook-agent` 运行。需要 root 的只有一个很小的辅助程序，sudoers 里只放它一个，它只认固定的几个动词：写证书到登记路径、重载或重启登记的服务、执行 apt 装/卸/升级（包名校验）、运行 ansible-playbook、重启、关机。动词以外的请求一律拒绝。
- **安装和自更新**：二进制来自 GitHub release。agent 用 sigstore-go 验证签名，只认 rackbook 的 release.yml 签发的版本，验证通过后原子替换并重启。新版本 5 分钟内没连上 Rackbook，就自动退回旧版本。
- **离线**：任务在 Rackbook 排队，并各自带有效期：证书、下发类可以晚到；重启、关机类过期作废，不会隔天突然执行。离线期间机器上什么都不改；Rackbook 显示“最后在线时间”，离线超过阈值会进 notify。

## 2. 模块 = 插件（统一写法）

- **包**：`名称.rbmod` = `manifest.yaml` + `module.wasm` + 签名。manifest 里写：名称、版本、设置项（JSON Schema）、操作（每个操作的参数 schema、是否危险）、定时、需要的权限、在 hub 端还是 agent 端执行。
- **运行**：用 Extism（底层 wazero，纯 Go 的 WebAssembly 运行时）在沙箱里跑。模块碰不到文件、网络和密钥，只能调用 Rackbook 提供的少量“能力”，而且只能调用清单里声明并经管理员批准的那几个。能力包括：
  - 读写声明过的台账集合；
  - 访问声明过的 HTTPS 主机；
  - 发邮件；
  - ACME 签发；
  - 取声明过的密钥；
  - 向 agent 下发声明过的动词。
- **作者不用管网页和认证**：Rackbook 按 schema 自动生成设置页（复用 v0.4.0 的表单），按操作生成按钮和参数表单，定时由 Rackbook 调度。模块可以用 Go、Rust、TypeScript 等任何 Extism 支持的语言写。
- **第三方**：用 `rackbook mod build` 打包，用 cosign 签名。管理员在控制台上传或填 URL；安装时像手机装 App 一样列出它要的权限，确认后才启用。默认只信任 KazuhaHub 的签名者，其他发布者要管理员手动加入信任列表。
- **密钥**：Entra 证书私钥、SMTP 密码、Cloudflare 令牌仍由 infra 用 SOPS 部署成文件，放在 Rackbook 的 state 目录里（只读）。模块只能按名字取到自己声明过的那几个。
- **entra、notify 迁移**：改成 hub 端模块。台账读写走能力，不再用 API 令牌；Graph 访问限定在 `graph.microsoft.com` 和 `login.microsoftonline.com`；notify 发邮件用“发邮件”能力。迁完后删掉主机上的定时器和两个 API 令牌。

## 3. 首批模块和顺序

1. 框架：agent、批准流程、审计、二次验证、模块运行时；然后迁移 entra、notify。
2. 证书：Rackbook 内置 lego 签发（Cloudflare DNS-01），到期前 30 天自动续签；也可以手动“立即续签”。按台账里每台机器登记的证书名，经 agent 分发并重载服务；每台机器只拿得到自己的证书。取代 cert-hub 和 cert-pull，infra-hub 方案就并入 Rackbook，不再单独建仓库。
3. 下发：agent 从 Rackbook 经 tailnet 取 KazuhaHub/infra，只接受 GitHub 签名、并且是当前提交后代的提交，然后在本机跑 ansible-playbook。触发方式三种：网页按钮、合并后自动、新机器批准后自动。取代 infra-pull 定时器。
4. 电源（重启、关机，可以延时、取消）和软件（apt 装/卸/升级；成套的配置仍交给 Ansible，不重造）。
5. 监控：对接 Beszel API，在设备页显示在线状态和负载，并可以一键安装 beszel-agent。

## 4. 权限、二次验证、审计

- 默认所有操作只有 admin 能做，其他角色只读；模块清单不能给非 admin 授权。
- 危险操作（关机、重启、卸载、下发、批准新机器、安装模块）执行前要再验证一次身份：用通行密钥（Rackbook 已经支持），或重新走一次 OIDC 登录；验证后 5 分钟内有效。
- 每个操作留一条审计记录：谁、何时、哪台机器、哪个模块的哪个操作、参数（密钥自动打码）、结果、输出的最后几行。只追加，不能改；控制台可以按机器和人筛选。

## 5. 数据放哪

- 台账、配置、模块清单和设置：仍在 Git（rackbook.yml），改动带作者和 diff。
- 任务队列、agent 状态、审计、运行记录：放 state 目录里的一个 SQLite 文件（modernc.org/sqlite，纯 Go，不需要 CGO）。理由：有队列和多台 agent 并发，JSON 文件不够可靠；SQLite 单文件，备份就是拷贝一个文件，不需要另起数据库服务。

## 6. 迁移路径（每步可单独上线、可回退、不中断现有服务）

| 步 | 上线内容 | 回退方法 | 淘汰 |
|---|---|---|---|
| A | Rackbook 加 tsnet 入口；agent 只上报（在线、版本、系统信息）；审计、二次验证 | 停 agent | 无 |
| B | 模块运行时；entra、notify 改为模块，先和旧的并行跑一周、比对结果 | 重新打开主机定时器 | entra/notify 定时器和两个 API 令牌 |
| C | 证书模块，机器按 development → TW → 4c6g → production 逐台切换 | 该机器切回 cert-pull | cert-hub、cert-pull、它们的 deploy key |
| D | 下发；过渡期 infra-pull 改为每天一次兜底，稳定后删除 | 恢复 infra-pull 频率 | infra-pull 定时器 |
| E | 电源、软件 | 卸载模块 | 手工 ssh 操作 |
| F | Beszel 对接 | 卸载模块 | 无 |

搁置的 v0.5.0 模块面板分支里，这些可以复用：设置表单、运行记录界面、“立即运行”和暂停、调度判断函数。改用 API 令牌的那部分不再需要。

## 7. 版本和工作量（粗估，按执行代理的节奏）

- v0.5.0 = 步 A（约 1 周）
- v0.6.0 = 步 B（约 1.5 周）
- v0.7.0 = 步 C（约 1 周）
- v0.8.0 = 步 D（约 1 周）
- v0.9.0 = 步 E 和 F（约 1 周）

原先排在 v0.6.0 以后的授权服务器、GitHub App、记录文档、MCP 改名和存储，整体顺延到 v0.10.0 之后，到时再排。

现成组件：

| 用途 | 组件 |
|---|---|
| 入网和认人 | tailscale.com/tsnet（WhoIs） |
| 插件沙箱 | Extism（wazero） |
| 签名校验 | sigstore-go；打包签名用 cosign |
| 证书 | lego |
| 状态库 | modernc.org/sqlite |
| 下发 | Ansible |
| 软件 | apt |
| 二次验证 | go-webauthn（已在用） |
| 监控 | Beszel |

## 待 owner 确认

1. 新机器要管理员批准才放行，而不是装上就全自动信任。
2. 第三方模块用 WebAssembly 沙箱和权限清单，不允许跑任意原生程序。
3. agent 主体不用 root，只给一个固定动词的 root 辅助程序。
4. state 用 SQLite。
5. infra-hub 并入 Rackbook，不再单独建仓库。
6. 版本顺序：A → F 依次是 v0.5 到 v0.9。

## 交接（给接手实现的新对话）

### 先读这些规则
- 不在任何产物里署 AI 或代理的名字（提交、PR、分支、代码注释都不行）；不 force push 共享分支，不改写历史。
- 给 owner 和主会话看的内容用中文；代码、提交信息可以用英文。
- 合并或打 tag 之前：先用演示数据把改动跑起来，给 owner 看截图或页面，等 owner 亲口说 OK。CI 和审查通过都不够。
- 安全要简单：用标准机制，每个机制在 README 或 docs 里用一段大白话解释；设计变复杂时，先停下来提出更简单的方案。
- 模型分工：Opus 做规划、审查和关键决策，Sonnet 执行，Haiku 做大范围搜索。合并前做一轮对抗式审查（Opus）。
- Rackbook 只往 KazuhaHub/ledger 写；不要改 ~/Codes/infra（infra 由主会话负责）。

### 代码结构（main，v0.4.0）
- `cmd/rackbook`：服务端和 CLI（serve、check、token…）。`serve.go` 负责装配：认证、tokens.Registry、mcpauth.Resource、api.New；`--state-dir` 已经有（token-use.json）。
- `cmd/rackbook-entra`、`cmd/rackbook-notify`：现有的两个模块，独立二进制，用 API 令牌访问 Rackbook；共用客户端在 `modules/rbclient`。`modules/boundary_test.go` 保证 `modules/` 不 import `internal/`。
- `internal/`：
  - `api`（HTTP API 和控制台路由；`api.go:112` 附近是公开路径的白名单，注意 `RawPath` 检查）；
  - `auth`、`login`（OIDC、通行密钥、会话）；
  - `mcpauth`（Bearer：OAuth 和 `rbk_` 令牌）；
  - `tokens`；
  - `gitstore`（克隆的读写、提交、推送；`StateFile` 写 `.rackbook/*.yml`）；
  - `config`（rackbook.yml；`Module`、`checkModules`）；
  - `ledger`、`validate`；
  - `yamledit`（保留格式写 YAML；嵌套对象的键按 schema 顺序）；
  - `types`（类型编辑器：把改动写成一次提交，带 version 检查。改 rackbook.yml 的现成范例）；
  - `secretscan`（每次写入都扫描；拦截档绝不豁免；`x-rackbook: {public: <kind>}` 标注）；
  - `expiry`；
  - `roles`。
- `web/`：React 19、Vite、refine v5、react-router 7、@rjsf/shadcn。
  - 纯逻辑放在 `web/src/lib/*.ts`，不 import 任何东西，用 `web/scripts/check-*.mts` 测试，并加进 `.github/workflows/ci.yml`。
  - `RecordForm.tsx` 和 `form-widgets.tsx` 是按 schema 生成表单的地方，模块设置页可以直接复用。
- 发布：GoReleaser 先发草稿，签名和 attestation 都完成后才 publish（immutable release）。只从 main 上的 tag 发布，发布前先跑 6 平台原生测试门禁（`verify.yml`）。main 有 ruleset，必须通过 go、web、fuzz、cross-compile、docker 这几项检查。

### feat/modules-panel（v0.5.0 旧思路，已搁置，头部 78659d4）
这个分支里，可以直接搬过来或参考的有：
- `modsettings/schedule.go` 和 `Decide`：纯函数调度判断，输入时间、时区、上次运行、暂停、待执行请求，输出跑还是跳过，带测试。
- `modsettings/runs.go` 和 `internal/modules/state.go`：运行记录，最近 30 条，原子写入 state 目录。新设计改用 SQLite 后，可以借鉴数据结构，代码不必照搬。
- `internal/modules/edit.go`：把模块设置作为一次 Git 提交写进 rackbook.yml，带 version 检查和密钥扫描；flow 格式的条目会拒绝编辑。
- `internal/modules/preview.go`：entra 的“改动前预览”。
- `web/src/pages/Modules.tsx`、`ModuleDetail.tsx`、`components/modules/*`（运行记录表、状态徽标、确认改动的对话框、设置表单）以及 `lib/modules.ts`：界面基本可以复用，把数据源换成清单驱动即可。

不要复用的：模块用 API 令牌拉设置、上报运行结果（`modules/rbclient/panel.go`、`/api/modules/{name}/runs`、令牌页的模块标注）。新设计里身份来自 Tailscale，hub 端模块跑在 Rackbook 内部。

### 已知的坑
- 演示或测试时：Rackbook 启动会切换到 `write.branch`（通常是 main），并要求克隆里只有已跟踪的文件，否则报 repo_dirty。拿副本做演示时，要把副本的 main 指到想要的提交，并删掉 origin。真实台账的 `write.mode: push` 会推送。
- Go：一律用 `GOWORK=off`。CI 用 `GOTOOLCHAIN=local` 并检查 `go env GOVERSION` 等于 go.mod；Dockerfile 的 Go 镜像按 digest 固定，要和 go.mod 一起改。
- 验证镜像签名要用 cosign v3（v2 会报“no signatures found”）。
- 依赖：react-router 8 和 @tanstack/react-table 9 暂缓，因为 refine 的适配器不支持；react-router 8 实测会白屏。@types/node 跟 Node 22。原因记在 docs/design.md。
- 记录 id：值里的 “/” 写成 `%2F`，“%” 写成 `%25`，网址里再编码一次（`%252F` 是对的）；界面上显示成 ` › ` 分隔。
- 密钥字段名的规则在 Go（`internal/secretscan/rules.go`）和前端（`web/src/lib/secretName.ts`）各有一份，要手动保持一致。
- entra 的现状：被排除的应用只是不再同步（相当于冻结），不会吊销；台账没记录一条凭据来自应用还是服务主体，所以“关闭服务主体”的预览不精确。
- 高熵启发式只对 confirm 档生效；SSH 指纹之类用 schema 里的 public 标注豁免，不要放宽启发式。
- KazuhaHub/ledger：CI 会跑固定版本的 `rackbook check`（`.github/workflows/ledger.yml` 里的 RACKBOOK_VERSION 和 RACKBOOK_SHA256），Rackbook 升级后要一起改。字段拆分 PR #8 按“先合 #8，紧接着由主会话改 infra 的 ledger_tool_commit pin”的顺序合并。
- 生产：rackbook.kazuha.org，v0.4.0，镜像 digest 和部署事实都在主会话共享笔记的 rackbook-v0.2-production.md；需要 `RACKBOOK_STATE_DIR=/data/state`。
- infra-hub 方案（tsnet 入网、按 inventory 的 `tailscale_node_id` 放行、lego 作为库、只认 GitHub web-flow 签名并且是当前提交后代的提交）已在共享笔记 infra-hub-plan.md 里验证过关键点，本设计直接并入。
