# aifree 品牌上线规划（aifree.sg）

本文是 Codex 与 Claude Code 协同开发的唯一任务源。每个工作包（WP）对应一个 GitHub Issue，分支命名沿用现有约定：Codex 用 `codex/issue-N-*`，Claude 用 `claude/*`。PR 用 `Fixes #N` 关联 Issue，并写明已跑的测试。

## 现状（2026-11-24）

| 项 | 现状 | 与需求的差距 |
| --- | --- | --- |
| 品牌 | 桌面端 `productName: "CC Proxy"`、`identifier: com.ccproxy.desktop`，约 60 处字符串分布在 18 个文件（tauri、tray、locales、console.html、安装脚本、README、CI） | 全量改名 + 新 logo + 图标集 |
| 域名 | 控制面 `https://ccproxy.macmini.sg`，已装的出口 Agent 和桌面端都指向它 | 新域名 aifree.sg，旧域名需保留过渡 |
| 用户体系 | `users` 表只有管理员创建的代理账号（用户名 + 密码 + 出口 IP + 设备上限），`/v1/login` 只给客户端设备登录 | 没有自助注册、邮箱、订阅、订单、支付 |
| 官网 | 无，`GET /` 返回管理控制台 | 需要营销站 + 价格 + 订阅入口 |
| 邮件 | 无 | 需要域名邮件配置 + 发信 + 企业邮箱开通 |

## 目标架构

```text
aifree.sg / www.aifree.sg   → Cloudflare Pages：营销官网（静态，中英双语）
app.aifree.sg               → Go 控制面：用户中心 /account + /v1/account/* API（同源 Cookie）
cp.aifree.sg                → Go 控制面：客户端/Agent API、管理控制台 /console
ccproxy.macmini.sg          → 同一控制面的旧域名，过渡期保留（Agent、旧客户端）
mail.aifree.sg              → cloud-mail（maillab/cloud-mail，MIT）：Cloudflare Worker + D1 + KV + R2，网页收件箱与发信
@aifree.sg 邮件              → Email Routing catch-all 交给 cloud-mail Worker；发信走 Cloudflare Email 或 Resend
```

一个 Go 服务、一个 PostgreSQL，按 Host 区分入口，不新增后端服务。用户中心与 `/v1/account/*` 同源，避免跨域 Cookie 和 CORS。

## 数据模型（新增，WP3/WP4/WP8 共用）

```text
customers        id, email(unique, citext), password_hash, email_verified_at, status, created_at
customer_sessions token_hash, customer_id, csrf, expires_at          -- 复用 admin_sessions 的做法
email_tokens     token_hash, customer_id, purpose(verify|reset), expires_at
plans            code(standard|premium|residential_ip), name, price_cny, period(month), fulfillment(manual|auto_ip), active
subscriptions    id, customer_id, plan_code, status(pending|active|past_due|cancelled|expired), current_period_start/end, cancel_at_period_end
orders           id, customer_id, subscription_id, amount_cny, provider, provider_ref, status(pending|paid|failed|refunded), paid_at
customer_proxy   customer_id → users.name   -- 付费后自动开代理账号，复用现有分配逻辑
mailboxes        id, customer_id, address(unique), cloudmail_user_id, status(active|disabled|deleted), created_at
```

价格：Standard 600 元/月，Premium 1500 元/月，海外住宅 IP 400 元/月。价格存表，后台可改。

订阅开通：
- `residential_ip`：`fulfillment=auto_ip`，支付成功后自动建 `users` 账号并走现有 `assign` 分配独享出口 IP；到期后进入现有 cooldown 释放流程并吊销设备。
- `standard` / `premium`：Team 席位 `fulfillment=manual`，支付成功后进入后台"待开通"队列，管理员人工开通后标记完成；同时自动分配独享住宅 IP（同上）。

## 工作包

| WP | 内容 | 负责 | 依赖 | 主要文件 |
| --- | --- | --- | --- | --- |
| WP0 | 决策确认 + API 契约 `docs/aifree-account-api.md`（路由、请求/响应、错误码、状态机） | Claude（本会话） | — | docs/ |
| WP1a | Logo 与品牌规范：SVG 主标、图标、色板、字体，产出 `brand/` 目录 | Claude | — | brand/ |
| WP1b | 全量改名 CC Proxy → aifree：tauri 配置、tray、locales、console、安装脚本、CI 产物名、README；用 WP1a 的图标生成全套 icons | Codex | WP1a（仅图标替换那一步） | client/desktop、controlplane/console.html、controlplane/install、.github |
| WP2 | 域名切换：控制面按 Host 路由、`--public-url` 配置、安装命令与客户端默认地址改为 `cp.aifree.sg`、旧域名并存；部署文档 | Codex | WP1b | controlplane/http.go、installer.go、client 默认值 |
| WP3 | 客户账号后端：开放注册 + 邮箱验证（经 cloud-mail `noreply@` 发信，失败重试）、登录/登出、找回密码、限流、会话与 CSRF | Codex | WP0、WP7（发信） | controlplane/schema.sql、store.go、新文件 account.go |
| WP4 | 套餐与订阅后端：plans/subscriptions/orders、Stripe Checkout + Billing 订阅 + Webhook（签名校验、幂等）、客户门户、到期任务、自动开通住宅 IP、控制台"订阅/订单/待开通"页 | Codex | WP3 | controlplane/ 新文件 billing.go、console.html |
| WP5 | 营销官网：首页（价值主张、架构图、对比、套餐卡片、流程、FAQ）、条款、隐私、下载页；中英双语；部署到 Cloudflare Pages | Claude | WP1a | 新目录 site/ |
| WP6 | 用户中心：注册/登录/验证/找回、我的订阅（订阅、续费、取消）、订单与收据、设备列表、客户端下载、企业邮箱面板 | Claude | WP0 契约；联调需 WP3/WP4 | controlplane/account.html（内嵌，同 console.html 做法） |
| WP7 | 部署 cloud-mail 到 `mail.aifree.sg`：Worker、D1、KV、R2、`jwt_secret`、管理员账号；Email Routing catch-all → Worker；发信域 SPF/DKIM/DMARC；建 `noreply@`、`support@`；控制面用的管理员 API 账号 | Claude + 你（需 Cloudflare 授权） | 域名已接入 Cloudflare | 新目录 deploy/cloud-mail/ + docs/aifree-email-setup.md |
| WP8 | 企业邮箱开通：后台对付费客户调用 cloud-mail API 生成 `name@aifree.sg`（`POST /api/login` 取管理员 token → `POST /api/user/add`），停用 `PUT /api/user/setStatus`、到期回收；初始密码只显示一次；用户中心展示并跳转 mail.aifree.sg 网页收件箱 | Codex（后端）+ Claude（UI） | WP3、WP4、WP7 | controlplane/ 新文件 mailbox.go |
| WP9 | 集成验收：docker compose e2e（注册→支付回调→开通→客户端登录→出网→到期回收→邮箱开通），预发布环境演练，域名切流 | Claude 主导，Codex reviewer 复核 | 全部 | controlplane/test/ |

## 排期与并行

```text
阶段 0（今天）   WP0 契约 + 决策            ← 阻塞后续，先做
阶段 1（并行）   Codex: WP1b → WP2           Claude: WP1a → WP5        你+Claude: WP7
                Codex 第二条线: WP3 → WP4（同改 schema.sql/store.go，必须串行在同一条线）
阶段 2（并行）   Codex: WP8 后端              Claude: WP6 用户中心（先按契约用 mock 开发）
阶段 3          WP9 集成验收 → 切域名
```

冲突规避：
- `schema.sql`、`store.go` 只由 Codex 的 WP3→WP4→WP8 一条线修改。
- `console.html` 先由 WP1b 改名合并，WP4/WP8 再加页面。
- Claude 的 WP5（site/）与 WP6（account.html）是新文件，不与 Codex 冲突。
- 每个 WP 在独立 worktree 开发，合并顺序以本表为准；后合并的分支先 rebase main。

## 协同方式

1. 本规划确认后，为每个 WP 建 GitHub Issue，标签 `agent:codex` / `agent:claude`，正文写验收标准并链接本文。
2. Codex 按 Issue 开发（`codex/issue-N-*` 分支），Claude 会话按 Issue 开发（`claude/*` 分支）。
3. 交叉评审：Codex 的 PR 由 Claude 做 code review；Claude 的 PR 由 Codex `reviewer` 代理复核。
4. 契约变更只改 `docs/aifree-account-api.md`，并在相关 Issue 留言，避免两边各自假设。

## 风险与合规

- **Claude Team 席位转售**：把 Anthropic Claude Team 席位按月转卖给第三方，可能违反 Anthropic 的商业条款；面向 Anthropic 不支持地区的用户同样有风险。参考站把自己写成"官方直连"并承诺规避封号。建议：官网与套餐名不用 Claude/Anthropic 商标或 logo，不写"官方"字样，不承诺规避封号；上线前请法务确认。
- **cloud-mail 接口边界**：管理员 token 通过 `/api/login` 获取、放在 `Authorization` 头（无 Bearer 前缀），文档未说明过期时间，控制面需在 401 时重新登录。没有"停用单个邮箱"接口，只能停用用户；删除用户是永久删除。没有 IMAP/SMTP，客户只能用网页收发。控制面的 cloud-mail 管理员密码放环境变量，不入库。
- **域名切换**：已装出口 Agent 的服务里写死了 `--cp https://ccproxy.macmini.sg`，旧域名至少保留到所有 Agent 重装完成。改桌面端 `identifier` 会让 macOS 视为新应用（钥匙串、自启动项不继承），需要迁移说明。
- **Stripe 与人民币**：需确认 Stripe 账号主体所在地是否支持 CNY 结算，以及国内用户的支付方式。微信支付在 Stripe 上不支持自动续费，支付宝的循环扣款也有地区限制；银行卡（Visa/Mastercard/银联）可以自动续费。上线前在 Stripe 测试模式验证 600/1500/400 CNY 三个 Price。

## 已确认决策（2026-11-24）

| 问题 | 决定 |
| --- | --- |
| 支付 | Stripe 自动订阅（Checkout + Billing + Webhook + Customer Portal） |
| 企业邮箱 | 自部署 [maillab/cloud-mail](https://github.com/maillab/cloud-mail)，控制面调用其 API 开户 |
| 注册 | 开放注册 + 邮箱验证 |
| Standard/Premium | 附带一个独享住宅 IP |
| 官网托管 | 默认 Cloudflare Pages（未特别确认，可改） |

## 仍需你提供

- Cloudflare：aifree.sg 已接入的账号，以及给 Claude 用的 API Token（Workers、D1、KV、R2、Email Routing、DNS、Pages 权限），或在本机 `wrangler login`。
- Stripe：账号主体所在地、测试模式密钥（只放 `.env`/密钥管理，不进仓库）。
- Logo 偏好：有无现成素材，或交给 WP1a 出 2–3 个方向。
