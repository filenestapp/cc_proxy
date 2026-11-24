# aifree 账户、订阅与邮箱 API 契约（WP0，#34）

WP3（#38）、WP4（#39）、WP6（#41）、WP8（#43）都按本文实现。改契约先改本文，再在相关 Issue 留言。

## 通用约定

- 用户中心与本 API 同源，部署在 `https://app.aifree.sg`。路由前缀 `/v1/account/`。管理端路由沿用 `/admin/`，部署在 `cp.aifree.sg`。
- 请求与响应都是 JSON，UTF-8。所有响应带 `Cache-Control: no-store`，与现有接口一致。
- 错误统一为 `{"error": "可读信息"}`，并带一个稳定的机器码：`{"error": "...", "code": "email_taken"}`。前端按 `code` 显示本地化文案，`error` 只用于日志。
- 时间字段是 Unix 秒（浮点），与现有表一致。金额是整数，单位为分（`60000` = 600.00 元），币种字段 `currency: "cny"`。
- 邮箱一律去空格并转小写后存储和比较。

### 会话与 CSRF

- Cookie：`aifree_session`，`HttpOnly`、`Secure`、`SameSite=Lax`（Stripe 跳回需要 Lax），`Path=/`，有效期 30 天，每次使用后滑动续期，最长 90 天。与管理员的 `cp_session` 分开，互不通用。
- 数据库只存 token 的 SHA-256。`customer_sessions(token_hash, customer_id, csrf, created_at, expires_at, address)`。
- 登录和 `GET /v1/account/me` 返回 `csrf`。除 GET/HEAD 外，所有带会话的请求必须带 `X-CSRF-Token`，不匹配返回 403 `csrf`。
- 改密码、重置密码会删除该客户的全部会话（当前请求的新会话除外）。

### 限流

沿用现有 `loginLimiter`：同一邮箱或同一地址 10 分钟内失败 10 次后返回 429 `rate_limited`。注册、重发验证邮件、找回密码按地址每小时 5 次、按邮箱每小时 3 次。

## 客户账号（WP3）

### 状态

```text
customers.status: active | suspended
email_verified_at: null 表示未验证；未验证可以登录，但不能下单、不能开通邮箱
```

### 路由

| 方法与路径 | 会话 | 说明 |
| --- | --- | --- |
| `POST /v1/account/register` | 无 | `{email, password, locale?}` → 201 `{customer}`，同时登录并下发 Cookie，发送验证邮件 |
| `POST /v1/account/verify` | 无 | `{token}` → 200 `{customer}`；token 一次性，24 小时有效 |
| `POST /v1/account/verify/resend` | 有 | 未验证时重发；已验证返回 409 `already_verified` |
| `POST /v1/account/login` | 无 | `{email, password}` → 200 `{customer, csrf}` 并下发 Cookie |
| `POST /v1/account/logout` | 有 | 删除当前会话，清 Cookie，204 |
| `GET /v1/account/me` | 有 | `{customer, csrf, subscription, proxy, mailbox}`，各字段无则为 null |
| `POST /v1/account/password` | 有 | `{current_password, new_password}` → 204 |
| `POST /v1/account/password/forgot` | 无 | `{email}` → 始终 202，不泄露邮箱是否存在；存在时发重置邮件，1 小时有效 |
| `POST /v1/account/password/reset` | 无 | `{token, new_password}` → 204，删除全部会话 |

`customer` 对象：

```json
{"id": 42, "email": "a@example.com", "email_verified": true, "status": "active", "locale": "zh-CN", "created_at": 1795500000.0}
```

密码规则与现有一致：PBKDF2-SHA256，20 万次迭代，至少 8 个字符。

错误码：`invalid_email`、`weak_password`、`email_taken`(409)、`invalid_credentials`(401)、`invalid_token`(400，过期或已使用)、`email_unverified`(403)、`suspended`(403)、`rate_limited`(429)。

### 邮件

验证与重置邮件由 `noreply@aifree.sg` 经 cloud-mail `POST /api/email/send` 发出。发信封装为接口 `mailSender`，测试用假实现。链接格式：

```text
https://app.aifree.sg/account/verify?token=...
https://app.aifree.sg/account/reset?token=...
```

发信失败不影响注册结果，记录告警并允许用户重发。

### 桌面客户端登录

现有 `POST /v1/login` 增加一条分支：`username` 含 `@` 时按客户邮箱查找，校验客户密码，再以该客户关联的代理账号（`customer_proxy`）签发设备 token。没有有效订阅或未分配代理账号时返回 403 `no_active_subscription`。管理员创建的老用户名登录不变。

## 套餐与订阅（WP4）

### 套餐

`GET /v1/account/plans`（无需会话）：

```json
{"plans": [
  {"code": "standard", "name": "Standard", "amount": 60000, "currency": "cny", "interval": "month", "includes_ip": true, "team_seat": true},
  {"code": "premium", "name": "Premium", "amount": 150000, "currency": "cny", "interval": "month", "includes_ip": true, "team_seat": true},
  {"code": "residential_ip", "name": "海外住宅 IP", "amount": 40000, "currency": "cny", "interval": "month", "includes_ip": true, "team_seat": false}
]}
```

`plans` 表另存 `stripe_price_id`、`active`、`sort`。官网的价格也从此接口读取（构建时或运行时）。

### 规则

- 每个客户同时最多一个未结束的订阅（`pending`、`active`、`past_due`）。升级、降级、换卡、取消都通过 Stripe Customer Portal 完成。
- 每个客户最多一个代理账号和一个独享出口 IP。三个套餐都包含 IP。
- `standard`、`premium` 另需人工开通团队席位，进入开通队列。

### 状态机

```text
                 checkout 完成
  (none) ──────────────────────────► pending ──invoice.paid──► active
                                        │                       │  ▲
                              checkout 过期(24h)    invoice.payment_failed │ invoice.paid
                                        ▼                       ▼  │
                                     expired                  past_due
                                                                │  超过宽限期 3 天，或 Stripe 标记 unpaid/canceled
  active ──用户在 Portal 取消──► active(cancel_at_period_end=true) ──周期结束──► cancelled
  past_due ─────────────────────────────────────────────────────► cancelled
```

权益判断：`status IN ('active','past_due') AND now < current_period_end + grace`。宽限期默认 3 天，放在 `settings`。

### 开通与回收

| 事件 | 动作 |
| --- | --- |
| 首次进入 `active` | 建代理账号（`users.name = 'c' || customer_id`，`mode = exclusive`，随机密码不外发），写 `customer_proxy`，调用现有 `assign` 分配独享 IP。无可用 IP 时订阅仍为 `active`，`proxy.state = waiting_ip`，产生告警并进入开通队列 |
| `standard`/`premium` 进入 `active` | 开通队列新增 `team_seat` 项，状态 `todo` |
| 进入 `past_due` | 不动资源，用户中心提示更新支付方式 |
| 进入 `cancelled` | 吊销全部设备，`release` 释放 IP（进入现有 cooldown），代理账号保留以便续订；邮箱按 WP8 规则停用 |
| 再次订阅 | 复用代理账号，重新 `assign` |

### 路由

| 方法与路径 | 会话 | 说明 |
| --- | --- | --- |
| `POST /v1/account/checkout` | 有，需已验证 | `{plan}` → `{url}`，跳转 Stripe Checkout（`mode=subscription`）。已有未结束订阅返回 409 `subscription_exists` |
| `POST /v1/account/portal` | 有 | → `{url}`，跳转 Stripe Customer Portal，返回地址 `https://app.aifree.sg/account` |
| `GET /v1/account/subscription` | 有 | 当前订阅或 null |
| `GET /v1/account/orders` | 有 | 订单列表，含 Stripe 托管的收据链接 `receipt_url` |
| `GET /v1/account/devices` | 有 | 代理账号下的设备：`name, platform, created_at, last_seen_at, active` |
| `POST /v1/account/devices/{name}/revoke` | 有 | 吊销一台设备，204 |
| `POST /v1/stripe/webhook` | Stripe 签名 | 见下 |

`subscription` 对象：

```json
{"id": 7, "plan": "premium", "status": "active", "current_period_start": 1795500000.0, "current_period_end": 1798092000.0,
 "cancel_at_period_end": false, "team_seat": "todo|done|null", "proxy": {"state": "ready|waiting_ip|none", "egress_ip": "203.0.113.9"}}
```

`order` 对象：`{id, subscription_id, amount, currency, status: pending|paid|failed|refunded, paid_at, receipt_url}`。

Checkout 跳回：成功 `https://app.aifree.sg/account?checkout=success`，取消 `...?checkout=cancel`。跳回页只提示"处理中"，以 Webhook 结果为准，前端轮询 `GET /v1/account/subscription`，每 2 秒一次，最多 30 秒。

### Stripe Webhook

- 用 `STRIPE_WEBHOOK_SECRET` 校验 `Stripe-Signature`，时间容差 5 分钟。校验失败返回 400。
- 处理的事件：`checkout.session.completed`、`customer.subscription.created`、`customer.subscription.updated`、`customer.subscription.deleted`、`invoice.paid`、`invoice.payment_failed`。其他事件返回 200 并忽略。
- 幂等：`stripe_events(event_id PRIMARY KEY, type, received_at)`，同一事件重复投递直接返回 200。
- 乱序：订阅状态以事件里的 Stripe subscription 对象为准，比较 `stripe_events` 记录的对象版本（`created` 时间）后只前进不后退；必要时回查 Stripe API 取最新对象。
- 关联：Checkout 时创建或复用 Stripe Customer，`customers.stripe_customer_id` 唯一；Checkout Session 带 `client_reference_id = customer_id` 和 `metadata.plan`。
- 资源开通和回收在同一个数据库事务里写状态，IP 分配失败不回滚订阅状态（见上表）。
- 密钥：`STRIPE_SECRET_KEY`、`STRIPE_WEBHOOK_SECRET` 只从环境变量读取。

### 管理端

| 方法与路径 | 说明 |
| --- | --- |
| `GET /admin/customers?q=` | 客户列表，含验证状态、订阅、代理账号、邮箱 |
| `PUT /admin/customers/{id}` | `{status}`，停用后会话失效、设备吊销 |
| `GET /admin/subscriptions?status=` | 订阅列表 |
| `GET /admin/orders` | 订单列表 |
| `GET /admin/provisioning` | 开通队列：`team_seat`、`waiting_ip`、`mailbox` 三类 |
| `POST /admin/provisioning/{id}/done` | `{note}` 标记完成 |
| `GET/PUT /admin/plans` | 查看和修改价格、Stripe Price ID、上下架 |

## 企业邮箱（WP8）

### 规则

- 有权益（见上）的客户最多一个企业邮箱，数量上限放 `settings.mailbox_quota`，默认 1。
- 由管理员在后台开通。客户在用户中心只能查看，并跳转 `https://mail.aifree.sg` 登录网页邮箱。
- 本地部分：3–32 位，小写字母、数字、`.`、`-`，首尾必须是字母或数字；保留 `admin`、`noreply`、`support`、`postmaster`、`abuse`、`billing`、`root`。

### 管理端路由

| 方法与路径 | 说明 |
| --- | --- |
| `POST /admin/customers/{id}/mailbox` | `{local_part}` → 201 `{mailbox, initial_password}`；初始密码只返回这一次，不入库 |
| `POST /admin/mailboxes/{id}/disable` | 停用 |
| `POST /admin/mailboxes/{id}/enable` | 恢复 |
| `DELETE /admin/mailboxes/{id}` | 永久删除，需要请求体 `{confirm: "<address>"}` |
| `GET /admin/mailboxes` | 列表 |

错误码：`no_entitlement`(403)、`quota_exceeded`(409)、`address_taken`(409)、`invalid_local_part`(400)、`mail_unavailable`(502，cloud-mail 出错)。

客户端只读：`GET /v1/account/me` 里的 `mailbox = {address, status: active|disabled, webmail_url}`。

### 生命周期

```text
active ──订阅进入 cancelled──► disabled ──30 天后定时任务──► deleted
disabled ──重新订阅──► active
```

### cloud-mail 调用

| 动作 | cloud-mail 接口 |
| --- | --- |
| 取管理员 token | `POST /api/login {email, password}` → `data.token`；放在 `Authorization` 头，不加 `Bearer` |
| 开户 | `POST /api/user/add {email, password}`，随后 `GET /api/user/list?email=` 取 `userId` 存入 `mailboxes.cloudmail_user_id` |
| 停用 / 恢复 | `PUT /api/user/setStatus {userId, status}`，1 为停用，0 为正常 |
| 删除 | `DELETE /api/user/delete?userIds=<id>` |
| 发事务邮件 | 以 `noreply@aifree.sg` 账号登录后 `POST /api/email/send` |

- 配置：`CLOUDMAIL_URL`、`CLOUDMAIL_ADMIN_EMAIL`、`CLOUDMAIL_ADMIN_PASSWORD`、`CLOUDMAIL_NOREPLY_EMAIL`、`CLOUDMAIL_NOREPLY_PASSWORD`，只从环境变量读取。
- token 缓存在内存。收到 401，或响应体的业务码表示未登录时，重新登录一次后重试；仍失败返回 `mail_unavailable`。
- 开户先写本地 `mailboxes`（状态 `creating`）占住地址，再调用 cloud-mail，成功后改为 `active`；失败删除本地记录。
- 实现前先在部署好的 cloud-mail 上核对以上路径和返回结构；文档与实际不一致时以实际为准并更新本文。
