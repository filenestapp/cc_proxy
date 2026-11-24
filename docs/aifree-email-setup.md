# aifree.sg 邮件部署（WP7，#42）

`mail.aifree.sg` 运行 [maillab/cloud-mail](https://github.com/maillab/cloud-mail) v3.6.0（MIT），提供网页收件箱和收信。控制面通过它的 API 为付费客户开通企业邮箱（WP8）。当前只收信，不对外发信（2026-11-24 决定）。

## 当前状态（2026-11-24）

| 项 | 状态 |
| --- | --- |
| Worker `aifree-mail`，自定义域名 `mail.aifree.sg` | 已部署，HTTPS 200 |
| D1 `aifree-mail`（`1303d0b8-080c-47fb-a54c-69ae217e6467`） | 已初始化 |
| KV `aifree-mail`（`f107f5d4b1c84bb3a713c55e64c294d4`） | 已绑定；附件存 KV（未启用 R2） |
| 账号 `admin@`、`noreply@`、`support@aifree.sg` | 已创建，管理员 API 登录已验证 |
| Email Routing | 已启用；catch-all → Worker `aifree-mail` |
| DNS | MX `route1/2/3.mx.cloudflare.net`，SPF `include:_spf.mx.cloudflare.net`，DKIM `cf2024-1._domainkey`，DMARC `p=quarantine` |
| 收信实测 | 已通过：从本机直连 `route1.mx.cloudflare.net:25` 投递到 `support@aifree.sg`，1 秒内写入 D1 并出现在收件箱 API |
| 发信 | 暂不启用。Worker 不带 `email` 绑定，也未配置 Resend；站内邮箱之间互发可用，发往外部地址会被 cloud-mail 拒绝（`noSendProvider`） |
| 角色 | 默认角色 `普通用户` 禁止发信（`sendType=ban`）；新建角色 `system-sender`（不限量）并分配给 `noreply@`、`support@` |

## 密钥

全部放在仓库外的 `cc_proxy-secrets/cloud-mail.env`（权限 600），不进仓库：

- `CLOUDMAIL_JWT_SECRET`、`CLOUDMAIL_ADMIN_PASSWORD`：已用 `wrangler secret put jwt_secret` / `password` 写入 Worker。
- `CLOUDMAIL_ADMIN_EMAIL`/`PASSWORD`：控制面 WP8 用来开户。
- `CLOUDMAIL_NOREPLY_EMAIL`/`PASSWORD`：控制面 WP3 用来发验证和重置邮件；在启用发信前不要给控制面配置这两个变量，否则注册时会记录发信失败日志。
- `CLOUDMAIL_SUPPORT_EMAIL`/`PASSWORD`：客服收件箱。

控制面部署时把 `CLOUDMAIL_URL`、`CLOUDMAIL_ADMIN_*`、`CLOUDMAIL_NOREPLY_*` 设为环境变量。

## 部署或升级

```bash
git clone https://github.com/maillab/cloud-mail && cd cloud-mail && git checkout v3.6.0
cp <cc_proxy>/deploy/cloud-mail/wrangler.toml mail-worker/wrangler.toml
cd mail-worker && npx --yes pnpm@9 install --frozen-lockfile
npx --yes wrangler@4.167.0 deploy
```

- 构建命令用 pnpm 9（锁文件是 v9）并以 `-C ../mail-vue` 安装前端依赖。
- 首次部署后写入密钥，再访问一次 `https://mail.aifree.sg/api/init/<jwt_secret>` 初始化数据库（只需一次）。
- 升级 cloud-mail 版本前先在 `cloud-mail-test` 之类的测试 Worker 上验证。

## 上线前必须开启发信

注册要发验证邮件，契约要求邮箱已验证才能下单（`docs/aifree-account-api.md`）。发信不开，新客户无法验证，也就无法订阅。所以发信是上线阻塞项（2026-11-24 决定，跟踪在 #44），不改为"跳过验证"。

开启后再给控制面配置 `CLOUDMAIL_NOREPLY_EMAIL`/`PASSWORD`，然后按下面的验收方法确认。

## 开启发信（二选一）

1. **Cloudflare Email Sending（推荐，留在 Cloudflare 内）**：在 Cloudflare 后台 Email → Email Sending 为 `aifree.sg` 开启发信并按提示添加 DNS 记录；然后在 `deploy/cloud-mail/wrangler.toml` 加上
   ```toml
   [[send_email]]
   name = "email"
   ```
   重新部署。cloud-mail 有该绑定时优先用它发信。
2. **Resend**：在 Resend 添加并验证 `aifree.sg`（DNS 记录加到 Cloudflare），把 API Key 填到 cloud-mail 管理后台的发信设置。

开启后验收：用 `noreply@aifree.sg` 发信到 Gmail，邮件头显示 SPF、DKIM、DMARC 均为 pass。

## 发信说明

- 收件人全部是 `@aifree.sg` 时，cloud-mail 直接写入本库，不经过 Cloudflare（`email-service.js` 的 `allInternal` 分支）；验证外发必须发往外部邮箱。
- 客户企业邮箱能否对外发信由 WP8（#43）决定：保持默认角色即只能收信，或为付费客户分配允许发信的角色并设每日上限。

## 收信验收方法

```bash
python3 - <<'PY'
import smtplib; from email.message import EmailMessage
m=EmailMessage(); m['From']='inbound-probe@probe.aifree.sg'; m['To']='support@aifree.sg'; m['Subject']='inbound check'; m.set_content('test')
with smtplib.SMTP('route1.mx.cloudflare.net',25,timeout=20) as s: s.starttls(); s.send_message(m)
PY
```

然后在 `support@` 收件箱或 D1 `email` 表中确认。Cloudflare 的 Email Routing 分析数据有延迟，不能用来判断是否送达。

## 已知限制

- 没有 IMAP/SMTP，客户只能用网页收发。
- cloud-mail API 没有"停用单个邮箱"接口，只能停用用户；删除用户是永久删除。
- 同一 Cloudflare 账号下还有 `cloud-mail-test` 和 `mailflare` 两个 D1，与 aifree 无关，未改动。
