# aifree.sg 邮件部署（WP7，#42）

`mail.aifree.sg` 运行 [maillab/cloud-mail](https://github.com/maillab/cloud-mail) v3.6.0（MIT），提供网页收件箱、收信和发信。控制面通过它的 API 发送事务邮件（WP3）并为付费客户开通企业邮箱（WP8）。

## 当前状态（2026-11-24）

| 项 | 状态 |
| --- | --- |
| Worker `aifree-mail`，自定义域名 `mail.aifree.sg` | 已部署，HTTPS 200 |
| D1 `aifree-mail`（`1303d0b8-080c-47fb-a54c-69ae217e6467`） | 已初始化 |
| KV `aifree-mail`（`f107f5d4b1c84bb3a713c55e64c294d4`） | 已绑定；附件存 KV（未启用 R2） |
| 账号 `admin@`、`noreply@`、`support@aifree.sg` | 已创建，管理员 API 登录已验证 |
| Email Routing | 已启用；catch-all → Worker `aifree-mail` |
| DNS | MX `route1/2/3.mx.cloudflare.net`，SPF `include:_spf.mx.cloudflare.net`，DKIM `cf2024-1._domainkey`，DMARC `p=quarantine` |
| 收信实测 | 待做：从外部邮箱发信到 `support@aifree.sg` |
| 发信 | 待做：需要在 Cloudflare 后台开启 Email Sending，或配置 Resend（见下） |

## 密钥

全部放在仓库外的 `cc_proxy-secrets/cloud-mail.env`（权限 600），不进仓库：

- `CLOUDMAIL_JWT_SECRET`、`CLOUDMAIL_ADMIN_PASSWORD`：已用 `wrangler secret put jwt_secret` / `password` 写入 Worker。
- `CLOUDMAIL_ADMIN_EMAIL`/`PASSWORD`：控制面 WP8 用来开户。
- `CLOUDMAIL_NOREPLY_EMAIL`/`PASSWORD`：控制面 WP3 用来发验证和重置邮件。
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

## 开启发信（二选一）

1. **Cloudflare Email Sending（推荐，留在 Cloudflare 内）**：在 Cloudflare 后台 Email → Email Sending 为 `aifree.sg` 开启发信并按提示添加 DNS 记录；然后在 `deploy/cloud-mail/wrangler.toml` 加上
   ```toml
   [[send_email]]
   name = "email"
   ```
   重新部署。cloud-mail 有该绑定时优先用它发信。
2. **Resend**：在 Resend 添加并验证 `aifree.sg`（DNS 记录加到 Cloudflare），把 API Key 填到 cloud-mail 管理后台的发信设置。

开启后验收：用 `noreply@aifree.sg` 发信到 Gmail，邮件头显示 SPF、DKIM、DMARC 均为 pass。

## 已知限制

- 没有 IMAP/SMTP，客户只能用网页收发。
- cloud-mail API 没有"停用单个邮箱"接口，只能停用用户；删除用户是永久删除。
- 同一 Cloudflare 账号下还有 `cloud-mail-test` 和 `mailflare` 两个 D1，与 aifree 无关，未改动。
