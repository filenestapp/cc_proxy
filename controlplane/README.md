# 控制面原型

管理多台出口机、出口 IP 和用户，给客户端下发配置，并让每台出口机上的 agent 自动热更新。只依赖 Python 3.8+ 标准库，数据存在 SQLite。sing-box 配置仍由 [`egress/gen.py`](../egress/gen.py) 生成：控制面先把一台主机的数据拼成 inventory，再交给 gen.py。

**v2 数据模型**（schema v2，不兼容 v1 的数据库，需要从新库开始）：

```text
主机 host    出口机：公网入口地址、Reality 密钥（自动生成）、用户入口端口范围、agent 令牌
出口 IP      属于某一台主机
用户 user    用户名 + 密码；绑定一个出口 IP，以及该 IP 所在主机上的一个专属入口端口
设备 device  用户在某台电脑上登录时创建；持有 VLESS 凭证和订阅令牌
```

每个用户在出口机上有自己的 sing-box 入站（`IP:端口`），流量按入站路由到绑定的出口 IP。

## 组成

| 文件 | 作用 |
| --- | --- |
| `store.py` | SQLite 存储和业务规则：主机、IP 与端口分配、冷却、封禁、密码与登录、设备令牌、配置版本号 |
| `x25519.py` | 纯 Python 的 X25519，用来给每台主机生成 Reality 密钥（已用 RFC 7748 和 sing-box 的密钥对验证） |
| `server.py` | HTTP API：`init` 和 `serve`；路由清单写在文件开头 |
| `agent.py` | 跑在出口机上：拉取 IP 列表和服务端配置，`sing-box check` 通过后原子替换，再重载 |
| `cpctl.py` | 管理命令行，调用 admin API |
| `monitor.py` | 健康数据：agent 心跳、每个出口 IP 的探测结果、各探测点到入口的延迟，以及看板用的拓扑汇总 |
| `probes.py` | 探测原语：绑定源 IP 的 HTTP 探测、TCP 建连探测 |
| `prober.py` | 探测点程序：每个用户所在的网络（运营商 + 地区）部署一个，测到各入口的延迟 |
| `console.html` | 管理后台（单页，无需构建），由 `GET /` 提供 |
| `auth.py` | 后台管理员账号、浏览器会话与 CSRF、审计日志 |
| `alerts.py` | 告警：在看板同一份拓扑数据上评估规则，维护告警状态，触发和解除时推送 webhook |
| `tests/` | 单元测试：存储规则、API、agent 的同步逻辑 |
| `test/` | Docker 端到端测试 |

## 规则

- **IP 状态**：`available`、`assigned`、`cooldown`、`banned`。最后一个持有者释放 IP 后（包括删除用户），IP 进入冷却，默认 7 天，由 `cooldown_seconds` 设置。封禁会让当前持有者立刻失去该 IP，以后也不再分配。`ip-available` 可以手动结束冷却或解除封禁。
- **绑定 IP 和端口**：`assign` 可以指定 IP、端口、主机，都可省略。省略 IP 时取（指定主机上）数值最小的空闲 IP；省略端口时取该主机端口范围内最小的空闲端口。端口必须在主机的范围内，同一主机上不能重复；不同主机可以用同样的端口。释放或封禁 IP 时，端口一并收回。
- **共享**：多个用户共用一个 IP 时，所有持有者都必须是 `shared` 模式；每个人仍然有自己的端口。
- **密码**：PBKDF2-SHA256（20 万次迭代、随机盐），至少 8 位。创建用户时不给密码就自动生成一个，只显示一次。重置密码时可以选择同时让所有设备下线。
- **登录**：`POST /v1/login`（用户名、密码、设备名）。错误时不区分是用户名还是密码错。同一用户名或同一来源地址 10 分钟内失败 10 次后，返回 429，正确密码也暂时不能登录。
- **设备**：每次在新电脑上登录会创建一个设备（独立的 VLESS 凭证和订阅令牌），默认每个账号最多 5 台（`max_devices`）。同一台电脑再次登录只换令牌，不新增设备。设备可以由管理员吊销，也可以在客户端退出登录。令牌在数据库里只存 SHA-256。
- **agent 令牌**：每台主机一个，添加主机时显示一次，可以轮换。agent 只能拿到自己主机的配置和 IP，也只能上报自己主机 IP 的探测结果。
- **版本号与 ETag**：每次成功的修改都会让全局版本号加一（`/healthz` 可查），失败的修改不会。`/v1/config` 和 `/agent/server-config` 的 ETag 则是**配置内容的哈希**，调用方带 `If-None-Match` 请求、内容没变时返回 304。所以不影响某份配置的修改，比如往 IP 池加 IP、新建一个还没有设备的用户，不会让对应的客户端或 agent 重新下载，更不会触发重载。
- **出站拦截**：每台主机默认拦截发往内网和云元数据地址的连接（`block_private`、`block_cidrs`）。拦截前会先在出口机上解析域名，所以用一个解析到内网地址的域名也绕不过去。

## 管理后台

浏览器打开控制端地址（`/`），用管理员账号登录。页面本身不含数据，登录后才通过 `/admin/*` 接口读写。

| 页面 | 能做什么 |
| --- | --- |
| 概览 | 拓扑：按出口主机分组，显示 agent 心跳与配置同步状态、入口延迟、每个出口 IP 的用户与端口、设备数、探测结果和历史；顶部显示正在触发的告警 |
| 出口主机 | 主机列表与 agent 状态；添加主机（生成 Reality 密钥，agent 令牌只显示一次，并附带启动命令）；编辑地址、伪装域名、端口范围；轮换 agent 令牌；删除主机；查看主机上的出口 IP 和用户 |
| 出口 IP | 所有 IP，可按主机和状态筛选；批量添加（单个地址、`.10-20` 末段范围、完整范围、`/22`–`/32` 网段）；封禁（可填原因，自动收回持有者）、解除封禁或结束冷却、删除空闲 IP |
| 用户 | 搜索；添加用户（不填密码就生成一个，只显示一次；可以同时自动分配出口）；分配或更换出口（选主机、选 IP、可指定端口）、收回出口；重置密码（可选让所有设备下线）；设备上限；删除用户；设备列表与强制下线；为服务器或脚本添加无界面设备 |
| 告警 | 进行中和历史告警，通知失败会标注；发送测试通知 |
| 设置 | 分流规则（走代理的域名、其他域名用的 DNS、是否拦截 QUIC）、IP 冷却天数、健康探测目标和额外入口、告警 webhook 与阈值 |
| 审计日志 | 每一次成功的修改操作和后台登录（包括失败的登录）：时间、操作人、操作、对象、请求内容（已去掉密码和令牌）、来源 IP；保留 180 天 |
| 管理员 | 添加管理员（自动生成密码）、重置他人密码、删除（不能删掉最后一个）、修改自己的密码 |

**安全设计**：

- 管理员密码用 PBKDF2 存储；同一账号或同一来源 10 分钟内登录失败 10 次，就暂时锁定。
- 会话令牌放在 `HttpOnly`、`SameSite=Strict` 的 cookie 里，数据库只存哈希，有效期 12 小时。用 `--tls-cert` 启动，或者请求带 `X-Forwarded-Proto: https`（在反向代理后面）时，cookie 会加上 `Secure`。
- 所有修改操作都必须带上与会话绑定的 `X-CSRF-Token`。
- 修改密码后，这个管理员的所有会话立即失效。
- 页面设置了 CSP 和 `X-Frame-Options: DENY`，不允许被嵌入其他网页。
- 原来的 `CP_ADMIN_TOKEN` 仍然可以用于 `cpctl` 和脚本，在审计日志里显示为 `api-token`。

## 运行

```bash
python3 controlplane/server.py init  --db cp.db --settings settings.json --admin admin   # 打印 admin 的初始密码
export CP_PROBE_TOKEN=$(openssl rand -hex 24)        # 可选：探测点用
export CP_ADMIN_TOKEN=$(openssl rand -hex 24)        # 可选：给 cpctl 和脚本用
python3 controlplane/server.py serve --db cp.db --listen 0.0.0.0 --port 8443 --tls-cert cert.pem --tls-key key.pem
```

放在反向代理后面时，用 `--trusted-proxy 10.0.0.5`（可重复，或设置 `CP_TRUSTED_PROXIES`）指定代理地址。只有来自这些地址的 `X-Forwarded-For` 和 `X-Forwarded-Proto` 才会被采信，用于登录限流、审计来源和 cookie 的 `Secure`；直连请求一律按真实对端地址计算。

以后要再加管理员，可以在后台「管理员」页面操作，也可以执行 `server.py admin-add --db cp.db NAME`（密码从 `CP_ADMIN_PASSWORD` 读取，没设置就提示输入）。启动 `serve` 时，管理员账号和 `CP_ADMIN_TOKEN` 至少要有一个。

`settings.json` 可以包含 `client_policy`（哪些域名走代理，例如 `{"domain_suffix": ["example.com"]}`）、`cooldown_seconds`、`monitor`、`alerts`，都可以之后再用 `PUT /admin/settings` 修改。

管理操作：

```bash
export CP_URL=https://cp.example:8443
controlplane/cpctl.py host-add hk-1 203.0.113.2 www.example.com --ports 20000-20999   # 输出 agent 令牌，只显示一次
controlplane/cpctl.py ip-add hk-1 203.0.113.3 203.0.113.4
controlplane/cpctl.py user-add alice                      # 不给 --password 就生成一个，只显示一次
controlplane/cpctl.py assign alice                        # 或: assign alice 203.0.113.3 --port 20007
controlplane/cpctl.py reassign alice --host jp-1          # 一步换到另一台主机/IP，客户端不断线（原 IP 无人用时冷却）
controlplane/cpctl.py hosts ; controlplane/cpctl.py users ; controlplane/cpctl.py ips
controlplane/cpctl.py passwd alice --revoke-devices       # 重置密码并让所有设备下线
controlplane/cpctl.py revoke alice MacBook                # 让一台设备下线
```

`host-add` 的第三个参数是 Reality 伪装用的 SNI，需要是一个支持 TLS 1.3 的真实站点。主机的端口范围要在防火墙上放行。

用户登录后，客户端用设备令牌请求 `GET /v1/config?mode=app` 获取配置（见 [client/README.md](../client/README.md)）。

出口机 agent（systemd 主机上用 `--reload-cmd`，容器里用 `--run`）：

```bash
CP_AGENT_TOKEN=<这台主机的 agent 令牌> controlplane/agent.py --cp https://cp.example:8443 --iface eth0 \
  --reload-cmd "systemctl reload sing-box" --status-cmd "systemctl is-active --quiet sing-box"
```

**合并重载。** 每次重载都会断开当时正在进行的连接，所以 agent 不会一看到新版本就装：

- 新版本出现后，要等 `--settle` 秒（默认 10）内不再有更新的版本，才执行一次 `sing-box check`、安装和重载。
- 管理员持续修改时，最多等 `--max-delay` 秒（默认 60）就强制安装一次，避免一直拖着不生效。
- 改了又改回去：如果在等待期间配置又变回当前已安装的样子，就不重载。
- 启动后的第一份配置立即安装，不等待。
- 被 `sing-box check` 拒绝的版本会被记住，不会每次轮询都重复检查。

因此，一次修改最晚 `settle + interval` 秒后生效，默认约 15 秒。

## 健康探测与看板

**三类数据**（都不会改变配置版本号，所以不会触发重载）：

| 来源 | 内容 | 频率 |
| --- | --- | --- |
| agent 心跳 | 已安装的配置版本、sing-box 是否在运行 | 每个同步周期（`--interval`） |
| agent 出口探测 | 从每个出口 IP（连接绑定到该 IP）请求 `monitor.egress_targets` 里的每个 URL，记录状态码和到响应头的延迟。2xx/3xx 算成功；403、429 这类「目标开始拒绝这个 IP」的信号算失败 | `--probe-interval`，默认 60 秒 |
| `prober.py` | 从探测点到每个入口的 TCP 建连延迟，取 3 次中最好的一次。入口包括每台有用户的出口机（以主机名命名，测它正在使用的最小入口端口）和 `monitor.entries` 里配的其他入口 | `--interval`，默认 30 秒 |

每条探测序列保留最近 20 次结果用于画历史条，所有结果保留 7 天。

配置：

```bash
curl -X PUT $CP_URL/admin/settings -H "Authorization: Bearer $CP_ADMIN_TOKEN" -d '{"monitor": {
  "egress_targets": ["https://www.example.com/"],
  "entries": [{"name": "hk-relay", "host": "198.51.100.1", "port": 443}]}}'
CP_PROBE_TOKEN=... controlplane/prober.py --cp $CP_URL --vantage sh-telecom
```

agent 用 `--reload-cmd` 模式时，加上 `--status-cmd "systemctl is-active --quiet sing-box"` 才能上报 sing-box 是否在运行，否则显示为未知。

**Network topology** refreshes from `/admin/topology` every 10 seconds. Search by host name, public entry, or egress IP, and use **Needs attention** to surface failures and warnings. Select a host to see agent status, entry-probe history, assigned users and devices, and egress-probe results. **Manage host** opens its settings. **Open IP inventory** scopes the table to that host.

The inventory shows allocation and probe health in separate columns. A probe result more than three minutes old is stale. **System**, **Light**, and **Dark** are available at sign-in and in the console header. The browser remembers the choice.

## 自动告警

告警规则和看板读的是同一份拓扑数据，后台线程每隔 `eval_interval` 秒（默认 15）评估一次：

| 规则 | 条件 | 级别 |
| --- | --- | --- |
| `egress_probe_failing` | 某出口 IP 访问某目标连续 `consecutive_failures`（默认 3）次失败 | 有用户在用时为严重，否则为警告（提醒别把它分配出去）。已封禁的 IP 不参与评估，所以封禁会让告警解除 |
| `entry_unreachable` | 某探测点连到某入口连续失败 | 警告；所有探测点都连不上时为严重 |
| `agent_stale` | 出口机超过 `agent_stale_seconds`（默认 120）秒没有心跳 | 严重 |
| `singbox_down` | agent 报告 sing-box 没有运行（状态未知时不算） | 严重 |
| `agent_out_of_sync` | 已安装的配置与当前配置不一致，并且持续了 `out_of_sync_seconds`（默认 300）秒 | 警告。因为合并重载本来就会造成一段时间的不一致，所以要有宽限期 |

**状态流转**：

- 条件成立后先进入 pending；等到 `for` 时间（宽限期）过去才转为 firing，同时发送通知。
- 条件消失后转为 resolved，发送「已解除」通知。
- 宽限期内就恢复的告警不会留下任何记录。
- 设置了 `repeat_seconds` 时，告警持续期间会按间隔重复提醒。
- 推送失败会在每轮评估时重试，直到所有 webhook 都接收成功。所以部分失败时，某个 webhook 可能收到两次同一条通知。
- 告警只负责通知，不会自动封禁 IP；消息里会附上建议执行的 `cpctl ban` 命令。

**配置**（格式支持 `generic` 完整 JSON、`slack`、`feishu`、`dingtalk`、`wecom`；后几种发送纯文本消息）：

```bash
curl -X PUT $CP_URL/admin/settings -H "Authorization: Bearer $CP_ADMIN_TOKEN" -d '{"alerts": {
  "webhooks": [{"url": "https://open.feishu.cn/open-apis/bot/v2/hook/...", "format": "feishu"}],
  "consecutive_failures": 3, "agent_stale_seconds": 120}}'
controlplane/cpctl.py alert-test        # 给每个 webhook 发一条测试消息，并返回各自的结果
controlplane/cpctl.py alerts --all      # 当前告警和历史告警（已解除的保留 30 天）
```

看板顶部会列出正在触发的告警；如果某条告警的通知发送失败，会标注出来。

## 测试

```bash
python3 -m unittest discover -s controlplane/tests -v     # 91 项，不需要 Docker
controlplane/test/run-e2e.sh                               # Docker，KEEP=1 保留容器
```

端到端测试用两台出口机（hk-1、jp-1），全程只通过 admin API 和客户端登录 API 操作，不手动生成配置，也不手动重载：

1. 开通：添加两台主机和 IP；用户分别是独享、自动分配、共享、未分配、在第二台主机上；每台设备用用户名和密码登录。检查每个客户端连的正是自己用户的主机和端口；错误密码返回 401。之后吊销一台已经拿到配置的设备——测试客户端故意继续用旧配置，以证明拒绝是服务端做的。
2. 变更：释放、吊销、把未分配的用户分配到另一台主机。每台主机只重载一次；一直在等配置的客户端自己拿到了新配置。每个设备的出口 IP 都正确，用域名访问被拦截的地址同样被拒绝。
3. 健康数据（`test/check_topology.py`）：
   - 两台 agent 心跳新鲜、配置已同步、sing-box 在运行；
   - 两台主机的入口都可达；指向关闭端口的 `backup` 入口显示不可达；
   - 每个出口 IP 都探测成功，只有 `10.99.0.6` 失败（echo 用 `BLOCK_IPS` 模拟目标站点封了这个 IP，结果是 HTTP 403）；
   - 共享 IP 的卡片列出两个用户和各自的端口；IP 归在各自的主机下。

3b. 真实客户端（`client/cli` 编译的 `ccproxy`，Linux TUN）：见 [client/README.md](../client/README.md)。
4. 告警（webhook 接收端是 `test/sink.py`）：
   - 被目标拒绝的 IP 和不可达的入口都触发告警，并送达 webhook；
   - `cpctl ban` 之后，webhook 收到「已解除」通知；
   - 停掉一台出口机（jp-1）后，收到它的 `agent_stale` 告警；
   - 没有出现预期之外的告警。

出口机容器启动时一个出口 IP 都没有，全部由 agent 添加。

合并重载的三项单元测试（连续修改只重载一次、`max-delay` 兜底、改回原样不重载）用假时钟驱动。把 agent 换回「看到新版本立即安装」的旧逻辑后，这三项都会失败。

2026-11-22 在 Docker Desktop（arm64）上运行，单元测试和端到端测试都通过。

## 已知限制

- 合并重载减少了断连次数，但每次重载仍会断开这台主机上的全部连接，包括与这次修改无关的用户。
- 从 IP 池删除 IP、从网卡上卸下 IP，都还没有实现。
- 每个用户一个端口，出口机上的防火墙要放行整个端口范围；控制面不管理防火墙。
- v2 数据库不兼容 v1，v1 的 `init --inventory` 迁移已移除；文件式流程（`egress/gen.py`）仍然可用。
- 中转机（如香港中转）还不在管理范围内。
- 告警只通知，不自动封禁；也没有静默或确认功能，问题没处理之前告警会一直保持 firing。
- 告警通知会发到外部服务（飞书、钉钉等），消息里包含 IP 和用户名。
- 后台没有细分权限：所有管理员权限相同。也没有两步验证。
- 删除 IP 只是从 IP 池中删除，agent 不会把它从出口机网卡上卸下。
- `--tls-cert` 走的是标准库 TLS，没做证书热更新。上线时建议放在反向代理后面。
