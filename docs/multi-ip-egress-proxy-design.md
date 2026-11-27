# 多 IP 出口分流代理设计

本产品把用户本机上**指定域名**或**指定应用**的流量送进加密隧道，从一台多 IP 出口机上**分配给该用户的固定 IP** 出去。其余流量保持本地原有路径。首版目标是：一台出口机绑定一段 IP，每个用户独享一个出口 IP，客户端支持 macOS，后续再扩展到 Windows 和 Linux。

## 范围

| 首版包含 | 首版不包含 |
| --- | --- |
| 按域名分流、按进程分流 | 浏览器指纹、时区等应用层伪装 |
| 每用户绑定一个出口 IP（独享，或多人共享） | 多台出口机之间的自动调度 |
| 一条可选的中转线路，主备两个入口 | 计费与支付 |
| 控制面：用户、设备、IP 分配、配置下发、健康探测 | 移动端客户端 |

## 网络路径

```text
用户设备
  客户端（sing-box 内核 + 外壳 UI）
  只把命中规则的流量送入 TUN
  -> 加密隧道（VLESS+Reality 或 Hysteria2）
  -> [可选] 中转机：四层转发，主备两台
  -> 出口机：一个 sing-box 进程，按用户选择出站
     出站绑定该用户的 IP（例如 203.0.113.N）
  -> 目标站点
```

目标站点看到的源地址就是分配给该用户的出口 IP。DNS 也在出口机上解析，所以解析结果和出口 IP 处在同一地域。

内核统一用 sing-box（1.12 及以上，DNS 使用新的服务器格式）。客户端和服务端用同一套配置语言，所以控制面只需要维护一种配置生成器。 [sing-box 文档](https://sing-box.sagernet.org/configuration/)

## 客户端

### 两种分流模式

分流方式决定了客户端要接管多少系统网络，所以设计成两种模式，由用户选择。

| | 域名模式（默认） | 应用模式 |
| --- | --- | --- |
| 原理 | fake-ip：命中的域名解析成 `198.18.0.0/15` 里的假地址，系统只把这一段路由到 TUN | TUN 接管默认路由，由 sing-box 按进程判断，未命中的流量走 `direct` |
| 对系统的影响 | 不改默认路由，不改系统代理，也不改系统 DNS | 改默认路由；与其他 VPN 或全局代理可能冲突 |
| 能匹配 | 域名 | 进程名、进程路径，以及域名 |
| 局限 | 应用如果直接连 IP、自带 DoH，或者用了硬编码的 DNS，流量就不会进隧道 | 侵入性更强，需要处理路由回环（`auto_detect_interface`） |

注意：**按进程分流必须让流量先进入 TUN**，所以只改 fake-ip 网段路由的域名模式做不到按进程分流。两种模式不能合并成同一种低侵入的实现。

### 域名模式配置要点

- TUN 开启 `auto_route`，但把 `route_address` 限定为 fake-ip 网段，这样默认路由保持不变。 [TUN 字段](https://sing-box.sagernet.org/configuration/inbound/tun/)
- macOS 上只为指定域名写入 `/etc/resolver/<domain>`，让它的 `nameserver` 指向 TUN 网段内的地址。这些 DNS 查询会进入 TUN，被 sing-box 用 `hijack-dns` 截获并返回 fake-ip，其他域名仍走系统原来的 DNS。Windows 用 NRPT 规则实现同样的效果。
- 默认 IPv6 不进隧道，客户端对命中的域名只返回 A 记录，防止应用改走 IPv6 直出。

```jsonc
{
  "dns": {
    "servers": [{ "type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/15" }],
    "rules": [{ "domain_suffix": ["example-target.com"], "server": "fake" }]
  },
  "inbounds": [{
    "type": "tun", "tag": "tun-in",
    "address": ["172.19.0.1/30"],
    "auto_route": true,
    "route_address": ["198.18.0.0/15", "172.19.0.0/30"]
  }],
  "route": {
    "rules": [
      { "protocol": "dns", "action": "hijack-dns" },
      { "ip_cidr": ["198.18.0.0/15"], "outbound": "egress" }
    ],
    "final": "direct",
    "auto_detect_interface": true
  }
}
```

### 应用模式配置要点

- `auto_route: true` 且不设 `route_address`，`strict_route: true`，用来防止 Windows 的 DNS 泄漏。
- 规则按 `process_name`、`process_path` 或 `process_path_regex` 匹配。CLI 工具常常以 `node`、`python` 这类解释器的身份运行，用进程名匹配会误伤其他程序，所以界面上要让用户选择具体的可执行文件路径。
- 命中规则的流量里，UDP 443（QUIC）要么一起转发，要么用 `reject` 拦截，逼应用回落到 TCP。首版选择拦截，行为更容易预测。
- 发往本地网段的流量不进 TUN：sing-box 加了一条 `lookup main suppress_prefixlength 0` 的策略规则，主路由表里除默认路由以外的网段路由都优先生效。因此，被选中的应用访问局域网地址时仍走直连。原型测试中实测确认了这一点。

两种模式都已实现在 `egress/gen.py client --mode domain|app` 中，并在 Docker 里的 Linux TUN 上通过了端到端测试；macOS 部分（`/etc/resolver`、utun）还待真机验证，见 [client/README.md](../client/README.md)。

### 客户端外壳

- 登录：用设备 token 换取订阅地址，定时拉取配置，并校验签名和版本号。
- 状态：当前入口线路、出口 IP、延迟，以及最近一次诊断结果。
- 诊断：通过隧道请求出口 IP 回显接口，确认看到的出口 IP 就是分配的那个；再检查 DNS 是否在远端解析、有没有 IPv6 直出。
- 冲突检测：如果检测到本机还有其他代理软件接管了同样的域名（系统代理，或者 `HTTP_PROXY` 等环境变量），提示用户为这些域名设置 `DIRECT` 规则，或者清除环境变量。

## 隧道与中转

- 客户端到入口这一段默认用 **VLESS+Reality**（TCP）；Hysteria2（UDP）作为备选，适合丢包高的线路。不要用明文 SOCKS5 或 HTTP 代理，这一段要穿越公网。
- 每个设备一个独立凭证（VLESS 的 `uuid` 加 `name`），这样可以单独吊销某个设备。
- 中转机只做四层转发（nftables DNAT 或 realm），不解密。两台中转机互为主备。客户端用 sing-box 的 `urltest` 或 `selector` 在两个入口之间切换，也保留直连出口机这一条线路作为第三选择。
- 什么时候需要中转：用户到出口机的直连线路质量差的时候。首版先用直连上线，再用实测延迟和丢包决定是否启用中转。

## 出口机

### IP 准备

- 出口 IP 必须由机房路由到这台机器上：额外 IP，或者路由过来的一整段（比如 /27 或 /24）。只在网卡上配地址、但上游并不把这些地址路由过来，是行不通的。
- 用 systemd-networkd 或 netplan 持久化配置，不用临时的 `ip addr add` 命令：

```bash
# 临时验证用
for i in $(seq 3 30); do ip addr add 203.0.113.$i/32 dev eth0; done
```

- 每个 IP 上线前用 `curl --interface 203.0.113.N https://api.ipify.org` 验证出站地址，并查一下它的地理位置和 ASN 归属。

### 用户 → 出口 IP

**方案 A（首版采用）：在 sing-box 里绑定出站地址。** 一个 sing-box 进程接收所有用户，按入站认证出来的用户名选择出站，每个出站用 `inet4_bind_address` 绑定一个 IP。 [Dial 字段](https://sing-box.sagernet.org/configuration/shared/dial/)

```jsonc
{
  "inbounds": [{
    "type": "vless", "tag": "in", "listen": "::", "listen_port": 443,
    "users": [{ "name": "u-alice", "uuid": "..." }, { "name": "u-bob", "uuid": "..." }],
    "tls": { "enabled": true, "reality": { "...": "..." } }
  }],
  "outbounds": [
    { "type": "direct", "tag": "ip-3", "inet4_bind_address": "203.0.113.3" },
    { "type": "direct", "tag": "ip-4", "inet4_bind_address": "203.0.113.4" },
    { "type": "block", "tag": "deny" }
  ],
  "route": {
    "rules": [
      { "auth_user": ["u-alice"], "outbound": "ip-3" },
      { "auth_user": ["u-bob"], "outbound": "ip-4" }
    ],
    "final": "deny"
  }
}
```

`final` 设为 `deny`：没有绑定 IP 的用户不允许走主 IP 出站，这样配置出错时会直接断开，而不是悄悄换成另一个出口。

**方案 B（规模大时再评估）：在内核里做 SNAT。** 给每个用户分配独立的入站端口或 fwmark，再用 `iptables -t nat -A POSTROUTING -m mark --mark N -j SNAT --to-source 203.0.113.N` 改写源地址。适合 IP 数量上百、而且不想在每次绑定变更时重载代理配置的场景。

### 配置热更新

控制面修改了用户和 IP 的绑定后，生成新的服务端配置，先用 `sing-box check` 校验，再平滑重载。首版接受重载时已有连接被断开。

### 出口机安全

- 只开放隧道端口和管理用的 SSH（限定来源 IP）。
- 出站方向禁止访问内网网段和云厂商的元数据地址（`169.254.169.254`），防止被用户当作跳板攻击内网。
- 只记录连接元数据（用户、目标域名、字节数、时间），不记录内容。

## 控制面

### 数据模型

```text
User(id, email, status, plan)
Device(id, user_id, name, credential_uuid, last_seen, revoked_at)
EgressIP(ip, host_id, asn, geo, status: available|assigned|cooldown|banned)
Assignment(user_id, ip, mode: exclusive|shared, assigned_at)
Entry(id, kind: direct|relay, address, port, priority, weight, status)
Probe(target, vantage, latency_ms, ok, at)
```

- 一个 IP 解除绑定后先进入 `cooldown`（例如 7 天），再回到可分配池，避免下一个用户立刻继承上一个用户在该 IP 上的信誉。
- `banned` 用来标记被目标站点拉黑的 IP，这类 IP 不再分配。

### 实际实现（v2）

上面是最初的设想。实现中的模型以 [controlplane/README.md](../controlplane/README.md) 为准，要点如下：

- **多台出口机（主机）**：每台有自己的公网入口地址、Reality 密钥（控制面自动生成）、一段用户入口端口范围和独立的 agent 令牌。出口 IP 归属于主机。
- **用户 = 用户名 + 密码**，绑定一个出口 IP，以及该 IP 所在主机上的一个专属入口端口。出口机为每个用户开一个 sing-box 入站，按入站路由到绑定的出口 IP。
- **设备在登录时创建**：每台电脑一个独立的 VLESS 凭证和订阅令牌，默认每个账号最多 5 台，可单独吊销。
- **出站拦截先解析再匹配**：用解析到内网地址的域名也绕不过内网拦截。这个漏洞是在多主机端到端测试里发现的，v1 的文件式流程也一并修复了。

### 配置下发

- 客户端先 `POST /v1/login` 换取设备令牌，再用 `Authorization: Bearer <令牌>` 请求 `GET /v1/config?mode=app`；ETag 是配置内容的哈希，内容没变时返回 304。
- 服务端配置按主机生成，每台出口机上的 agent 用自己的令牌拉取，等配置稳定后合并成一次重载。

### 健康探测

- 从多个探测点（按用户所在的地区和运营商选）定时测量每个入口的 TCP 握手延迟和丢包。
- 从出口机用每个出口 IP 分别请求目标域名，记录成功率和状态码，及早发现被拉黑的 IP。
- 后台拓扑页展示：入口 → 中转 → 出口 IP → 绑定的用户和设备，以及每条线路最快的探测结果。

## 防泄漏清单

| 泄漏点 | 处理方式 |
| --- | --- |
| DNS | 命中的域名只由 sing-box 解析，真实解析在出口机进行 |
| IPv6 | 首版命中的域名不返回 AAAA，出口机也不配置 IPv6 出站 |
| QUIC/UDP | With QUIC blocking enabled, matching UDP 443 is rejected after the STUN rule is evaluated. |
| WebRTC (STUN) | Compatible app-mode clients route recognized UDP STUN through the exit by default, including UDP 443. The dual-stack TUN captures IPv6 STUN, and the exit refuses IPv6 destinations. On Linux, an outgoing filter drops local STUN that remains bound to a physical interface. The bundled frpc uses direct IPv4 STUN to establish XTCP. The environment check compares STUN replies with the verified exit. See the [client policy and coverage](../client/README.md#webrtc-and-stun). |
| 应用自带 DoH | 域名模式下无法控制；在诊断页说明，引导用户改用应用模式 |
| 其他代理抢先接管 | 客户端检测并提示设置 `DIRECT` 规则 |
| 绑定缺失 | 服务端 `final: deny`，没有绑定就断开 |

## 里程碑

1. **出口机原型**：绑定 3 个 IP，sing-box 配 3 个用户，用 `sing-box` 客户端或 `curl --proxy` 分别验证每个用户看到的出口 IP。已完成，见 [egress/](../egress/README.md)。
2. **客户端原型（macOS）**：手写配置，跑通域名模式和应用模式，按防泄漏清单逐项验证。分流逻辑已在 Linux TUN 上验证；macOS 真机待验收，见 [client/](../client/README.md)。
3. **控制面 MVP**：用户、设备、IP 分配、配置订阅接口，加上出口机 agent 的热更新。已完成，见 [controlplane/](../controlplane/README.md)。
4. **客户端外壳**：登录、状态、诊断、冲突检测，以及打包和签名。已完成：Tauri 桌面端（macOS、Windows、Linux）和 ccproxy 命令行，见 [client/](../client/README.md)。Linux 客户端已通过端到端测试；macOS 应用已构建；三个平台的提权方式和 Windows、Linux 安装包未验证；冲突检测和代码签名未做。
5. **线路增强**：中转主备、多点探测、拓扑看板。多点探测和拓扑看板已完成，见 [controlplane/](../controlplane/README.md#monitoring-and-topology)；中转主备未做。

## 验收

| 项目 | 验收方法与预期结果 |
| --- | --- |
| 出口 IP 绑定 | 两个用户同时在线，各自通过隧道请求 IP 回显接口，看到的分别是自己被分配的 IP，并且与分配表一致 |
| 域名分流 | 命中的域名走出口 IP；未命中的域名和本地内网仍走本地出口。用 `netstat -rn` 确认默认路由没有变化 |
| 应用分流 | 选中的应用走出口 IP；同一台机器上其他应用访问同一域名时，按规则判断（命中域名规则的走隧道，否则直连） |
| DNS / IPv6 / QUIC | 抓包确认命中域名的 DNS 查询没有发往本地 DNS 服务器，没有 IPv6 直出，UDP 443 被拦截 |
| 绑定缺失 | 删除某个用户的 IP 绑定后，该用户的新连接失败，而不是从主 IP 出去 |
| 设备吊销 | 吊销某个设备的凭证后，该设备的新连接被拒绝，同一用户的其他设备不受影响 |
| 线路切换 | 停掉主入口，客户端在设定时间内切到备用入口，出口 IP 不变 |

## 待定问题

- 出口 IP 的来源：机房 IP 段，还是住宅 IP（ISP 代理）？这影响成本、IP 信誉，以及能否拿到整段路由。
- 用户所在地区以及到出口机的线路质量，这决定首版是否需要中转。
- 共享模式下一个 IP 最多分给几个用户。
- 客户端首版是否需要 Windows。
