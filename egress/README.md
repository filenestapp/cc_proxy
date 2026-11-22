# 出口机原型

这是 [多 IP 出口分流代理设计](../docs/multi-ip-egress-proxy-design.md) 里程碑 1 的实现。一台出口机挂一组 IP，每个用户的流量从分配给他的那个 IP 出去。内核用 sing-box 1.14.4：入站是 VLESS+Reality，路由按 `auth_user` 识别用户，再交给绑定了该用户 IP 的 `direct` 出站（`inet4_bind_address`）。

## 文件

| 路径 | 作用 |
| --- | --- |
| `gen.py` | 从 inventory 生成服务端配置、原型客户端配置和 IP 列表，并做校验。只依赖 Python 3.8+ 标准库 |
| `inventory.example.json` | inventory 格式示例 |
| `deploy/ips.sh` | 把出口 IP 加到网卡上或移除（`up`/`down`），以及逐个 IP 验证出口（`verify`）|
| `deploy/egress-ips.service` | 开机时在 sing-box 启动前加好 IP |
| `deploy/apply.sh` | 在服务器上执行：生成 → `sing-box check` → 安装 → 加 IP → 重载 |
| `test/` | Docker 端到端测试，不依赖外网 |

## inventory 规则

- `egress_ips[].status` 可以是 `available`、`cooldown` 或 `banned`，只有 `available` 的 IP 能分配给用户。
- 每个用户最多绑定一个 `egress_ip`。默认独享；一个 IP 分给多个用户时，这些用户都必须标记 `"mode": "shared"`，否则校验报错。
- 认证按设备进行，每个设备一个 uuid，服务端用户名是 `用户/设备`。设备标记 `"revoked": true` 后，服务端配置里就不再有这个设备。
- 没有绑定 IP 的用户、已吊销的设备，流量都落到 `route.final = deny`，连接断开，不会从主 IP 出去。
- `block_private`（默认开启）和 `block_cidrs` 用来拦截发往内网和云元数据地址的连接。

```bash
python3 gen.py check  inventory.json
python3 gen.py server inventory.json -o server.json
python3 gen.py client inventory.json alice-mac -o alice-mac.json   # 本地 127.0.0.1:2080 起一个 SOCKS/HTTP 代理
python3 gen.py ips    inventory.json
```

`client` 默认生成本地代理配置（`--mode proxy`）。`--mode domain` 和 `--mode app` 生成 TUN 分流客户端配置，规则取自 inventory 里的 `client_policy`，详见 [client/README.md](../client/README.md)。`gen.py domains` 列出需要写进 macOS `/etc/resolver` 的域名。

## 本地端到端测试

需要 Docker。测试用两个网络：`lan` 是用户侧，`wan` 模拟公网。出口机同时连两边，在 `wan` 上挂 5 个出口 IP，并兼做 lan 到 wan 的路由器。echo 服务回显它看到的源地址，Caddy 充当 Reality 的握手目标。目标站点必须放在 `wan`：发往本地网段的流量不会进入客户端的 TUN。

```bash
egress/test/run-e2e.sh          # KEEP=1 时测试结束后保留容器
```

测试分三段：

1. **SOCKS 客户端，初始绑定**：两个独享用户、两个共享同一个 IP 的用户、一个没有 IP 的用户、一个已吊销的设备。每个设备都测 TCP（用 IP 连接）、TCP（用域名连接，由出口机解析）、UDP，以及一个被拦截的目标。
2. **TUN 客户端**：域名模式和应用模式，覆盖范围见 [client/README.md](../client/README.md)。
3. **SIGHUP 重载**：解除一个用户的绑定、吊销一个设备、把冷却期的 IP 分配给新用户。

2026-11-21 在 Docker Desktop（arm64）上运行，三段全部通过。

## 部署到真实主机

需要 Linux、官方包安装的 sing-box、python3，以及机房已经路由到这台机器的 IP 段。

```bash
sudo mkdir -p /opt/egress /etc/egress
sudo cp -r gen.py deploy /opt/egress/
echo 'EGRESS_IFACE=eth0' | sudo tee /etc/egress/env
sudo cp inventory.json /etc/egress/inventory.json && sudo chmod 600 /etc/egress/inventory.json
sudo cp /opt/egress/deploy/egress-ips.service /etc/systemd/system/ && sudo systemctl daemon-reload
sudo /opt/egress/deploy/apply.sh /etc/egress/inventory.json
sudo systemctl enable egress-ips
sudo /opt/egress/deploy/ips.sh verify eth0 /etc/egress/ips.txt
```

## 已知限制

- 重载会断开当时正在进行的连接。
- 从 inventory 删掉的 IP，`apply.sh` 不会自动从网卡上移除，需要先用旧列表执行 `ips.sh down`。
- `apply.sh` 和 `egress-ips.service` 还没在真实的 systemd 主机上跑过。`ips.sh` 只在容器里测过。
- 只支持 IPv4 出站，DNS 也只解析 IPv4（`ipv4_only`）。
