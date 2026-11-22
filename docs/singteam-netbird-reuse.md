# SingTeam 客户端的技术实现与复用方案

家庭出口试点可以直接用官方 NetBird 客户端。它提供了 SingTeam 使用的 WireGuard 隧道、本地后台服务和设备策略。Mac mini 运行后台服务作为出口，日本用户先用官方客户端选线路。需要自有界面时，再通过本机 API 接入同一个后台服务。 [NetBird macOS 安装](https://docs.netbird.io/get-started/install/macos) · [NetBird 出口节点](https://docs.netbird.io/use-cases/remote-access/exit-nodes)

## SingTeam 安装包的证据

公开的 Apple Silicon 安装包 `0.1.38` 包含两个 Go 可执行文件。以下信息来自解包后的 Go 构建元数据、符号和安装脚本。 [公开安装包](https://sgteam.ai/downloads/v0.1.38/SingTeam_0.1.38_darwin_arm64.pkg)

| 组件 | 安装包里的实现 | 上游复用点 |
| --- | --- | --- |
| `singteam-service` | Go 入口 `github.com/netbirdio/netbird/client`，使用 `netbirdio/wireguard-go`。安装脚本注册系统级 `launchd` 服务 `io.singteam.client`。 | 用签名的 NetBird 官方发行版，在家用 Mac 上运行后台服务。 [macOS 安装](https://docs.netbird.io/get-started/install/macos) |
| `singteam-ui` | Go 入口 `github.com/netbirdio/netbird/client/ui`，使用 Wails v3。UI 包含 `Status`、`GetConfig`、`ListNetworks` 和 `SelectNetworks` 的 gRPC 客户端。服务通过 Unix socket `/var/run/singteam.sock` 提供本机接口。 | 试点先用 NetBird 官方 UI。自有桌面界面可用 Wails，通过 NetBird 的本机 gRPC API 查看状态、读取线路并执行连接控制。 [本机 gRPC API](https://docs.netbird.io/client/grpc-socket) |
| 域名分流 | 后台包含 `DnsInterceptor.ServeDNS`、`replaceIPsInDNSResponse`、`AllocateFakeIP` 和动态路由代码。官方排障页面描述了 `utun`、`100.91` 路由和 `pf`。 | 从 NetBird 的域名资源与路由节点 DNS 功能开始，先用自有测试域名验证。 [SingTeam 排障](https://sgteam.ai/troubleshooting.html) · [NetBird 域名资源](https://docs.netbird.io/manage/networks/use-cases/by-resource-type/accessing-entire-domains-within-networks) |
| 登录与诊断 | 官网描述企业邮箱准入。安装包包含 `doctor` 诊断逻辑，排障页列出守护进程、隧道和域名提示。 | 账户准入先用 NetBird 的设备注册与组策略。自有客户端可以实现连接状态、实际出口 IP 和 DNS 检查。 [SingTeam 隐私政策](https://sgteam.ai/privacy.html) · [NetBird 访问策略](https://docs.netbird.io/manage/access-control) |

两个二进制都记录了构建提交 `c3229f3589442c4451272aa20dad69bf18adcfe2`。NetBird 官方公开仓库按完整 SHA 查询未找到该提交，因此采用官方发行版作为可复用源。安装包能确认客户端组件，生产环境的 DNS 参数、登录后端以及远端 SOCKS 和地址池实现仍需运行时或服务端证据。 [NetBird 发行版](https://github.com/netbirdio/netbird/releases)

## 家庭出口试点

```text
NetBird management -> device enrollment, groups, and routes
Japan device -> WireGuard tunnel -> home Mac mini -> home ISP -> Internet
Optional desktop UI -> local Unix socket -> NetBird daemon
```

1. 使用专用 NetBird 网络。Mac mini 用官方包装好后台服务，接入隔离 VLAN 或已验证隔离的访客网络。Mac mini 和日本端设备分别放进 `home-egress` 和 `japan-pilot` 设备组。 [macOS 安装](https://docs.netbird.io/get-started/install/macos) · [设备组](https://docs.netbird.io/manage/access-control)
2. 将 Mac mini 添加为 Exit Node。分发组只选 `japan-pilot`，开启 Masquerade，关闭 Auto Apply，让用户手动启用。创建 `japan-pilot → home-egress` 的单向最小访问策略，允许官方文档要求的 ICMP，移除初始 `All → All` 规则。出口网段对家庭主网的过滤由家用路由器执行。 [出口节点配置](https://docs.netbird.io/use-cases/remote-access/exit-nodes) · [路由节点与最小策略](https://docs.netbird.io/manage/networks/how-routing-peers-work#exit-node-mode)
3. 为试点组配置适合全隧道的 DNS，并检查日本端的实际解析路径。用 `netbird status -d` 确认当前出口和直连或中转状态。沿用[家庭出口验收](home-mac-mini-exit-node.md#验收)中的公网 IPv4、IPv6、DNS、UDP、家庭隔离、断线和撤权测试。补测一次重启后停在登录界面时，Mac mini 是否已经恢复出网服务。 [出口 DNS 与验证](https://docs.netbird.io/use-cases/remote-access/exit-nodes)

## 自有客户端的开发边界

- **全流量模式**由管理面把家庭 Exit Node 分配给指定设备。客户端显示连接状态和实际公网出口。 **域名模式**用 NetBird 域名资源配置指定域名，验收时分别检查命中和未命中的连接路径。 [出口节点](https://docs.netbird.io/use-cases/remote-access/exit-nodes) · [域名资源](https://docs.netbird.io/manage/networks/use-cases/by-resource-type/accessing-entire-domains-within-networks)
- **自有桌面 UI**通过上游本机 gRPC 接口接入后台服务，主要做登录、连接、线路选择和诊断。将后台服务控制保留在本机 socket，管理面使用独立的设备与策略 API。 [本机 gRPC API](https://docs.netbird.io/client/grpc-socket) · [NetBird 管理 API](https://docs.netbird.io/api)
- **多公网 IP**仍需独立实现出口分配。首版 Mac mini 只有一个家庭宽带出口。未来若落到持有多个公网 IP 的 Linux 主机，可先验证保留设备隧道源地址，再用 nftables 做固定 SNAT。 [NetBird 源地址转换](https://docs.netbird.io/manage/networks/masquerade) · [nftables 映射](https://wiki.nftables.org/wiki-nftables/index.php/Maps)
- **重新发行**以 NetBird 上游授权为依据。当前上游 `client/` 按 BSD-3-Clause，分发时保留适用声明。自托管涉及的 `management/`、`signal/`、`relay/` 和 `combined/` 目录按各自的 AGPLv3 许可处理。 [NetBird 许可证](https://raw.githubusercontent.com/netbirdio/netbird/main/LICENSE)

如果交付目标是尽快给一位用户共享家庭宽带，[Tailscale 方案](home-mac-mini-exit-node.md)可以直接试点。如果交付目标包含自己的客户端或域名分流，优先采用以上 NetBird 方案，先测通官方客户端，再做自有界面。
