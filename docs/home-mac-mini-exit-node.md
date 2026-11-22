# Mac mini 家庭宽带出口设计

第一版为日本的一名用户提供整机互联网出口。用户在自己的设备上启用 Tailscale 出口节点后，网站看到的是 Mac mini 所在家庭宽带的公网出口地址。首轮按一台 Mac mini、一台用户设备设计。用户自行选择何时启用出口。

如果首版还要为自有客户端或域名分流铺路，使用 [SingTeam 技术复用方案](singteam-netbird-reuse.md)中的 NetBird 试点。两种客户端共用本文的出口、隔离与重启验收。

## 网络路径

```text
User device in Japan
  -> Tailscale WireGuard tunnel (direct or DERP relay)
  -> Mac mini exit node on an isolated home segment
  -> Home router and ISP
  -> Internet
```

家里的路由器或运营商处理公网 IPv4 出站。Tailscale 优先尝试 UDP 直连，直连失败时可以通过 DERP 转发加密流量。两条路径都在家里的 Mac mini 结束隧道。首版用现有家宽测试，路由器端口映射保持关闭。用 `tailscale status` 区分 `direct` 和 `relay`。 [出口节点](https://tailscale.com/docs/features/exit-nodes?tab=macos) · [连接类型](https://tailscale.com/docs/reference/connection-types) · [防火墙说明](https://tailscale.com/docs/integrations/firewalls)

家宽如果通过 CGNAT 上网，网站看到的是运营商共享的公网 IPv4。宽带重新拨号也可能更换公网地址。若后续要让第三方长期把该 IP 加入白名单，需要先确认运营商能否提供固定公网地址。

## 用户权限与家庭网络

1. 为这台出口机使用独立的 Tailscale 网络。批准 Mac mini 作为出口后，在管理台 **Share** 中用收件地址分享给该日本用户，并勾选 **Allow use as an exit node**。对方使用自己的账号接受分享。 [分享出口节点](https://tailscale.com/docs/features/sharing#sharing-and-exit-nodes)
2. 将访客的权限限定为 `autogroup:internet`。使用对方接受邀请的邮箱替换下方占位值，清理任何同时覆盖该访客的全放行规则。避免发布家庭子网路由，Mac mini 的 SSH、屏幕共享和文件共享仅走独立管理路径。 [出口权限](https://tailscale.com/docs/features/exit-nodes#grant-access-to-use-the-exit-node) · [访问策略语法](https://tailscale.com/docs/reference/syntax/policy-file)
3. 优先用网线将 Mac mini 接入隔离 VLAN。家用路由器只支持访客 Wi-Fi 时，先确认访客网络能出网且隔离主网。路由器防火墙应阻止出口网段访问家庭主网和路由器管理界面，并验证 IPv4、IPv6 两种地址。客户端的 **Allow Local Network Access** 控制日本端自己的局域网访问，家庭主网隔离由家里的路由器负责。 [客户端本地网络访问](https://tailscale.com/docs/features/exit-nodes#local-network-access)

以下是访客的权限条目，放进独立网络的访问策略并保留所需的管理员权限。

```json
{
  "grants": [
    {
      "src": ["visitor@example.com"],
      "dst": ["autogroup:internet"],
      "ip": ["*"]
    }
  ]
}
```

## 首次部署

1. 在目标 Mac mini 确认 macOS 版本和上网接口。官方当前的三种 macOS 客户端均要求 macOS 13 或更新版本。首轮使用官方 Standalone 图形客户端，批准系统扩展，在菜单选择 **Exit Node → Run Exit Node**，再到管理台批准。在 macOS「节能」中启用「显示器关闭时防止自动睡眠」。 [macOS 版本对照](https://tailscale.com/docs/concepts/macos-variants) · [Mac 睡眠设置](https://support.apple.com/en-gb/guide/mac-help/mchle41a6ccd/mac)
2. 先用自己的一台设备切到手机热点，选择 Mac mini 作为出口，执行出口地址和家庭隔离测试。两项通过后，再对日本用户开通分享。
3. 日本用户接受分享，在 Tailscale 客户端选择 Mac mini，然后执行同一套验收。共享授权按账号授予，首轮在一台指定设备上验收。用户停用时可选择 **None**。管理者可在 **Machines → Share** 撤销该用户的分享。 [开通出口](https://tailscale.com/docs/features/exit-nodes/how-to/setup?tab=macos) · [撤销分享](https://tailscale.com/docs/features/sharing#revoke-an-invite)

## 验收

在 Mac mini 和外网测试设备上分别运行以下命令。日本端在启用出口前后各测一次。Windows PowerShell 里用 `curl.exe`。 [ipify 公网地址查询](https://www.ipify.org/)

```bash
curl --noproxy '*' -4 -fsS --max-time 10 https://api.ipify.org
curl --noproxy '*' -6 -fsS --max-time 10 https://api6.ipify.org
```

| 项目 | 验收方法与预期结果 |
| --- | --- |
| 公网 IPv4 | 同一时段在 Mac mini 与日本设备查询外部服务看到的 IPv4。日本端启用出口后与 Mac mini 一致，停用后恢复当地出口。 |
| DNS、IPv6 和 UDP | 检查浏览器与至少一个实际应用。验证 DNS 查询及 UDP/QUIC 流量按预期走出口。若家庭宽带提供 IPv6，验证 IPv6 的出站路径。若家庭没有可用的 IPv6 出口，确认测试连接无法从日本端 IPv6 直出。Tailscale 默认会使用出口节点处理系统 DNS，还应验证应用启用加密 DNS 时的实际网络路径。 [Tailscale DNS](https://tailscale.com/docs/reference/dns-in-tailscale#nameservers-and-exit-nodes) |
| 家庭隔离 | 在家里先确认路由器管理页和一个受控的家庭服务可从管理网络访问。再从日本设备测试同一地址和端口，应无法连接。另测 Mac mini 的管理服务，确认访客权限仅允许互联网出口。 |
| 性能 | 标记 `direct` 或 `relay`，从日本记录一次实际使用场景的延迟、下载和上传。日本端下载会消耗家宽上行，优先用家宽上行测速和真实场景判断是否够用。 |
| 中断与回滚 | 测试 Mac mini 断网、重新联网和权限撤销。家庭出口仍被选中时，验收要求联网失败并且公网地址测试无结果。用户主动选 **None** 后恢复当地出口。撤权后用新连接确认该账号无法继续用家庭出口。 |

## 重启与长期运行

首版以 macOS 用户登录后开始提供出口为运维条件。图形版需要登录会话。如果要求断电重启后自动恢复，可以在同一台机器上评估开源 `tailscaled` 变体。官方将它列为支持登录前运行的 macOS 变体，实际恢复还受启动解锁、服务自启动和网络上线顺序影响。保留 FileVault 的现有安全设置，用一次计划内重启验证完全无人值守是否成立。 [macOS 变体对照](https://tailscale.com/docs/concepts/macos-variants) · [无人值守说明](https://tailscale.com/docs/how-to/run-unattended)

进入部署前核对目标 Mac mini 的 macOS 版本、家庭路由器的隔离能力以及日本用户设备的操作系统。日本端真实延迟、吞吐量与公网地址以实测为准。
