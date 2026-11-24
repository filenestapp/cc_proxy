# 客户端

用户在桌面端用控制端分配的用户名和密码登录。登录后客户端自动取到出口 IP 和入口 `IP:端口`，配好隧道；命中规则的域名走代理，其他流量保持本机网络。

```text
client/
  core/     Rust 库：登录与订阅 API、会话存储、配置同步、sing-box 守护、按系统提权
  cli/      ccproxy 命令行：无界面客户端，同时也是桌面端提权后运行的守护程序
  desktop/  Tauri 2 桌面端（macOS、Windows、Linux），界面在 desktop/ui
  macos/    文件式流程时代的 /etc/resolver 脚本（域名模式），桌面端不再使用
```

## 工作方式

- **登录**：客户端用用户名、密码和设备名（默认为本机名）调用 `POST /v1/login`，拿到这台设备的令牌。本地只保存令牌（在用户配置目录下的 `cc-proxy/session.json`，Unix 上权限 0600），不保存密码。管理员可以单独吊销这台设备。
- **配置**：用令牌请求 `GET /v1/config?mode=app`，得到指向用户专属入口（`主机:端口`）的 sing-box 配置。之后每 30 秒带 ETag 检查一次：配置没变时只有一个 304，变了就写入新文件。管理员把用户换到另一台出口机时，客户端会自己跟上。
- **macOS 的 DNS**：mDNSResponder 把查询绑定在物理网卡上直接发出，不经过 TUN，所以单靠劫持 DNS 不起作用。为此，守护进程会为每个规则域名写一个 `/etc/resolver/<域名>`，指向 TUN 内的 DNS `172.19.0.2`，只改变这些域名的解析；断开时删除这些文件。域名来自服务端下发的配置，而这些文件是以 root 身份写入的，所以只接受规范的域名，`../` 之类会被丢弃；不是本程序写的同名文件也不会动。
- **DNS 缓存**：连接、每次配置重载、断开之后，都会刷新系统 DNS 缓存（macOS 用 `dscacheutil`/mDNSResponder，Windows 用 `ipconfig /flushdns`，Linux 用 `resolvectl`）。否则连接前缓存的真实地址或「不存在」会绕过规则，断开后残留的 fake-ip 又会让这些域名打不开。重载后会先等 1.5 秒，让 sing-box 加载完新规则，再改解析和刷新缓存。
- **分流**：app 模式，即 TUN 接管默认路由并劫持 DNS。控制端 `client_policy.domain_suffix` 里的域名解析成 fake-ip，通过隧道从用户的出口 IP 出去；其他域名用 `direct_dns` 解析后直连。命中域名的 UDP 443（QUIC）被拦截，迫使应用回落到 TCP。发往本地网段的流量不进 TUN。
- **提权**：TUN 需要管理员权限。点击「连接」时弹一次系统授权（macOS 输入密码，Linux 走 polkit，Windows 走 UAC），以管理员身份启动随包附带的 `ccproxy tunnel`。之后界面进程只写文件：配置、每 5 秒一次心跳、断开时的 stop 文件。守护进程只读这些文件，各个系统用同一套机制：
  - 配置文件变了，先 `sing-box check`，再重载（Unix 发 SIGHUP，Windows 重启进程）。检查不通过就继续用旧配置。
  - 配置文件被删除（已退出登录或出口被收回），停止。
  - 出现 stop 文件，停止。
  - 心跳超过 30 秒没更新（界面崩溃或被强制退出），停止。所以不会留下一个以 root 身份运行的 sing-box。
  - sing-box 意外退出，自动重启；一分钟内超过 5 次就停止，并在状态里报失败。
- **权限边界**：守护进程以 root 或管理员身份运行，只把用户目录当作输入。它从客户端配置里提取有限的几项参数并逐项校验，自己重新生成配置，要求客户端文件与生成结果完全一致，有任何多余字段就拒绝。生成的配置、工作目录、日志、状态都放在只有 root 能写的目录里：macOS 是 `/Library/Application Support/CCProxy`，Linux 是 `/var/lib/ccproxy`，Windows 是 `%ProgramData%\CCProxy`（会重设 ACL）。启动、重载、重启用的都是这份校验过的配置。
- **被下线**：令牌失效（管理员吊销、重置密码、在别处退出）后，下一次检查拿到 401，客户端清掉会话和配置，隧道随之关闭。出口被收回（409）也一样。

## 桌面端

```bash
cd client/desktop
scripts/fetch-binaries.sh                     # 编译 ccproxy，下载 sing-box 1.14.4 并按 GitHub 公布的 SHA-256 校验
cd src-tauri && npx @tauri-apps/cli@2.12.6 build --bundles app    # macOS；Windows 用 nsis，Linux 用 deb/appimage
```

安装包里，`ccproxy` 和 `sing-box` 放在主程序旁边。[.github/workflows/desktop.yml](../.github/workflows/desktop.yml) 分别在 macOS（Apple 芯片）、Windows、Linux 上构建并上传安装包。没有签名：macOS 公证和 Windows 代码签名需要证书，还没配。

The desktop app shows the control plane URL, username, password, and optional device name at sign-in. The home screen shows the tunnel state, connection control, assigned entry and egress IP, host, account, and device.

Use **Language** in the header to choose **System**, **English**, or **Simplified Chinese**. System is the default. The app uses the first supported system language and falls back to English. The app remembers language and appearance choices across restarts.

## 命令行（ccproxy）

```bash
ccproxy login --server https://cp.example.com --user alice     # 密码从标准输入或 CCPROXY_PASSWORD 读取
sudo ccproxy up                                                # 前台运行：保持配置最新，运行 sing-box；Ctrl-C 停止
ccproxy status
ccproxy logout                                                 # 在服务端吊销这台设备，并清掉本地会话
```

`ccproxy up` 把同步和守护放在同一个进程里，适合 Linux 服务器或排查问题。`ccproxy tunnel` 是桌面端提权后运行的那一半，不需要手动执行。

## 测试

- 控制面的端到端测试 [controlplane/test/run-e2e.sh](../controlplane/test/run-e2e.sh) 第 3b 段，在 Docker 里的 Linux TUN 上运行真实的 `ccproxy`（`client/test/Dockerfile` 编译）。2026-11-22 全部通过：
  - 用密码登录；
  - 规则域名拿到 fake-ip，并从用户的出口 IP 出去；其他域名经劫持的 DNS 正常解析，并且直连；默认路由走 TUN；
  - 管理员把用户换到另一台出口机后，客户端在下一次检查时拿到新配置，出口 IP 随之切换，客户端无需任何操作；
  - 管理员吊销设备后，`ccproxy up` 退出，sing-box 和 TUN 网卡都清理干净，本地会话被清除；
  - stop 文件和心跳超时都能让守护进程自己停下，不留 sing-box 进程。
- `cargo clippy -D warnings` 通过（core、cli、desktop）。
- macOS 应用（Apple 芯片）能构建、打包，两个附带程序都能运行。界面的登录页和主页在浏览器里用模拟接口检查过显示效果。

- **macOS 真机**（2026-11-22，Apple 芯片，用 `client/test/local-demo/up.sh` 搭建本地控制端和 Docker 出口机）：
  - 登录、授权提示、以 root 运行守护进程，全部正常；
  - 规则域名 `echo.example.com` 经系统解析得到 fake-ip，从出口 IP `10.99.0.3` 出去；
  - 其他域名照常解析和直连，公网 IP 不变；
  - 控制端修改规则后，客户端自动重载；
  - 退出 App 后，隧道在 1 秒内停止，路由被清理。

  真机测试中发现并修复了三个问题：
  - 界面每 1.5 秒刷新一次时，会把出口信息清空；
  - macOS 的 DNS 查询绕过了 TUN；
  - DNS 缓存的问题。

  另外，`.test` 域名在 macOS 上会被系统本地直接判为「不存在」，规则域名不要用 `.test`。

**未验证**：

- Linux 的 pkexec、Windows 的 UAC 提权（macOS 的 osascript 已在真机验证）。
- Windows 和 Linux 的安装包：已写好 CI 构建流程，没有实际运行过。
- Windows 和 Linux 桌面上的 DNS 行为。Linux 上的 systemd-resolved 也按网卡发送查询，可能需要和 macOS 类似的按域名设置解析服务器。
- Windows 版 sing-box 运行 TUN 所需的 wintun 驱动是否已包含在 release 里。
