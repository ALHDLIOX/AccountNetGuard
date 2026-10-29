# AccountNetGuard

中文 | [English](README.en.md)

AccountNetGuard 给开着 Clash TUN 上网的 Mac 加一道断网保护：Clash TUN 不正常时整台 Mac 马上断网，只放行本机、局域网和 Tailscale，流量不会绕开代理直连出去。

它是一个由 launchd 运行的守护进程，只用系统自带的 PF 和 `/usr/bin/python3`，不需要装别的软件。Clash TUN 正常时它什么都不拦。支持用 mihomo 内核的 Clash 客户端，内核和 TUN 网卡都能自动识别。

## 先记下紧急放行命令

装之前先把这条命令存好。断网以后运行它，马上恢复上网，重启后也保持停用：

```sh
sudo /usr/bin/python3 -I "/Library/Application Support/AccountNetGuard2/accountnetguard.py" disable
```

要恢复保护，把最后的 `disable` 换成 `enable`。`disable` 没能恢复上网时，按[马上恢复上网](docs/recovery.md#马上恢复上网)一节处理。

## 支持的环境

真机验证过的只有一套环境：macOS 26.6.2（25G83），Apple 芯片，Clash Party 2.0.4，Tailscale，系统自带的 `/usr/bin/python3`（3.9.6）。2.0.0 在这套环境上做过完整的真机验收，2.1.0 在同一台 Mac 上从 2.0.0 升级后，验收了自动识别、断网和恢复。验证记录见 [docs/verification.md](docs/verification.md)。

其他版本的 macOS 和 Intel 芯片的 Mac 理论上支持，未验证。

还要满足这几条：

- 用系统自带的 `/usr/bin/python3`，版本 3.9 或更新。新 Mac 第一次运行 `/usr/bin/python3` 时，如果还没装 Xcode 命令行工具（Command Line Tools），系统会弹窗提示安装。装好后再运行一次原来的命令。也可以先运行 `xcode-select --install` 装好。
- PF 的主规则集里要有 `anchor "com.apple/*" all`。系统默认的 `/etc/pf.conf` 里就有，安装器会检查。
- 安装、`disable` 和 `enable` 都要管理员权限（`sudo`）。

## 支持的客户端

用下面这些客户端时不用改配置。自动识别只看内核进程的文件名，内核装在别的目录也认得出。客户端名只用来在 `status` 和 `doctor` 里显示。

| 客户端 | 内核文件名 | `ps` 里显示的路径 | 依据 |
| --- | --- | --- | --- |
| Clash Party（1.8.5 及以前叫 Mihomo Party） | `mihomo`、`mihomo-alpha`、`mihomo-smart` | `/Applications/Clash Party.app/Contents/Resources/sidecar/<文件名>` | `mihomo` 真机验证过（2.0.4），另外两个看的是 2.0.4 的源码 |
| Clash Verge Rev | `verge-mihomo`、`verge-mihomo-alpha` | 2.5.4 起是 `/Library/Application Support/clash-verge-service/cores/<文件名>`，2.5.2 及以前是 `/Applications/Clash Verge.app/Contents/MacOS/<文件名>` | 源码（2.5.8 和它用的服务程序），没在真机上测过 |
| FlClash | `FlClashCore` | `/Applications/FlClash.app/Contents/MacOS/FlClashCore` | 源码（0.9.2），没在真机上测过 |
| ClashX Meta | `com.metacubex.ClashX.ProxyConfigHelper.meta` | `~/Library/Application Support/com.metacubex.ClashX.meta/.private_core/<文件名>`，alpha 内核没有 `.private_core` 这一层 | 源码（1.4.47），没在真机上测过 |
| Homebrew 的 mihomo | `mihomo` | 用 `brew services` 启动时是 `/opt/homebrew/opt/mihomo/bin/mihomo`，在终端里直接运行时只显示 `mihomo` | Homebrew 的 formula，没在真机上测过。Intel Mac 的 `/usr/local` 前缀是按 Homebrew 的惯例写的，待核实 |
| 手动安装的 mihomo | `mihomo`、`mihomo-alpha`、`mihomo-smart` | 任意位置 | 显示成 `manual install or unknown client` |

app 装在 `~/Applications` 里时也能标出客户端名，这种装法没有查过，待核实。

各客户端打开 TUN 的地方（界面文字取自各自源码里的简体中文翻译）：

- Clash Party：打开侧栏的“虚拟网卡”开关。第一次用要在虚拟网卡页面点“手动授权内核”。
- Clash Verge Rev：先在设置里安装服务（服务模式），再打开“虚拟网卡模式”。
- FlClash：打开“虚拟网卡”，按提示授权。
- ClashX Meta：按提示安装 helper，再在菜单栏菜单里勾选“Tun 模式”。
- Homebrew 的 mihomo：在 mihomo 的配置里打开 tun（`enable: true`），再用 root 运行，比如 `sudo brew services start mihomo`。

## 怎么识别 Clash TUN

守护进程每次检查这三项，全部满足才算 Clash TUN 正常：

1. 内核在运行：`ps -axww -o pid=,comm=` 里有文件名是上表之一的进程。客户端的 helper 进程不算。
2. 探测地址走 utun：`route -n get` 查探测地址（默认 `1.1.1.1` 和 `8.8.8.8`）的路由，都走同一个 utun 网卡。
3. 这个 utun 是 Clash 的 TUN 网卡：已启用，有 IPv4 地址，而且不是 Tailscale 的网卡。带 `100.64.0.0/10` 地址的 utun 算 Tailscale 的。

有一项不满足，或者检查时哪个命令出错、超时，都算 Clash TUN 不正常，马上断网。配置里写了内核路径或网卡名时，按写的值检查，写法见下面的“配置”。

## 快速开始

先在 Clash 客户端里打开 TUN，再按下面三步装。

1. 克隆仓库，运行只读预检：

   ```sh
   git clone https://github.com/ALHDLIOX/AccountNetGuard.git
   cd AccountNetGuard
   /usr/bin/python3 -I src/accountnetguard.py doctor --config config.example.json
   ```

   `doctor` 不加载规则，不改文件，也不发网络请求。有 `config.local.json` 时把 `--config` 换成它。看 `core` 和 `TUN interface` 两行认得对不对，`verdict` 那一行应该是 `Clash TUN ok, the daemon will flush rules and allow all traffic`。识别不到时，它会列出本机装了哪些客户端，以及去哪打开 TUN。

2. 安装：

   ```sh
   sudo /usr/bin/python3 -I install.py
   ```

   install.py 分 6 步：检查环境和规则语法，复制程序和启动项，拉取 Tailscale 服务器地址，写配置并启动守护进程，停掉 v1（没装过就跳过），打印状态。Clash TUN 不正常时它照样会装，装好就断网，所以先让 `doctor` 通过。

3. 确认装好了：

   ```sh
   /usr/bin/python3 -I "/Library/Application Support/AccountNetGuard2/accountnetguard.py" status
   ```

   应该看到 `mode: allow (Clash TUN ok)`。`core` 一行是正在用的客户端，`TUN interface` 一行是 Clash 的网卡。然后退出 Clash 试一次，`curl -m 5 https://1.1.1.1` 应该马上失败。重新打开 Clash 并开启 TUN，1 秒左右恢复。完整的验收步骤见 [docs/verification.md](docs/verification.md)。

## 断网时放行什么

断网时只放行这些出站流量：

- 本机回环 `lo0`。
- 局域网 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`169.254.0.0/16`。
- DHCP（UDP 68 到 67）。
- 组播和 IPv6 链路本地 `224.0.0.0/4`、`fe80::/10`、`ff00::/8`。IPv6 的 ULA（`fc00::/7`）不放行。
- Tailscale 的网卡、地址段和服务器，见下一节。

其余 IPv4 和 IPv6 出站一律 `block return`，ICMP 也算在内。TCP 连接会马上收到 RST，程序不用干等超时。

## Tailscale

断网时 Tailscale 照样能用，放行的是这些：

- Tailscale 网卡上的所有出站流量。Tailscale 的 utun 编号会变，守护进程每次检查都现找带 `100.64.0.0/10` 地址的 utun。
- 发往 `100.64.0.0/10` 和 `fd7a:115c:a1e0::/48` 的流量。
- Tailscale 的控制服务器和 DERP 中继。按目标地址放行，只放 TCP 80、443 和 UDP 3478。

服务器地址由守护进程在放行时拉取。DERP 地址来自 `https://login.tailscale.com/derpmap/default`，控制服务器的地址经 Cloudflare 的 DoH 解析。结果缓存在安装目录里，默认每 6 小时刷新一次。还没有缓存时，断网期间只放行前两项。

和其他设备之间的 WireGuard 直连不放行，断网期间 Tailscale 走 DERP 中继。没装 Tailscale 也能用。

## 日常使用

程序输出（日志、`status`、`doctor`、安装器）是英文。

查看状态不需要 root：

```sh
/usr/bin/python3 -I "/Library/Application Support/AccountNetGuard2/accountnetguard.py" status
sudo /usr/bin/tail -n 40 /private/var/log/AccountNetGuard2.log
```

程序的命令都这样运行，把最后的 `status` 换成下表里的命令：

| 命令 | 作用 | 要 sudo |
| --- | --- | --- |
| `status` | 当前模式和原因，识别出的内核和 TUN 网卡，Tailscale 网卡，缓存的服务器地址数，最近的错误 | 不要 |
| `status --json` | 输出原始状态 | 不要 |
| `doctor` | 只读预检。加 sudo 能多查 PF 状态、anchor 和 v1 | 不要 |
| `rules` | 打印现在断网会加载的规则 | 不要 |
| `disable` | 清空规则并保持停用，重启后仍然有效 | 要 |
| `enable` | 删除停用标记，2 秒内恢复检测 | 要 |
| `refresh` | 马上刷新 Tailscale 服务器地址 | 要 |

要临时全放行，比如酒店 Wi-Fi 要先在网页上登录，就运行 `disable`，用完再运行 `enable`。程序、配置、日志等文件的位置见[文件位置](docs/recovery.md#文件位置)。

## 配置

一般不用改。要改的话，把要改的字段写进仓库根目录的 `config.local.json`，再运行一次 install.py。安装器用 `config.example.json` 打底，`config.local.json` 里写了的字段覆盖它。`config.local.json` 不进 git，也可以用 `--config` 指定别的文件。

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `version` | `2` | 配置格式版本，v1 的配置不能用 |
| `tun_interface` | `"auto"` | Clash 的 TUN 网卡。`"auto"` 是自动识别，也可以写固定的网卡名，比如 `"utun1500"` |
| `mihomo_path` | `"auto"` | 内核。`"auto"` 或 `""` 是按文件名自动识别。也可以写一个绝对路径，或者 1 到 16 个绝对路径组成的列表，要和 `ps` 显示的完全一样 |
| `probe_addresses` | `["1.1.1.1", "8.8.8.8"]` | 1 到 8 个公网 IPv4，到它们的路由都走 TUN 网卡才算正常 |
| `tailscale_refresh_hours` | `6` | 多久刷新一次 Tailscale 服务器地址，1 到 168 |

写固定值的例子（Clash Party）：

```json
{
  "tun_interface": "utun1500",
  "mihomo_path": "/Applications/Clash Party.app/Contents/Resources/sidecar/mihomo"
}
```

这两个值要在开着 TUN 时查。运行 `ps -axww -o pid=,comm=`，找到内核那一行。运行 `route -n get 1.1.1.1`，看 `interface` 那一行。写固定网卡名时，客户端里也要把网卡名固定成同一个，Clash Party 在虚拟网卡页面的“Tun 网卡名称”里改。

这两种情况建议写固定的 `tun_interface`：同时在用别的 VPN，或者 Clash TUN 的地址在 `100.64.0.0/10` 里。原因见“已知限制”。

装好后的配置在 `/Library/Application Support/AccountNetGuard2/config.json`，守护进程每 30 秒重读一次。配置无效时按 Clash TUN 不正常处理，会断网，`status` 里能看到原因。每次运行 install.py 都会重写这个文件，所以改配置要改 `config.local.json`。

## 升级

在仓库目录里拉取新代码，再运行一次 install.py：

```sh
git pull
sudo /usr/bin/python3 -I install.py
```

install.py 会先停掉正在运行的守护进程，再写配置、启动新的。这中间断网规则保持原样。

已安装的配置和新配置不一样时，第 1 步会逐项列出来。从 2.0 升级时会看到 `tun_interface` 和 `mihomo_path` 从原来的固定值变成 `"auto"`。要沿用原来的值，把它们写进 `config.local.json`，再运行一次 install.py。新配置识别不到 Clash TUN、已安装的配置却可以时，安装器在第 1 步停下，什么都不改。

## 卸载

```sh
sudo /usr/bin/python3 -I uninstall.py
```

卸载会停掉守护进程，清空规则，释放 PF 引用，把启动项移进安装目录的 `archive/`。安装目录 `/Library/Application Support/AccountNetGuard2/` 和日志 `/private/var/log/AccountNetGuard2.log` 都留着，确认不再需要后可以手动删除。卸载不会恢复 v1，要回到 v1 见[回滚到 v1](docs/recovery.md#回滚到-v1)。

## 已知限制

- 只管出站。从外面连进来的连接不拦，但断网时发往公网地址的回包也会被拦。
- Clash TUN 正常时 anchor 是空的。这时绑定物理网卡直连的程序、Clash 没接管的 IPv6，都不拦。
- 自动识别分不清 Clash 的 TUN 和别的 VPN。Clash 没开 TUN（比如只开了系统代理），而别的 VPN 占了默认路由时，会被当成 Clash TUN 正常，不断网。同时用别的 VPN 时，把 `tun_interface` 写成固定的网卡名。
- Clash TUN 的地址在 `100.64.0.0/10` 里时，自动识别会把它当成 Tailscale 的网卡，一直断网。这时也把 `tun_interface` 写成固定的网卡名。
- 检测看的是 `ps` 显示的启动命令，别的程序可以用同样的文件名或路径冒充内核。
- 内核卡死但进程还在、TUN 网卡和路由都正常时，检测不出来。这时流量进了 TUN 出不去，也不会直连出去。
- 断网时发给局域网路由器的 DNS 查询照样放行，路由器转发出去会暴露查询的域名。
- 用了 Tailscale 出口节点时，所有流量都走 Tailscale 网卡，会被放行。
- 自建 DERP 用了 80、443、3478 以外的端口时，断网期间连不上。
- PF 里别的规则建立的连接状态可能绕过断网规则（待核实）。
- 开机到守护进程启动之间没有保护。
- 守护进程用 `/usr/bin/python3` 运行。卸掉 Xcode 命令行工具后它起不来，重启以后就没有保护。
- 要在网页上登录的 Wi-Fi，需要先 `disable`。
- 守护进程运行时，单独用 `pfctl -F` 清规则或者用 `pfctl -d` 关 PF，最多 30 秒就会被改回来。要放行就用 `disable`。

## 工作原理

守护进程由 launchd 以 root 运行，标签是 `org.accountnetguard2.daemon`。Clash TUN 正常时，它清空自己的 PF anchor `com.apple/010.accountnetguard2`。检查不通过，或者检查本身出错、配置读不了，它就往这个 anchor 加载断网规则。

检查靠事件触发：路由表或网卡有变化时由路由 socket 通知，内核进程退出时由 kqueue 通知。另外每 2 秒兜底查一次，目标是 1 秒内断网。TUN 恢复后要连续正常 0.8 秒才放行。60 秒内放行超过 6 次就先保持断网，防止来回切换。每 30 秒核对一次 anchor 和 PF 的状态，被改掉就改回来。

只有手动 `disable` 能解除断网。守护进程退出或被杀时，规则留在 PF 里继续生效，launchd 会很快把它重新拉起来。重启后守护进程随系统启动，Clash 还没起来就先断网。

规则只按网卡、目标地址和端口放行，从不按用户或组匹配。v1 的规则按用户匹配（`user 501`）再加 `no state`。2026-10-29 作者的 Mac 卡死，内核的网卡收包线程和 mihomo 的收发线程互相锁死，高度怀疑就是这种规则让每个出站包都去查连接表的锁。

## 和 v1 的关系

v1 只拦一个登录账户的流量，规则里写这个账户的 UID，Clash TUN 正常时也拦这个账户绕开 TUN 的直连。名字里的 Account 就是这么来的。v2 在 Clash TUN 不正常时拦整台 Mac 的出站流量，IPv4、IPv6、ICMP 都算，哪个用户发的都一样。Clash TUN 正常时 v2 什么都不拦。

v2 用新的安装目录、launchd 标签和 PF anchor，可以直接装在 v1 上。install.py 先启动 v2，确认断网规则生效后，再停掉 v1、清空 v1 的 anchor。具体步骤和装完怎么检查，见[从 v1 迁移](docs/recovery.md#从-v1-迁移)。

## 开发

源码只用 Python 标准库，兼容 `/usr/bin/python3`（3.9）。测试不需要 root，不改 PF 和 launchd：

```sh
python3 -B -m unittest discover -s tests -v
/usr/bin/python3 -B -m unittest discover -s tests -v
```

测试会用 `pfctl -n` 检查规则语法（只解析，不加载），会打开路由 socket 和 kqueue，会跑几个很快退出的子进程。别的系统命令都由 `tests/support.py` 里的 `FakeSystem` 模拟。

| 文件 | 内容 |
| --- | --- |
| `src/accountnetguard.py` | 守护进程和命令行：识别、规则生成、PF 引用、Tailscale 地址、事件循环 |
| `install.py` | 安装、升级、从 v1 迁移 |
| `uninstall.py` | 卸载 |
| `config.example.json` | 默认配置 |
| `tests/` | 测试 |
| `docs/` | [恢复与迁移](docs/recovery.md)、[验收和测试记录](docs/verification.md) |

## 许可

MIT，见 [LICENSE](LICENSE)。
