# 验收

装好后在本机做完下面几步，才算确认它真的能断网。测试和 `pfctl -n` 只能说明规则能被解析，说明不了真的能断网。

## 准备

在本机终端操作，准备好[恢复命令](recovery.md#马上恢复上网)。记下路由器的局域网地址、一台局域网设备的地址，以及一台 Tailscale 设备的名字。Clash 客户端开着 TUN。

后面的命令都用这个变量指向装好的程序：

```sh
G="/Library/Application Support/AccountNetGuard2/accountnetguard.py"
```

## 1. 装好后的状态

```sh
/usr/bin/python3 -I "$G" status
sudo /usr/bin/python3 -I "$G" doctor
sudo /sbin/pfctl -a com.apple/010.accountnetguard2 -sr
```

`status` 应该显示 `mode: allow (Clash TUN ok)`。`core` 一行应该是正在用的客户端，`TUN interface` 一行应该是 Clash 的网卡。还要能找到 Tailscale 网卡，服务器地址数不是 0。把内核的 pid 和 TUN 网卡名记下来，后面要用。

`doctor` 最后一行应该是 `result   no failures`。anchor 里应该没有规则，`pfctl` 只打印 ALTQ 提示和 `pfctl: DIOCGETRULES: Invalid argument` 也算，那是 anchor 为空时的正常输出。

从 v1 迁移过来的，再按[从 v1 迁移](recovery.md#从-v1-迁移)里的两条命令确认 v1 停了。

## 2. 退出 Clash

先在另一个终端窗口运行这段脚本，第一行换成上面记下的 TUN 网卡名。它每 50 毫秒看一次这个网卡在不在、能不能连上 `1.1.1.1:443`，有变化就打印带毫秒的时间：

```sh
TUN=utun1500
/usr/bin/python3 -I - "$TUN" <<'EOF'
import socket, sys, time
tun = sys.argv[1]
last = None
while True:
    try:
        socket.if_nametoindex(tun)
        state = tun + ' 在'
    except OSError:
        state = tun + ' 不在'
    try:
        socket.create_connection(('1.1.1.1', 443), timeout=0.5).close()
        net = '能连'
    except OSError as exc:
        net = '连不上（%s）' % type(exc).__name__
    if (state, net) != last:
        t = time.time()
        print(time.strftime('%H:%M:%S', time.localtime(t)) + '.%03d' % (t % 1 * 1000), state, net, flush=True)
        last = (state, net)
    time.sleep(0.05)
EOF
```

然后彻底退出 Clash 客户端。运行 `ps -p <内核的 pid> -o comm=`，没有输出就说明内核也退出了。

脚本应该先打印网卡不在，1 秒内再打印“连不上（ConnectionRefusedError）”。中间如果有“能连”，那一段就是流量直连漏出去的时间，把它记下来。日志里应该有一行 `blocked:` 开头的记录，比如 `blocked: Clash core is not running (tailscale: utun4, 204 server addresses)`。

断网时逐项检查。下面的尖括号要换成自己的值，不要照抄：路由器地址看 `route -n get default` 里的 `gateway`，Tailscale 设备名看 `tailscale status`。

```sh
curl -m 5 -sS -o /dev/null https://1.1.1.1
ping -c 2 8.8.8.8
curl -6 -m 5 -sS -o /dev/null 'https://[2606:4700:4700::1111]'
ping -c 2 <路由器地址>
tailscale status
tailscale ping <Tailscale 设备名>
ssh <Tailscale 设备名>
```

前三条应该很快失败，第三条只在网络有 IPv6 时有意义。ping 路由器应该通。`tailscale status` 应该正常列出设备，`tailscale ping` 应该通，多半显示经过 DERP。ssh 到 Tailscale 设备应该能登录。再用局域网地址 ssh 到那台局域网设备，或者打开它的网页，也应该能连上。

找不到 `tailscale` 命令时，可以用 `/Applications/Tailscale.app/Contents/MacOS/Tailscale` 代替（待核实）。

## 3. 重新打开 Clash

打开 Clash 客户端并开启 TUN。脚本应该在网卡出现之后 1 秒左右打印“能连”。日志里应该有一行 `allowed: Clash TUN ok` 开头的记录，anchor 变空。

## 4. 断网时 Wi-Fi 重连

退出 Clash 保持断网，关掉 Wi-Fi 再打开：

```sh
networksetup -setairportpower en0 off
networksetup -setairportpower en0 on
for i in $(seq 1 30); do ipconfig getifaddr en0 && break; sleep 1; done
```

刚打开 Wi-Fi 时还没连上网络，所以最后一条最多等 30 秒，拿到地址就打印出来。应该能拿到地址，ping 路由器能通。Wi-Fi 网卡不是 `en0` 就换成实际的名字，`networksetup -listallhardwareports` 能查到。有条件的话换一个 Wi-Fi 网络再试一次。

## 5. 重启

让 Clash 客户端登录后自动启动并开启 TUN，然后重启电脑。登录后运行：

```sh
/usr/bin/python3 -I "$G" status
sudo /usr/bin/tail -n 20 /private/var/log/AccountNetGuard2.log
```

日志里应该能看到开机后守护进程启动、断网，等 Clash 起来以后放行。`status` 应该是放行。

## 6. 停用和恢复保护

```sh
sudo /usr/bin/python3 -I "$G" disable
```

退出 Clash，`curl -m 5 https://1.1.1.1` 应该能通，`status` 显示已停用。重启一次，应该还是已停用。然后运行：

```sh
sudo /usr/bin/python3 -I "$G" enable
```

2 秒内恢复检测，Clash 没开就会断网。

## 7. 断网时 Tailscale 重连

退出 Clash 保持断网，退出 Tailscale 再打开。`tailscale status` 应该重新列出设备，`tailscale netcheck` 应该能测出 DERP 延迟。这一步看的是控制服务器和 DERP 的地址有没有放行对。

## 测试环境与结果

### 2.0.0 真机验收（2026-10-29）

环境是 macOS 26.6.2（25G83），Apple 芯片，Clash Party 2.0.4，Tailscale，`/usr/bin/python3` 3.9.6。Clash Party 的 TUN 网卡固定为 `utun1500`，配置是 2.0 的写法，写死了网卡名和内核路径。测试机原来装着按用户拦截的早期版本，和 v1 用同一个 anchor。上面第 1 到 7 步都做了。

结果：

- 迁移：早期版本停掉，旧 anchor 里 16 条 `user = 501` 规则清空，旧启动项移进 `archive/`。
- 退出 Clash：网卡消失后 57 毫秒内连接就被拒，中间没有漏出去的连接。修复后又测两次，都在 60 毫秒内断网。
- 重开 Clash：网卡出现后约 1.1 秒放行，测了两次都一样。
- 断网时：公网 IPv4、IPv6 都连不上，ping 公网不通。`tailscale ping` 经 DERP 通，ssh 到 Tailscale 设备能登录，`tailscale netcheck` 测出了 DERP 延迟。
- 断网时关掉再打开 Wi-Fi，几秒内重新拿到地址。
- 断网时退出再打开 Tailscale，设备列表、DERP 和 ssh 都恢复了，守护进程也认回了 Tailscale 网卡。
- 重启：开机后先断网，Clash 起来后约 11 秒放行。修复后再测约 14 秒。重启后 Tailscale 网卡的编号变了，也认得出来。
- `disable` 后能直连，重启后仍是停用。`enable` 后马上断网，开 Clash 后放行。

真机上发现两个问题，已经修掉：

- 开机标识原来用 `kern.boottime`，开机后校时会让它变，每次 `disable` 再 `enable` 都多留一个 PF 引用。现在改用 `kern.bootsessionuuid`。修复后 `disable` 能释放 v2 的 PF 引用，`enable` 后回到 1 个。
- 开机那一阵 `ps` 在 2 秒内没跑完，被当成 TUN 不正常，误断网 3 秒。检测命令的超时改成 5 秒，修复后重启没再出现。

### 2.1.0

- 模拟测试：Homebrew 的 Python 3.15.0 和系统的 `/usr/bin/python3`（3.9.6）各跑了 241 项测试，全部通过。系统命令都是模拟的。
- 断网规则用 `pfctl -n` 检查过语法（只解析，不加载），包括 2000 个地址的表。生成的规则除了版本号注释，和 2.0.0 一样。
- 真机升级（2026-10-29，同一台测试机）：从 2.0.0 原地升级，配置从写死的网卡名和内核路径改成 `"auto"`。安装器先停掉旧守护进程再写配置，PF 引用还是原来那 1 个。
- 自动识别：认出了 Clash Party 的内核、`utun1500` 和 Tailscale 网卡，Clash 重开后内核的 pid 变了也认得出。
- 退出 Clash：网卡消失后 56 毫秒内连接就被拒，`status` 的原因是“mihomo 没在运行”（2.1.0 当时的中文输出，现在是 `Clash core is not running`），`doctor` 提示去 Clash Party 打开虚拟网卡。
- 断网时：`tailscale ping` 经 DERP 通，ssh 到 Tailscale 设备能登录。
- 重开 Clash：网卡出现后约 0.6 秒放行。
- 没重做的：第 4 步 Wi-Fi 重连、第 5 步重启、第 6 步停用和恢复、第 7 步 Tailscale 退出重开，这几项相关代码 2.1.0 没改。Clash Party 以外的客户端只按源码写了识别规则，没在真机上测过。
