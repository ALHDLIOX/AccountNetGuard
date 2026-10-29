# 恢复与迁移

## 马上恢复上网

运行 `disable`：

```sh
sudo /usr/bin/python3 -I "/Library/Application Support/AccountNetGuard2/accountnetguard.py" disable
```

它先写停用标记，再清空 anchor，释放 v2 的 PF 引用，1 秒后再清一次。停用标记重启后仍然有效，守护进程看到它就不再加载规则。要恢复保护就运行同一个程序的 `enable`。

断网时 Tailscale 和局域网还能用。人不在电脑前，可以从 tailnet 或局域网里的另一台设备 ssh 进来运行 `disable`，前提是本机打开了远程登录。

`disable` 报 `not fully done`，或者守护进程行为不对，就先停掉守护进程再清规则：

```sh
sudo /bin/launchctl bootout system/org.accountnetguard2.daemon
sudo /sbin/pfctl -a com.apple/010.accountnetguard2 -F rules
```

守护进程停掉后规则不会自己消失，要靠第二条命令清空。守护进程还在运行时只清规则没用，它最多 30 秒就会重新加载。

上面都不行，最后可以关掉整个 PF：

```sh
sudo /sbin/pfctl -d
```

这会让其他用 PF 的软件一起失效。守护进程还在运行时会在 30 秒内重新打开 PF，所以要先 `bootout`。

`bootout` 之后要让守护进程重新运行，就再跑一次 install.py。启动项还在，重启也会把它带起来。

## 查看规则和日志

```sh
/usr/bin/python3 -I "/Library/Application Support/AccountNetGuard2/accountnetguard.py" status
sudo /usr/bin/python3 -I "/Library/Application Support/AccountNetGuard2/accountnetguard.py" doctor
sudo /sbin/pfctl -a com.apple/010.accountnetguard2 -sr
sudo /usr/bin/tail -n 40 /private/var/log/AccountNetGuard2.log
```

放行时 anchor 是空的，`pfctl -sr` 可能会报 `pfctl: DIOCGETRULES: Invalid argument`，这是 anchor 里没有规则时的正常输出。断网时最后两条规则是 `block return out quick inet all` 和 `block return out quick inet6 all`。`status` 里 `problem:` 开头的行是还没解决的问题，比如规则加载失败，或者 PF 主规则集里没有 `anchor "com.apple/*" all`。

`status` 里 `core` 和 `TUN interface` 两行是最近一次识别的结果。一直断网时先看这两行，再看 `mode:` 后面括号里的原因。识别不到时运行 `doctor`，它会列出装了哪些客户端、去哪打开 TUN。

## 从 v1 迁移

直接运行 install.py：

```sh
sudo /usr/bin/python3 -I install.py
```

v1 是 2.0 以前的版本，launchd 标签 `org.accountnetguard.daemon`，安装目录 `/Library/Application Support/AccountNetGuard/`，anchor `com.apple/002.account-uid-guard`。

安装器先启动 v2，确认断网规则生效后再处理 v1，中间不留没有保护的空档：

1. v1 的任务还在运行就 `bootout`。v1 的启动项从 `/Library/LaunchDaemons/` 移到 `/Library/Application Support/AccountNetGuard2/archive/`，重启后不会再启动。
2. 清空 v1 的 anchor `com.apple/002.account-uid-guard`。清之前把里面的规则打印出来。v1 的规则按用户匹配，留着有内核死锁的风险。
3. 释放 v1 申请的 PF 引用。几个条件都满足才释放：记录属于这次开机，v1 自己没释放过，PF 引用列表里还有它，它和 v2 自己的不是同一个。释放前先记进 `migration.json`，同一个值以后不会再释放第二次。条件不满足就留着不动，多一个引用只会让 PF 保持开启，重启后自然消失。

安装器不改 v1 的安装目录 `/Library/Application Support/AccountNetGuard/`、运行目录 `/private/var/run/AccountNetGuard/` 和日志，也不调用 v1 自己的恢复命令。

装完检查 v1 确实停了：

```sh
sudo /bin/launchctl print system/org.accountnetguard.daemon
sudo /sbin/pfctl -a com.apple/002.account-uid-guard -sr
```

第一条应该报找不到服务。第二条应该没有规则输出，或者只报 `pfctl: DIOCGETRULES: Invalid argument`，两种都说明 anchor 是空的。

install.py 最后报 `not done:` 时，v2 已经在运行。按提示手动处理，再重新运行 install.py：

- v1 的任务停不掉：运行 `sudo /bin/launchctl bootout system/org.accountnetguard.daemon`。
- v1 的 anchor 没清空：运行 `sudo /sbin/pfctl -a com.apple/002.account-uid-guard -F rules`。
- v1 的 PF 引用没处理完：可以不管，重启后就没了。

v2 用了一段时间没问题，可以手动删掉 v1 的安装目录 `/Library/Application Support/AccountNetGuard/` 和日志 `/private/var/log/AccountNetGuard.log`。v1 的运行目录 `/private/var/run/AccountNetGuard/` 重启后会被系统清掉（待核实）。归档里 v1 的启动项回滚时要用，确认不再回滚再删。

## 回滚到 v1

先卸载 v2，把归档的 v1 启动项放回去，然后重启电脑：

```sh
sudo /usr/bin/python3 -I uninstall.py
sudo /bin/mv "/Library/Application Support/AccountNetGuard2/archive/org.accountnetguard.daemon.plist" /Library/LaunchDaemons/
```

归档里已经有同名文件时，后归档的那个文件名后面会加上时间，比如 `org.accountnetguard.daemon.plist.20261029-101500`。移回去时要改回 `org.accountnetguard.daemon.plist`。

不要在同一次开机里直接 `launchctl bootstrap` v1。安装时已经释放了 v1 记下的 PF 引用，v1 的运行记录和 PF 的实际状态对不上，v1 可能判断出错（待核实）。重启后运行目录清空，v1 从头开始。

回滚会带回按用户匹配加 `no state` 的规则，也就是 2026-10-29 内核死锁的嫌疑对象。

## 文件位置

| 内容 | 位置 |
| --- | --- |
| 程序 | `/Library/Application Support/AccountNetGuard2/accountnetguard.py` |
| 配置 | `/Library/Application Support/AccountNetGuard2/config.json` |
| 停用标记 | `/Library/Application Support/AccountNetGuard2/disabled` |
| Tailscale 服务器地址缓存 | `/Library/Application Support/AccountNetGuard2/tailscale-cache.json` |
| 归档的启动项（v1 的和卸载时 v2 的） | `/Library/Application Support/AccountNetGuard2/archive/` |
| 释放过的 v1 PF 引用 | `/Library/Application Support/AccountNetGuard2/migration.json` |
| 启动项 | `/Library/LaunchDaemons/org.accountnetguard2.daemon.plist` |
| 状态 | `/private/var/run/AccountNetGuard2/status.json` |
| v2 的 PF 引用 | `/private/var/run/AccountNetGuard2/token.json` |
| 运行锁 | `/private/var/run/AccountNetGuard2/daemon.lock` |
| 日志 | `/private/var/log/AccountNetGuard2.log` |
| PF anchor | `com.apple/010.accountnetguard2` |
