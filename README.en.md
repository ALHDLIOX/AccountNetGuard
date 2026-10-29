# AccountNetGuard

[中文](README.md) | English

AccountNetGuard is a kill switch for Macs that use Clash in TUN mode: when Clash TUN is not working, it cuts the whole Mac off the network except localhost, the LAN and Tailscale, so traffic cannot leak around the proxy.

It is a daemon run by launchd. It only uses the built-in PF firewall and `/usr/bin/python3`, so there is nothing else to install. It blocks nothing while Clash TUN is working. It supports Clash clients built on the mihomo core and detects the core and the TUN interface automatically.

The program prints its messages in Chinese. The documents under `docs/` are in Chinese too.

## Save the emergency command first

Save this command before you install. If you lose network access, run it to get back online right away. It stays disabled across reboots:

```sh
sudo /usr/bin/python3 -I "/Library/Application Support/AccountNetGuard2/accountnetguard.py" disable
```

To turn protection back on, run the same command with `enable` instead of `disable`. If `disable` does not bring the network back, follow the "马上恢复上网" (restore network now) section of [docs/recovery.md](docs/recovery.md#马上恢复上网).

## Supported environment

Only one setup has been verified on a real machine: macOS 26.6.2 (25G83) on Apple silicon, Clash Party 2.0.4, Tailscale, and the system `/usr/bin/python3` (3.9.6). Version 2.0.0 passed a full real-machine acceptance test on this setup. Version 2.1.0 was upgraded from 2.0.0 on the same Mac, and auto-detection, blocking and recovery were tested there. See [docs/verification.md](docs/verification.md) for the records.

Other macOS versions and Intel Macs should work in theory but are not verified.

You also need:

- The system `/usr/bin/python3`, version 3.9 or later. On a new Mac, the first run of `/usr/bin/python3` asks you to install the Xcode Command Line Tools if they are missing. Install them, then run the same command again. You can also install them beforehand with `xcode-select --install`.
- The main PF ruleset must contain `anchor "com.apple/*" all`. The default `/etc/pf.conf` has it, and the installer checks for it.
- Administrator rights (`sudo`) for installing, `disable` and `enable`.

## Supported clients

These clients work without any configuration. Auto-detection only looks at the file name of the core process, so it also finds a core installed somewhere else. The client name is only shown in `status` and `doctor`.

| Client | Core file name | Path shown by `ps` | Source |
| --- | --- | --- | --- |
| Clash Party (named Mihomo Party up to 1.8.5) | `mihomo`, `mihomo-alpha`, `mihomo-smart` | `/Applications/Clash Party.app/Contents/Resources/sidecar/<file name>` | `mihomo` verified on a real machine (2.0.4), the other two taken from the 2.0.4 source |
| Clash Verge Rev | `verge-mihomo`, `verge-mihomo-alpha` | From 2.5.4: `/Library/Application Support/clash-verge-service/cores/<file name>`. Up to 2.5.2: `/Applications/Clash Verge.app/Contents/MacOS/<file name>` | Source (2.5.8 and the service it uses), not tested on a real machine |
| FlClash | `FlClashCore` | `/Applications/FlClash.app/Contents/MacOS/FlClashCore` | Source (0.9.2), not tested on a real machine |
| ClashX Meta | `com.metacubex.ClashX.ProxyConfigHelper.meta` | `~/Library/Application Support/com.metacubex.ClashX.meta/.private_core/<file name>`. The alpha core sits one level up, outside `.private_core` | Source (1.4.47), not tested on a real machine |
| Homebrew mihomo | `mihomo` | `/opt/homebrew/opt/mihomo/bin/mihomo` when started by `brew services`, just `mihomo` when run directly in a terminal | Homebrew formula, not tested on a real machine. The `/usr/local` prefix for Intel Macs follows Homebrew's convention and is unverified |
| Manually installed mihomo | `mihomo`, `mihomo-alpha`, `mihomo-smart` | Anywhere | Shown as `manual install or unknown client` |

Apps installed in `~/Applications` also get their client name. That layout has not been checked (unverified).

Where to turn on TUN in each client:

- Clash Party: turn on the TUN switch in the sidebar. The first time, click "Authorize Core" on the TUN page.
- Clash Verge Rev: install the service (service mode) in Settings first, then turn on TUN mode.
- FlClash: turn on TUN and grant permission when asked.
- ClashX Meta: install the helper when asked, then tick "Tun mode" in the menu bar menu.
- Homebrew mihomo: enable tun in the mihomo config (`enable: true`) and run it as root, for example with `sudo brew services start mihomo`.

## How Clash TUN is detected

On every check the daemon tests three things. Clash TUN counts as working only when all three hold:

1. The core is running: `ps -axww -o pid=,comm=` lists a process whose file name is in the table above. Client helper processes do not count.
2. The probe addresses go through a utun: `route -n get` for each probe address (`1.1.1.1` and `8.8.8.8` by default) returns the same utun interface.
3. That utun is Clash's TUN interface: it is up, has an IPv4 address and is not Tailscale's interface. A utun with an address in `100.64.0.0/10` counts as Tailscale's.

If any of them fails, or a command errors out or times out, Clash TUN counts as not working and the Mac is blocked at once. When the config names a core path or an interface, the daemon checks those values instead. See "Configuration" below.

## Quick start

Turn on TUN in your Clash client, then follow these three steps.

1. Clone the repository and run the read-only check:

   ```sh
   git clone https://github.com/ALHDLIOX/AccountNetGuard.git
   cd AccountNetGuard
   /usr/bin/python3 -I src/accountnetguard.py doctor --config config.example.json
   ```

   `doctor` loads no rules, changes no files and sends no network requests. If you have a `config.local.json`, pass it to `--config` instead. Check that the `core` and `TUN interface` lines are right. The `verdict` line should say `Clash TUN ok, the daemon will flush rules and allow all traffic`. If nothing is detected, it lists the clients installed on this Mac and where to turn on TUN.

2. Install:

   ```sh
   sudo /usr/bin/python3 -I install.py
   ```

   install.py runs six steps: check the environment and the rule syntax, copy the program and the launchd job, fetch Tailscale server addresses, write the config and start the daemon, stop v1 (skipped if it was never installed), and print the status. It installs even when Clash TUN is not working, and then the Mac is blocked right away. So make `doctor` pass first.

3. Confirm the installation:

   ```sh
   /usr/bin/python3 -I "/Library/Application Support/AccountNetGuard2/accountnetguard.py" status
   ```

   It should show `mode: allow (Clash TUN ok)`. The `core` line should name your client, and the `TUN interface` line should name Clash's interface. Then quit Clash once to try it: `curl -m 5 https://1.1.1.1` should fail at once. Reopen Clash with TUN on, and the network comes back in about a second. For the full acceptance test, see [docs/verification.md](docs/verification.md).

## What is allowed while blocked

While blocked, only this outbound traffic is allowed:

- Loopback `lo0`.
- LAN `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`.
- DHCP (UDP 68 to 67).
- Multicast and IPv6 link-local `224.0.0.0/4`, `fe80::/10`, `ff00::/8`. IPv6 ULA (`fc00::/7`) is not allowed.
- Tailscale's interface, address ranges and servers, see the next section.

All other IPv4 and IPv6 outbound traffic, ICMP included, gets `block return`. TCP connections get an RST right away, so programs do not hang until a timeout.

## Tailscale

Tailscale keeps working while blocked. This is what is allowed:

- All outbound traffic on the Tailscale interface. Its utun number changes, so the daemon looks for the utun with a `100.64.0.0/10` address on every check.
- Traffic to `100.64.0.0/10` and `fd7a:115c:a1e0::/48`.
- Tailscale's control servers and DERP relays, by destination address, on TCP 80 and 443 and UDP 3478 only.

The daemon fetches the server addresses while in allow mode. DERP addresses come from `https://login.tailscale.com/derpmap/default`. Control server addresses are resolved through Cloudflare DoH. The result is cached in the install directory and refreshed every 6 hours by default. Without a cache, only the first two items are allowed while blocked.

Direct WireGuard connections to other devices are not allowed, so Tailscale goes through DERP relays while blocked. AccountNetGuard also works without Tailscale.

## Daily use

All program output (log, `status`, `doctor`, installer) is in English.

Checking the status needs no root:

```sh
/usr/bin/python3 -I "/Library/Application Support/AccountNetGuard2/accountnetguard.py" status
sudo /usr/bin/tail -n 40 /private/var/log/AccountNetGuard2.log
```

All commands run the same way. Replace `status` at the end with one from this table:

| Command | What it does | Needs sudo |
| --- | --- | --- |
| `status` | Current mode and reason, detected core and TUN interface, Tailscale interfaces, number of cached server addresses, latest error | No |
| `status --json` | Prints the raw status | No |
| `doctor` | Read-only check. With sudo it also checks PF, the anchor and v1 | No |
| `rules` | Prints the rules that would be loaded if the Mac were blocked now | No |
| `disable` | Clears the rules and stays disabled, also after a reboot | Yes |
| `enable` | Removes the disable marker. Checks resume within 2 seconds | Yes |
| `refresh` | Refreshes the Tailscale server addresses now | Yes |

To allow everything for a while, for example to sign in to a hotel Wi-Fi portal, run `disable`, then `enable` when you are done. For file locations, see the "文件位置" (file locations) section of [docs/recovery.md](docs/recovery.md#文件位置).

## Configuration

Usually nothing needs changing. To change a field, put it in `config.local.json` in the repository root and run install.py again. The installer starts from `config.example.json`, and the fields in `config.local.json` override it. `config.local.json` is ignored by git. You can also pass another file with `--config`.

| Field | Default | Meaning |
| --- | --- | --- |
| `version` | `2` | Config format version. v1 configs do not work |
| `tun_interface` | `"auto"` | Clash's TUN interface. `"auto"` detects it. You can also give a fixed name such as `"utun1500"` |
| `mihomo_path` | `"auto"` | The core. `"auto"` or `""` detects it by file name. You can also give one absolute path, or a list of 1 to 16 absolute paths, exactly as `ps` shows them |
| `probe_addresses` | `["1.1.1.1", "8.8.8.8"]` | 1 to 8 public IPv4 addresses. Routes to all of them must go through the TUN interface |
| `tailscale_refresh_hours` | `6` | How often to refresh the Tailscale server addresses, 1 to 168 |

Example with fixed values (Clash Party):

```json
{
  "tun_interface": "utun1500",
  "mihomo_path": "/Applications/Clash Party.app/Contents/Resources/sidecar/mihomo"
}
```

Look these values up while TUN is on. Run `ps -axww -o pid=,comm=` and find the core's line. Run `route -n get 1.1.1.1` and read the `interface` line. When you fix the interface name here, fix the same name in the client too. In Clash Party it is "Tun 网卡名称" (TUN interface name) on the TUN page.

Use a fixed `tun_interface` in two cases: you also use another VPN, or Clash TUN's address is in `100.64.0.0/10`. See "Known limitations" for why.

The installed config is `/Library/Application Support/AccountNetGuard2/config.json`, and the daemon rereads it every 30 seconds. An invalid config counts as Clash TUN not working, so the Mac is blocked, and `status` shows why. install.py rewrites this file on every run, so make your changes in `config.local.json`.

## Upgrade

Pull the new code in the repository directory and run install.py again:

```sh
git pull
sudo /usr/bin/python3 -I install.py
```

install.py stops the running daemon first, then writes the config and starts the new one. The block rules stay as they are in between.

If the installed config differs from the new one, step 1 lists each change. When upgrading from 2.0 you will see `tun_interface` and `mihomo_path` change from fixed values to `"auto"`. To keep the old values, put them in `config.local.json` and run install.py again. If the new config cannot detect Clash TUN but the installed one can, the installer stops at step 1 and changes nothing.

## Uninstall

```sh
sudo /usr/bin/python3 -I uninstall.py
```

Uninstalling stops the daemon, clears the rules, releases the PF reference and moves the launchd job into `archive/` in the install directory. The install directory `/Library/Application Support/AccountNetGuard2/` and the log `/private/var/log/AccountNetGuard2.log` stay. Delete them by hand once you no longer need them. Uninstalling does not bring v1 back. To go back to v1, see the "回滚到 v1" (roll back to v1) section of [docs/recovery.md](docs/recovery.md#回滚到-v1).

## Known limitations

- Outbound only. Incoming connections are not blocked, but while blocked, replies to public addresses are blocked too.
- The anchor is empty while Clash TUN is working. Programs bound to the physical interface and IPv6 that Clash does not take over are not blocked then.
- Auto-detection cannot tell Clash's TUN from another VPN. If Clash runs without TUN (for example with only the system proxy) while another VPN holds the default route, this counts as Clash TUN working and nothing is blocked. If you use another VPN, set `tun_interface` to a fixed name.
- If Clash TUN's address is in `100.64.0.0/10`, auto-detection takes it for Tailscale's interface and keeps the Mac blocked. Set `tun_interface` to a fixed name in that case too.
- Detection relies on the command shown by `ps`. Another program can pose as the core with the same file name or path.
- A hung core whose process is still alive, with the TUN interface and routes intact, goes unnoticed. Traffic then enters the TUN and goes nowhere. It does not leak directly either.
- While blocked, DNS queries to the LAN router are still allowed. The router forwards them and exposes the queried names.
- With a Tailscale exit node, all traffic goes through the Tailscale interface and is allowed.
- A self-hosted DERP on ports other than 80, 443 and 3478 is unreachable while blocked.
- Connection states created by other PF rules may bypass the block rules (unverified).
- There is no protection between boot and daemon start.
- The daemon runs on `/usr/bin/python3`. If the Xcode Command Line Tools are removed, it cannot start, and after a reboot there is no protection.
- Wi-Fi networks with a sign-in page need `disable` first.
- While the daemon runs, flushing the rules with `pfctl -F` or turning PF off with `pfctl -d` gets undone within 30 seconds. Use `disable` to allow traffic.

## How it works

launchd runs the daemon as root under the label `org.accountnetguard2.daemon`. While Clash TUN is working, the daemon keeps its PF anchor `com.apple/010.accountnetguard2` empty. When a check fails, the check itself errors out, or the config cannot be read, it loads the block rules into that anchor.

Checks are event-driven. The route socket reports route table and interface changes, and kqueue reports when the core process exits. A fallback check also runs every 2 seconds. The goal is to block within 1 second. After TUN recovers, it must stay healthy for 0.8 seconds before traffic is allowed. More than 6 allows within 60 seconds keep the Mac blocked to stop flapping. Every 30 seconds the daemon checks the anchor and the PF state and restores them if they were changed.

Only a manual `disable` lifts the block. If the daemon exits or is killed, the rules stay in PF, and launchd restarts it shortly. After a reboot the daemon starts with the system and blocks before Clash is up.

The rules allow traffic only by interface, destination address and port. They never match on user or group. v1 matched on the user (`user 501`) together with `no state`. On 2026-10-29 the author's Mac froze because the kernel's network receive thread and mihomo's send and receive threads deadlocked, and such rules are strongly suspected: they make every outbound packet take the connection table lock.

## Relation to v1

v1 only blocked one login account. Its rules named that account's UID, and it blocked that account's direct connections around TUN even while TUN was working. That is where the "Account" in the name comes from. v2 blocks all outbound traffic of the whole Mac when Clash TUN is not working: IPv4, IPv6 and ICMP, from any user. v2 blocks nothing while Clash TUN is working.

v2 uses a new install directory, launchd label and PF anchor, so it installs directly over v1. install.py starts v2 first. Once the block rules are confirmed in effect, it stops v1 and clears v1's anchor. For the steps and how to check afterwards, see the "从 v1 迁移" (migrating from v1) section of [docs/recovery.md](docs/recovery.md#从-v1-迁移).

## Development

The source uses only the Python standard library and is compatible with `/usr/bin/python3` (3.9). Tests need no root and do not touch PF or launchd:

```sh
python3 -B -m unittest discover -s tests -v
/usr/bin/python3 -B -m unittest discover -s tests -v
```

The tests check rule syntax with `pfctl -n` (parse only, nothing is loaded), open a route socket and a kqueue, and run a few short-lived subprocesses. All other system commands are simulated by `FakeSystem` in `tests/support.py`.

| File | Contents |
| --- | --- |
| `src/accountnetguard.py` | Daemon and CLI: detection, rule generation, PF references, Tailscale addresses, event loop |
| `install.py` | Install, upgrade, migration from v1 |
| `uninstall.py` | Uninstall |
| `config.example.json` | Default config |
| `tests/` | Tests |
| `docs/` | [Recovery and migration](docs/recovery.md), [acceptance test and records](docs/verification.md), both in Chinese |

## License

MIT, see [LICENSE](LICENSE).
