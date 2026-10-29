"""测试公用：加载被测模块，模拟 ps、ifconfig、route、sysctl、pfctl 和 launchctl。

所有测试都不需要 root，也不碰真实的 PF 和 launchd。
"""
import importlib.util
import json
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[1]


def load(name, path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


guard = load('accountnetguard', BASE / 'src' / 'accountnetguard.py')

BOOT_TEXT = '{ sec = 1793258157, usec = 207225 } Thu Oct 29 00:15:57 2026'
BOOT_TIME = '1793258157.207225'
BOOT = 'D14E237B-939E-4400-849F-E5D7CDD8DA6F'
MIHOMO = '/Applications/Clash Party.app/Contents/Resources/sidecar/mihomo'
# 2.0 装好后的配置：写死网卡名和内核路径。升级后要照样能用。
V2_0_CONFIG = {'version': 2, 'tun_interface': 'utun1500', 'mihomo_path': MIHOMO,
               'probe_addresses': ['1.1.1.1', '8.8.8.8'], 'tailscale_refresh_hours': 6}
MAIN_RULES = 'scrub-anchor "com.apple/*" all fragment reassemble\nanchor "com.apple/*" all\n'
ALTQ = 'No ALTQ support in kernel\nALTQ related functions disabled\n'

ROUTE_TEXT = '''   route to: {address}
destination: {address}
    gateway: 198.18.0.1
  interface: {interface}
      flags: <UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE,IFREF>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
'''

LO0 = '''lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\toptions=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
'''
EN0 = '''en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 02:00:00:00:00:01
\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
\tstatus: active
'''
TAILSCALE = '''{name}: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280
\tinet6 fe80::a:b:c:d%{name} prefixlen 64 scopeid 0x12
\tinet 100.64.10.20 --> 100.64.10.20 netmask 0xffffffff
\tinet6 fd7a:115c:a1e0::a:14 prefixlen 48
'''

DERPMAP = {
    'Regions': {
        '1': {'RegionID': 1, 'Nodes': [
            {'Name': '1f', 'RegionID': 1, 'HostName': 'derp1f.tailscale.com',
             'IPv4': '199.38.181.104', 'IPv6': '2607:f740:f::bc', 'CanPort80': True}]},
        '2': {'RegionID': 2, 'Nodes': [
            {'Name': '2d', 'RegionID': 2, 'HostName': 'derp2d.tailscale.com',
             'IPv4': '192.73.252.65', 'IPv6': '2607:f740:0:3f::287'},
            {'Name': '2x', 'RegionID': 2, 'HostName': 'derp2x.example.com'},
            {'Name': '2y', 'RegionID': 2, 'HostName': 'derp2y.example.com', 'IPv4': 'none',
             'IPv6': '2607:f740:0:3f::288'}]},
    }
}

DNS = {
    ('controlplane.tailscale.com', 'A'): [('controlplane.tailscale.com', 1, '192.200.0.111')],
    ('controlplane.tailscale.com', 'AAAA'): [('controlplane.tailscale.com', 28, '2606:b740:49::112')],
    ('login.tailscale.com', 'A'): [('login.tailscale.com', 5, 'login.edge.example.net.'),
                                   ('login.edge.example.net.', 1, '192.200.0.112')],
    ('login.tailscale.com', 'AAAA'): [],
    ('log.tailscale.com', 'A'): [('log.tailscale.com', 1, '199.165.136.101')],
    ('log.tailscale.com', 'AAAA'): [],
    ('derp2x.example.com', 'A'): [('derp2x.example.com', 1, '203.0.114.9')],
    ('derp2x.example.com', 'AAAA'): [],
}


def doh_answer(records, name, rtype):
    return {'Status': 0, 'Question': [{'name': name, 'type': 1 if rtype == 'A' else 28}],
            'Answer': [{'name': n, 'type': t, 'TTL': 60, 'data': d} for n, t, d in records]}


class FakeFetch:
    """模拟 derpmap 和 DoH。failing 里放 'derp' 或 'control' 让对应来源失败。"""

    def __init__(self, derpmap=None, dns=None):
        self.derpmap = DERPMAP if derpmap is None else derpmap
        self.dns = DNS if dns is None else dns
        self.failing = set()
        self.calls = []

    def __call__(self, url, headers=None):
        self.calls.append(url)
        if url == guard.DERPMAP_URL:
            if 'derp' in self.failing:
                raise OSError('derpmap fetch failed')
            return self.derpmap
        query = dict(part.split('=', 1) for part in url.split('?', 1)[1].split('&'))
        name, rtype = query['name'], query['type']
        if 'control' in self.failing and name in guard.CONTROL_HOSTS:
            raise OSError('DoH failed')
        return doh_answer(self.dns[(name, rtype)], name, rtype)


class FakeSystem:
    """一台假的 Mac：按 argv[0] 分派命令，记下每次调用。

    override 里按命令种类放 Result 或函数，用来模拟失败、超时。
    """

    def __init__(self):
        self.mihomo = True
        self.mihomo_pid = 881
        self.core = MIHOMO          # ps 里内核那一行显示的命令
        self.extra_ps = []          # 另外的 (pid, 命令)
        self.tun = 'utun1500'
        self.tun_exists = True
        self.tun_up = True
        self.tun_inet = True
        self.tun_address = '198.18.0.1'
        self.extra_ifconfig = ''    # 另外的网卡，比如别的 VPN
        self.route_via = 'utun1500'  # 网卡名，或者 {探测地址: 网卡名}
        self.tailscale = 'utun3'
        self.boot = BOOT
        self.boottime = BOOT_TEXT
        self.main = MAIN_RULES
        self.anchors = {}
        self.enabled = False
        self.tokens = []
        self.next_token = 18446744073709000000
        self.override = {}
        self.on_load = None
        self.loaded_labels = set()
        self.on_bootstrap = None
        self.calls = []

    # -- 查看

    def kinds(self):
        return [kind for kind, _ in self.calls]

    def count(self, kind):
        return self.kinds().count(kind)

    def rules(self, anchor=guard.ANCHOR):
        return '\n'.join(self.anchors.get(anchor, []))

    # -- 分派

    @staticmethod
    def kind(argv):
        prog = argv[0]
        if prog == guard.PS:
            return 'ps'
        if prog == guard.IFCONFIG:
            return 'ifconfig'
        if prog == guard.ROUTE:
            return 'route'
        if prog == guard.SYSCTL:
            return 'sysctl'
        if prog == guard.LAUNCHCTL:
            return 'launchctl-' + argv[1]
        if prog == guard.PFCTL:
            if '-n' in argv:
                return 'pf-check'
            if '-f' in argv:
                return 'pf-load'
            if '-F' in argv:
                return 'pf-flush'
            if '-sr' in argv:
                return 'pf-rules' if '-a' in argv else 'pf-main'
            if argv[1:] == ['-s', 'info']:
                return 'pf-info'
            if argv[1:] == ['-s', 'References']:
                return 'pf-refs'
            if '-E' in argv:
                return 'pf-enable'
            if '-X' in argv:
                return 'pf-release'
        return 'other'

    def __call__(self, argv, timeout=None, input=None, grace=None):
        argv = [str(a) for a in argv]
        kind = self.kind(argv)
        self.calls.append((kind, argv))
        if kind in self.override:
            value = self.override[kind]
            return value(argv, input) if callable(value) else value
        handler = getattr(self, 'do_' + kind.replace('-', '_'), None)
        if handler is None:
            return guard.Result(0, '', '')
        return handler(argv, input)

    # -- 检测命令

    def do_ps(self, argv, input):
        lines = ['    1 /sbin/launchd', '  517 /Library/PrivilegedHelperTools/party.mihomo.helper']
        if self.mihomo:
            lines.append('%5d %s' % (self.mihomo_pid, self.core))
        lines += ['%5d %s' % row for row in self.extra_ps]
        return guard.Result(0, '\n'.join(lines) + '\n', '')

    def do_ifconfig(self, argv, input):
        text = LO0 + EN0
        if self.tailscale:
            text += TAILSCALE.format(name=self.tailscale)
        if self.tun_exists:
            flags = '8051<UP,POINTOPOINT,RUNNING,MULTICAST>' if self.tun_up else '8010<POINTOPOINT,MULTICAST>'
            text += '%s: flags=%s mtu 1500\n' % (self.tun, flags)
            if self.tun_inet:
                text += '\tinet %s --> %s netmask 0xfffffffc\n' % (self.tun_address, self.tun_address)
        return guard.Result(0, text + self.extra_ifconfig, '')

    def do_route(self, argv, input):
        via = self.route_via.get(argv[-1], 'en0') if isinstance(self.route_via, dict) else self.route_via
        return guard.Result(0, ROUTE_TEXT.format(address=argv[-1], interface=via), '')

    def do_sysctl(self, argv, input):
        if argv[-1] == 'kern.boottime':
            return guard.Result(0, self.boottime + '\n', '')
        if argv[-1] == 'kern.bootsessionuuid':
            return guard.Result(0, self.boot + '\n', '')
        return guard.Result(1, '', 'sysctl: unknown oid %s\n' % argv[-1])

    # -- pfctl

    def anchor_of(self, argv):
        return argv[argv.index('-a') + 1]

    def do_pf_check(self, argv, input):
        return guard.Result(0, '', ALTQ)

    def do_pf_load(self, argv, input):
        if self.on_load:
            refused = self.on_load(input)
            if refused:
                return refused
        lines = [line for line in input.splitlines() if line.startswith(('pass', 'block'))]
        self.anchors[self.anchor_of(argv)] = lines
        return guard.Result(0, '', 'pfctl: Use of -f option, could result in flushing of rules\n'
                                   'present in the main ruleset added by the system at startup.\n'
                                   'See /etc/pf.conf for further details.\n')

    def do_pf_flush(self, argv, input):
        if argv[-1] == 'rules':
            self.anchors[self.anchor_of(argv)] = []
        return guard.Result(0, '', '')

    def do_pf_rules(self, argv, input):
        lines = self.anchors.get(self.anchor_of(argv), [])
        return guard.Result(0, ''.join(line + '\n' for line in lines), ALTQ)

    def do_pf_main(self, argv, input):
        return guard.Result(0, self.main, ALTQ)

    def do_pf_info(self, argv, input):
        state = 'Enabled' if self.enabled else 'Disabled'
        return guard.Result(0, 'Status: %s for 0 days 00:10:00           Debug: Urgent\n' % state, ALTQ)

    def do_pf_refs(self, argv, input):
        lines = ['TOKENS:', 'PID      Process Name                 TOKEN                     TIMESTAMP']
        lines += ['%-8d %-28s %-25s %s' % (4242, 'pfctl', token, '12 secs ago') for token in self.tokens]
        return guard.Result(0, '\n'.join(lines) + '\n', ALTQ)

    def do_pf_enable(self, argv, input):
        token = str(self.next_token)
        self.next_token += 1
        self.tokens.append(token)
        self.enabled = True
        return guard.Result(0, '', ALTQ + 'pf enabled\nToken : %s\n' % token)

    def do_pf_release(self, argv, input):
        token = argv[-1]
        if token not in self.tokens:
            return guard.Result(1, '', 'pfctl: DIOCSTOPREF: Invalid argument\n')
        self.tokens.remove(token)
        if not self.tokens:
            self.enabled = False
        return guard.Result(0, '', ALTQ + ('pf disabled\n' if not self.enabled else ''))

    # -- launchctl

    def do_launchctl_print(self, argv, input):
        label = argv[2].split('/', 1)[1]
        if label in self.loaded_labels:
            return guard.Result(0, '%s = {\n\tstate = running\n}\n' % argv[2], '')
        return guard.Result(113, '', 'Could not find service "%s" in domain for system\n' % label)

    def do_launchctl_bootout(self, argv, input):
        self.loaded_labels.discard(argv[2].split('/', 1)[1])
        return guard.Result(0, '', '')

    def do_launchctl_bootstrap(self, argv, input):
        self.loaded_labels.add(Path(argv[3]).stem)
        if self.on_bootstrap:
            self.on_bootstrap()
        return guard.Result(0, '', '')


def make_paths(base):
    base = Path(base)
    paths = guard.Paths(base / 'root', base / 'state', base / 'guard.log')
    paths.root.mkdir(parents=True)
    paths.state.mkdir()
    return paths


def write_config(paths, **fields):
    data = dict(guard.DEFAULTS)
    data.update(fields)
    paths.config.write_text(json.dumps(data))
    return data


def vpn_interface(name, address='10.8.0.2'):
    """别的 VPN 的 utun：已启用、有 IPv4，地址不在 100.64.0.0/10 里。"""
    return '%s: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400\n\tinet %s --> %s netmask 0xffffffff\n' % (
        name, address, address)


def sample_cache(now=1793260000.0):
    return {'version': 1, 'sources': {
        'derp': {'updated': now, 'addresses': ['192.73.252.65', '199.38.181.104', '2607:f740:f::bc']},
        'control': {'updated': now, 'addresses': ['192.200.0.111', '2606:b740:49::112']},
    }}
