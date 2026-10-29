#!/usr/bin/python3
"""AccountNetGuard v2：Clash TUN 不正常时整台 Mac 断网，只放行本机回环、局域网和 Tailscale。

只依赖 Python 标准库，兼容 /usr/bin/python3（3.9）。规则一律不按用户或组匹配。
用法见仓库里的 README.md，紧急关闭见 docs/recovery.md。
"""
import argparse
import collections
import fcntl
import glob
import ipaddress
import json
import os
from pathlib import Path
import posixpath
import queue
import re
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

VERSION = '2.1.0'
LABEL = 'org.accountnetguard2.daemon'
ROOT = Path('/Library/Application Support/AccountNetGuard2')
STATE = Path('/private/var/run/AccountNetGuard2')
LOG = Path('/private/var/log/AccountNetGuard2.log')
PLIST = Path('/Library/LaunchDaemons') / (LABEL + '.plist')
INSTALLED = ROOT / 'accountnetguard.py'
ANCHOR = 'com.apple/010.accountnetguard2'
TABLE = 'tailscale_infra'
MAIN_ANCHOR_RULE = 'anchor "com.apple/*" all'
BLOCK_PREFIX = 'block return out quick'

PYTHON = '/usr/bin/python3'
PFCTL = '/sbin/pfctl'
IFCONFIG = '/sbin/ifconfig'
ROUTE = '/sbin/route'
PS = '/bin/ps'
SYSCTL = '/usr/sbin/sysctl'
LAUNCHCTL = '/bin/launchctl'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'}

# v1（2.0 以前的版本）。安装目录、launchd 标签、anchor 和运行目录都和 v2 不同。
OLD_ROOT = Path('/Library/Application Support/AccountNetGuard')
OLD_STATE = Path('/private/var/run/AccountNetGuard')
OLD_LABELS = ('org.accountnetguard.daemon',)
OLD_ANCHOR = 'com.apple/002.account-uid-guard'

AUTO = 'auto'
DEFAULTS = {
    'version': 2,
    'tun_interface': AUTO,
    'mihomo_path': AUTO,
    'probe_addresses': ['1.1.1.1', '8.8.8.8'],
    'tailscale_refresh_hours': 6,
}

# 自动识别时认这些内核文件名。ps 显示的是启动命令（argv[0]），客户端用绝对路径启动内核，
# 手动在 shell 里启动时只有文件名，所以按文件名认，不看目录。
CORE_NAMES = frozenset((
    'mihomo', 'mihomo-alpha', 'mihomo-smart',            # Clash Party、Homebrew、手动安装
    'verge-mihomo', 'verge-mihomo-alpha',                # Clash Verge Rev
    'FlClashCore',                                       # FlClash
    'com.metacubex.ClashX.ProxyConfigHelper.meta',       # ClashX Meta
))
# 各客户端放内核的目录，只用来在 status 和 doctor 里标出客户端名。* 只匹配一段路径。
# 路径来源见 README 的“支持的客户端”。
APP_DIRS = (
    ('Clash Party', 'Clash Party.app/Contents/Resources/sidecar'),
    ('Clash Party', 'Mihomo Party.app/Contents/Resources/sidecar'),   # 1.8.6 以前叫 Mihomo Party
    ('Clash Verge Rev', 'Clash Verge.app/Contents/MacOS'),
    ('FlClash', 'FlClash.app/Contents/MacOS'),
)
CLIENT_DIRS = tuple((name, prefix + '/' + path) for name, path in APP_DIRS
                    for prefix in ('/Applications', '/Users/*/Applications')) + (
    ('Clash Verge Rev', '/Library/Application Support/clash-verge-service/cores'),
    ('ClashX Meta', '/Users/*/Library/Application Support/com.metacubex.ClashX.meta'),
    ('ClashX Meta', '/Users/*/Library/Application Support/com.metacubex.ClashX.meta/.private_core'),
    ('Homebrew', '/opt/homebrew/opt/mihomo/bin'),
    ('Homebrew', '/opt/homebrew/bin'),
    ('Homebrew', '/opt/homebrew/Cellar/mihomo/*/bin'),
    ('Homebrew', '/usr/local/opt/mihomo/bin'),
    ('Homebrew', '/usr/local/Cellar/mihomo/*/bin'),
)
UNKNOWN_CLIENT = 'manual install or unknown client'
CONFIGURED_CLIENT = 'path from config'
MAX_CORE_PATHS = 16
MAX_CORES = 8

LAN_V4 = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '224.0.0.0/4')
LAN_V6 = ('fe80::/10', 'ff00::/8')
TAILNET_V4 = '100.64.0.0/10'
TAILNET_V6 = 'fd7a:115c:a1e0::/48'
DERPMAP_URL = 'https://login.tailscale.com/derpmap/default'
DOH_URL = 'https://cloudflare-dns.com/dns-query'
CONTROL_HOSTS = ('controlplane.tailscale.com', 'login.tailscale.com', 'log.tailscale.com')
SOURCES = ('derp', 'control')
MAX_ADDRESSES = 2000
MAX_HOSTNAMES = 50
MAX_TAILSCALE_INTERFACES = 4

# ipaddress 的 is_global 在 3.9 和新版之间判定不完全一样，这里另外写死一份非公网地址段。
NOT_PUBLIC = tuple(ipaddress.ip_network(n) for n in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
    '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64',
    '2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20', 'fc00::/7', 'fe80::/10',
    'fec0::/10', 'ff00::/8'))

POLL = 2.0              # 兜底轮询间隔
COALESCE = 0.1          # 路由消息合并窗口
ROUTE_GAP = 0.25        # 路由消息触发的两次检查之间的最短间隔
DEBOUNCE = 0.8          # TUN 恢复后要连续正常这么久才放行
RECONCILE = 30.0        # 核对 anchor 和 PF 状态的间隔
ALLOW_BURST = 6         # ALLOW_WINDOW 秒内最多放行几次，超过就先保持断网
ALLOW_WINDOW = 60.0
ERROR_INTERVAL = 60.0   # 同一类错误在日志里最多每分钟记一次
LOG_LIMIT = 4 * 1024 * 1024
TIMEOUT = 5.0           # pfctl 等命令的超时
DETECT_TIMEOUT = 5.0    # ps、ifconfig、route 的超时。开机那一阵负载高，2 秒不够 ps 跑完
GRACE = 1.0             # 超时 kill 后再等多久
REFRESH_RETRY = 1800.0  # 刷新 Tailscale 地址失败后多久再试
STATUS_STALE = 90.0

UTUN = re.compile(r'utun\d{1,5}')
TOKEN = re.compile(r'Token\s*:\s*(\d+)')
HOSTNAME = re.compile(r'(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')
IFACE_LINE = re.compile(r'([A-Za-z0-9_.-]+): flags=[0-9a-fA-F]+<([^>]*)>')

# 路由 socket 消息（XNU net/route.h）
RTM_ADD, RTM_DELETE, RTM_CHANGE, RTM_REDIRECT = 0x1, 0x2, 0x3, 0x6
RTM_NEWADDR, RTM_DELADDR, RTM_IFINFO, RTM_IFINFO2 = 0xc, 0xd, 0xe, 0x12
RTF_LLINFO, RTF_WASCLONED = 0x400, 0x20000
ROUTE_CHANGES = (RTM_ADD, RTM_DELETE, RTM_CHANGE, RTM_REDIRECT)
LINK_CHANGES = (RTM_NEWADDR, RTM_DELADDR, RTM_IFINFO, RTM_IFINFO2)

# 有这几类问题时，断网规则可能没生效
PROTECTION_PROBLEMS = frozenset(('apply', 'main', 'state', 'token'))
MODE_TEXT = {'allow': 'allow', 'block': 'block', 'disabled': 'disabled', 'unknown': 'unknown'}
RELEASE_TEXT = {
    'released': 'released',
    'none': 'no token file, skipped',
    'gone': 'token no longer listed by PF, skipped',
    'stale': 'token is from a previous boot, not released',
    'invalid': 'token file is invalid, not released',
    'failed': 'release failed, token file kept',
}


class GuardError(Exception):
    pass


class ConfigError(GuardError):
    pass


class DetectError(GuardError):
    pass


# ---------------------------------------------------------------- 外部命令

class Result:
    def __init__(self, code, out='', err='', timed_out=False):
        self.code, self.out, self.err, self.timed_out = code, out, err, timed_out

    @property
    def ok(self):
        return self.code == 0

    def brief(self):
        lines = [line.strip() for line in (self.err or self.out).splitlines() if line.strip()]
        # pfctl 每次 -f 都会打一段固定警告，没用，去掉。
        lines = [line for line in lines
                 if not line.startswith(('pfctl: Use of -f', 'present in the main', 'See /etc/pf.conf'))]
        text = ' / '.join(lines[-2:])[:300]
        if self.timed_out:
            return 'timed out' + (': ' + text if text else '')
        return 'exit %s' % self.code + (': ' + text if text else '')


_ABANDONED = []


def _decode(data):
    return data.decode('utf-8', 'replace') if data else ''


def _reap():
    for proc in list(_ABANDONED):
        try:
            done = proc.poll() is not None
        except Exception:
            done = True
        if done:
            _ABANDONED.remove(proc)


def run(argv, timeout=TIMEOUT, input=None, grace=GRACE):
    """运行外部命令，最多等 timeout + grace 秒。

    超时先 kill，再等 grace 秒；还退不出（比如卡在内核里）就放弃这个子进程，
    返回超时结果，调用方照常往下走。绝不无限期等待。
    """
    _reap()
    data = input.encode('utf-8') if isinstance(input, str) else input
    try:
        proc = subprocess.Popen([str(a) for a in argv],
                                stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                close_fds=True, env=ENV, cwd='/')
    except OSError as exc:
        return Result(None, '', 'cannot run %s: %s' % (argv[0], exc))
    try:
        out, err = proc.communicate(data, timeout=timeout)
        return Result(proc.returncode, _decode(out), _decode(err))
    except subprocess.TimeoutExpired:
        pass
    try:
        proc.kill()
    except OSError:
        pass
    try:
        out, err = proc.communicate(timeout=grace)
        return Result(None, _decode(out), _decode(err), timed_out=True)
    except subprocess.TimeoutExpired:
        pass
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        if stream:
            try:
                stream.close()
            except OSError:
                pass
    _ABANDONED.append(proc)
    return Result(None, '', '%s did not exit after kill, gave up waiting' % os.path.basename(str(argv[0])), timed_out=True)


def checked(run, argv, what, **kwargs):
    result = run(argv, **kwargs)
    if not result.ok:
        raise DetectError('%s failed (%s)' % (what, result.brief()))
    return result.out


# ---------------------------------------------------------------- 文件

def now_text(value=None):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() if value is None else value))


def atomic_write(path, data, mode=0o644):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def archive_file(path, directory, stamp=None):
    """把文件移进归档目录。同名文件已经在了，就在文件名后面加上时间。返回新路径。"""
    directory = Path(directory)
    if not os.path.isdir(str(directory)):
        os.mkdir(str(directory), 0o755)
    name = Path(path).name
    target = directory / name
    if os.path.lexists(str(target)):
        target = directory / ('%s.%s' % (name, stamp or time.strftime('%Y%m%d-%H%M%S')))
    shutil.move(str(path), str(target))
    return target


def read_json(path, limit=4 * 1024 * 1024):
    with open(str(path), 'rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('file too large')
    return json.loads(data.decode('utf-8'))


def check_trusted(path, directory=False):
    """特权程序读写的文件和目录必须属于 root，组和其他人不可写，不能是符号链接。"""
    path = Path(path)
    meta = os.lstat(str(path))
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    # 系统的 /private/var/run 是 root:daemon 0775，只对它放宽组写。
    forbidden = 0o002 if directory and str(path) == '/private/var/run' else 0o022
    if not kind(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & forbidden:
        raise GuardError('wrong owner, type or permissions: %s' % path)


def check_tree(path, directory=False):
    path = Path(path)
    for parent in reversed(path.parents):
        check_trusted(parent, True)
    check_trusted(path, directory)


class Paths:
    def __init__(self, root=ROOT, state=STATE, log=LOG):
        self.root, self.state, self.log = Path(root), Path(state), Path(log)
        self.config = self.root / 'config.json'
        self.marker = self.root / 'disabled'
        self.cache = self.root / 'tailscale-cache.json'
        self.archive = self.root / 'archive'
        self.status = self.state / 'status.json'
        self.token = self.state / 'token.json'
        self.lock = self.state / 'daemon.lock'


def marker_exists(paths):
    return os.path.lexists(str(paths.marker))


# ---------------------------------------------------------------- 配置

def is_public(address):
    ip = ipaddress.ip_address(address) if isinstance(address, str) else address
    return ip.is_global and not any(ip in net for net in NOT_PUBLIC)


def valid_core_path(path):
    return (isinstance(path, str) and path.startswith('/') and len(path) <= 1024
            and not any(ch in path for ch in '\0\n\r'))


def validate_config(data):
    if not isinstance(data, dict):
        raise ConfigError('config must be a JSON object')
    unknown = sorted(set(data) - set(DEFAULTS))
    if unknown:
        raise ConfigError('unknown fields: ' + ', '.join(unknown))
    cfg = dict(DEFAULTS)
    cfg.update(data)
    if isinstance(cfg['version'], bool) or cfg['version'] != 2:
        raise ConfigError('version must be 2')
    tun = cfg['tun_interface']
    if not isinstance(tun, str) or not (tun == AUTO or UTUN.fullmatch(tun)):
        raise ConfigError('tun_interface must be "auto" or utun plus a number, such as utun1500')
    core = cfg['mihomo_path']
    if core == '':
        cfg['mihomo_path'] = core = AUTO
    if isinstance(core, list):
        if not 1 <= len(core) <= MAX_CORE_PATHS or not all(valid_core_path(p) for p in core):
            raise ConfigError('mihomo_path list must hold 1 to %d absolute paths' % MAX_CORE_PATHS)
        cfg['mihomo_path'] = list(core)
    elif core != AUTO and not valid_core_path(core):
        raise ConfigError('mihomo_path must be "auto", an absolute path or a list of absolute paths')
    probes = cfg['probe_addresses']
    if not isinstance(probes, list) or not 1 <= len(probes) <= 8:
        raise ConfigError('probe_addresses must be 1 to 8 IPv4 addresses')
    for value in probes:
        try:
            ip = ipaddress.ip_address(value) if isinstance(value, str) else None
        except ValueError:
            ip = None
        if ip is None or ip.version != 4 or not is_public(ip) or str(ip) != value:
            raise ConfigError('probe_addresses must be public IPv4 addresses: %r' % (value,))
    hours = cfg['tailscale_refresh_hours']
    if isinstance(hours, bool) or not isinstance(hours, (int, float)) or not 1 <= hours <= 168:
        raise ConfigError('tailscale_refresh_hours must be between 1 and 168')
    return cfg


def load_config(path, secure=False):
    try:
        if secure:
            check_tree(path)
        data = read_json(path, 1024 * 1024)
    except FileNotFoundError:
        raise ConfigError('config file not found: %s' % path)
    except (OSError, ValueError, GuardError) as exc:
        raise ConfigError('cannot read config file %s: %s' % (path, exc))
    return validate_config(data)


def merge_config_files(example, local=None):
    """安装用：config.example.json 打底，config.local.json 里写了的字段覆盖。"""
    try:
        base = read_json(example, 1024 * 1024)
        override = read_json(local, 1024 * 1024) if local else {}
    except (OSError, ValueError) as exc:
        raise ConfigError('cannot read config file: %s' % exc)
    if not isinstance(base, dict) or not isinstance(override, dict):
        raise ConfigError('config must be a JSON object')
    merged = dict(base)
    merged.update(override)
    return validate_config(merged)


# ---------------------------------------------------------------- 检测

def parse_ps(text):
    """解析 ps -o pid=,comm= 的输出，返回 [(pid, 启动命令)]。命令里可以有空格。"""
    rows = []
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        rows.append((int(parts[0]), parts[1]))
    if not rows:
        raise DetectError('cannot parse ps output')
    return rows


def _dir_pattern(directory):
    return re.compile(re.escape(directory).replace(r'\*', '[^/]+') + '/[^/]+')


CLIENT_PATTERNS = tuple((name, _dir_pattern(directory)) for name, directory in CLIENT_DIRS)


class Core:
    """一个识别出的 Clash 内核进程。"""

    def __init__(self, pid, path, client):
        self.pid, self.path, self.client = pid, path, client

    def data(self):
        return {'pid': self.pid, 'path': self.path, 'client': self.client}


def client_of(path, fallback=UNKNOWN_CLIENT):
    for name, pattern in CLIENT_PATTERNS:
        if pattern.fullmatch(path):
            return name
    return fallback


def find_cores(rows, setting):
    """按 mihomo_path 找内核进程。auto 按文件名认；写了路径就要和 ps 里的命令完全一样。"""
    if setting == AUTO:
        found = [Core(pid, command, client_of(command)) for pid, command in rows
                 if posixpath.basename(command) in CORE_NAMES]
    else:
        wanted = [setting] if isinstance(setting, str) else list(setting)
        found = [Core(pid, command, client_of(command, CONFIGURED_CLIENT)) for pid, command in rows
                 if command in wanted]
    return found[:MAX_CORES]


def parse_ifconfig(text):
    ifaces, current = {}, None
    for line in text.splitlines():
        match = IFACE_LINE.match(line)
        if match:
            current = {'flags': set(f for f in match.group(2).split(',') if f), 'inet': [], 'inet6': []}
            ifaces[match.group(1)] = current
            continue
        if current is None or not line[:1].isspace():
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[0] == 'inet':
            current['inet'].append(fields[1])
        elif len(fields) >= 2 and fields[0] == 'inet6':
            current['inet6'].append(fields[1].split('%')[0])
    if not ifaces:
        raise DetectError('cannot parse ifconfig output')
    return ifaces


def parse_route_interface(text):
    for line in text.splitlines():
        match = re.match(r'\s*interface:\s*(\S+)\s*$', line)
        if match:
            return match.group(1)
    raise DetectError('no interface in route get output')


def has_tailnet_address(info):
    tailnet = ipaddress.ip_network(TAILNET_V4)
    for value in info['inet']:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            continue
        if ip.version == 4 and ip in tailnet:
            return True
    return False


def tailscale_interfaces(ifaces, tun=None):
    """Tailscale 的 utun：带 100.64.0.0/10 地址的 utun，编号会变，每次现找。

    写死了 Clash TUN 的网卡名时把它排除在外；自动识别时不排除，带这种地址的 utun 不会被认成 Clash TUN。
    """
    found = [name for name in sorted(ifaces, key=lambda n: (len(n), n))
             if name != tun and UTUN.fullmatch(name) and has_tailnet_address(ifaces[name])]
    return found[:MAX_TAILSCALE_INTERFACES]


def parse_boot_id(text):
    """kern.bootsessionuuid 每次开机生成一次，之后不变。"""
    match = re.fullmatch(r'\s*([0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})\s*', text or '')
    if not match:
        raise DetectError('cannot parse kern.bootsessionuuid')
    return match.group(1).upper()


def boot_id(run=run):
    return parse_boot_id(checked(run, [SYSCTL, '-n', 'kern.bootsessionuuid'], 'reading boot ID'))


def parse_boottime(text):
    """v1 用 kern.boottime 当开机标识。它是“现在时间减运行时长”，开机后校时会让它变，只用来比对 v1 的状态。"""
    match = re.search(r'sec = (\d+), usec = (\d+)', text)
    if not match:
        raise DetectError('cannot parse kern.boottime')
    return '%s.%06d' % (match.group(1), int(match.group(2)))


def boottime(run=run):
    return parse_boottime(checked(run, [SYSCTL, '-n', 'kern.boottime'], 'reading boot time'))


class Health:
    """一次检测的结果。tun 是写死的网卡名，或者自动识别出的网卡名（没识别出来是 None）。"""

    def __init__(self, ok, reason, cores=(), tailscale=(), tun=None, auto_tun=False):
        self.ok, self.reason = ok, reason
        self.cores, self.tailscale = list(cores), list(tailscale)
        self.tun, self.auto_tun = tun, auto_tun

    @property
    def pids(self):
        return [core.pid for core in self.cores]

    def summary(self):
        parts = ['core pid %s %s' % (self.cores[0].pid, self.cores[0].client)] if self.cores else []
        if self.tun:
            parts.append('tun %s' % self.tun)
        return ', '.join(parts)


def tun_problem(name, ifaces):
    info = ifaces.get(name)
    if info is None:
        return '%s does not exist' % name
    if 'UP' not in info['flags']:
        return '%s is not up' % name
    if not info['inet']:
        return '%s has no IPv4 address' % name
    return None


def route_via(run, address):
    out = checked(run, [ROUTE, '-n', 'get', address], 'route lookup for %s' % address, timeout=DETECT_TIMEOUT)
    return parse_route_interface(out)


def check_routes(cfg, run, ifaces):
    """查探测地址的路由。返回 (TUN 网卡名或 None, 问题或 None)。

    写死网卡名时，每个探测地址都要走它。自动识别时，每个探测地址都要走同一个 utun，
    它不能是 Tailscale 的网卡（带 100.64.0.0/10 地址），还要已启用、有 IPv4 地址。
    """
    tun = cfg['tun_interface'] if cfg['tun_interface'] != AUTO else None
    for address in cfg['probe_addresses']:
        try:
            via = route_via(run, address)
        except Exception as exc:
            return None, str(exc)
        if tun is None:
            if not UTUN.fullmatch(via):
                return None, 'route to %s goes via %s, not Clash TUN' % (address, via)
            if via in ifaces and has_tailnet_address(ifaces[via]):
                return None, 'route to %s goes via Tailscale interface %s, not Clash TUN' % (address, via)
            problem = tun_problem(via, ifaces)
            if problem:
                return None, problem
            tun = via
        elif via != tun:
            return None, 'route to %s goes via %s, not %s' % (address, via, tun)
    return tun, None


def inspect(cfg, run=run, cfg_error=None):
    """判定 Clash TUN 是否正常。任何一步出错都算不正常。"""
    reasons = []
    if cfg is None:
        reasons.append('invalid config: %s' % (cfg_error or 'no config'))
    auto_tun = cfg is not None and cfg['tun_interface'] == AUTO
    fixed = cfg['tun_interface'] if cfg is not None and not auto_tun else None
    cores, tailscale, tun = [], [], fixed
    if cfg is not None:
        try:
            out = checked(run, [PS, '-axww', '-o', 'pid=,comm='], 'listing processes', timeout=DETECT_TIMEOUT)
            cores = find_cores(parse_ps(out), cfg['mihomo_path'])
            if not cores:
                reasons.append('Clash core is not running')
        except Exception as exc:
            reasons.append('Clash core check failed: %s' % exc)
    try:
        ifaces = parse_ifconfig(checked(run, [IFCONFIG, '-a'], 'reading interfaces', timeout=DETECT_TIMEOUT))
        tailscale = tailscale_interfaces(ifaces, fixed)
        if fixed:
            problem = tun_problem(fixed, ifaces)
            if problem:
                reasons.append(problem)
    except Exception as exc:
        reasons.append('interface check failed: %s' % exc)
    if not reasons:
        found, problem = check_routes(cfg, run, ifaces)
        if auto_tun:
            tun = found
        if problem:
            reasons.append(problem)
    if reasons:
        return Health(False, reasons[0], cores, tailscale, tun, auto_tun)
    return Health(True, 'Clash TUN ok', cores, tailscale, tun, auto_tun)


# ---------------------------------------------------------------- 规则

def table_lines(name, addresses, per_line=6):
    items = [str(a) for a in addresses]
    chunks = [items[i:i + per_line] for i in range(0, len(items), per_line)]
    lines = []
    for index, chunk in enumerate(chunks):
        head = 'table <%s> const { ' % name if index == 0 else '    '
        tail = ' }' if index == len(chunks) - 1 else ', \\'
        lines.append(head + ', '.join(chunk) + tail)
    return lines


def block_rules(tailscale=(), infra=()):
    """断网规则：只过滤出站，放行规则一律 quick + no state，最后两条拦下其余 IPv4 和 IPv6。"""
    for name in tailscale:
        if not isinstance(name, str) or not UTUN.fullmatch(name):
            raise ValueError('bad Tailscale interface name: %r' % (name,))
    addresses = set()
    for value in infra:
        ip = ipaddress.ip_address(value)
        if not is_public(ip):
            raise ValueError('not a public address: %s' % value)
        addresses.add(ip)
    if len(addresses) > MAX_ADDRESSES:
        raise ValueError('more than %d Tailscale addresses' % MAX_ADDRESSES)
    ordered = sorted(addresses, key=lambda ip: (ip.version, int(ip)))
    lines = ['# AccountNetGuard %s block rules (generated)' % VERSION]
    if ordered:
        lines += table_lines(TABLE, ordered)
    lines += [
        'pass out quick on lo0 all no state',
        'pass out quick inet proto udp from any port 68 to any port 67 no state',
        'pass out quick inet to { %s } no state' % ', '.join(LAN_V4),
        'pass out quick inet6 to { %s } no state' % ', '.join(LAN_V6),
    ]
    lines += ['pass out quick on %s all no state' % name for name in tailscale]
    lines += [
        'pass out quick inet to %s no state' % TAILNET_V4,
        'pass out quick inet6 to %s no state' % TAILNET_V6,
    ]
    if ordered:
        lines += [
            'pass out quick proto tcp to <%s> port { 80, 443 } no state' % TABLE,
            'pass out quick proto udp to <%s> port 3478 no state' % TABLE,
        ]
    lines += ['block return out quick inet all', 'block return out quick inet6 all']
    return '\n'.join(lines) + '\n'


MINIMAL_RULES = block_rules()


def has_block(text):
    return any(line.startswith(BLOCK_PREFIX) for line in (text or '').splitlines())


def normalize_rules(text):
    return '\n'.join(line.rstrip() for line in text.splitlines() if line.strip())


class PF:
    """pfctl 的薄封装。所有调用都经过带超时的 run。"""

    def __init__(self, run=run, anchor=ANCHOR):
        self.run, self.anchor = run, anchor

    def load(self, text):
        result = self.run([PFCTL, '-o', 'none', '-a', self.anchor, '-f', '-'], input=text)
        return result.ok, result.brief()

    def check(self, text):
        result = self.run([PFCTL, '-n', '-o', 'none', '-a', self.anchor, '-f', '-'], input=text)
        return result.ok, result.brief()

    def flush(self, anchor=None):
        anchor = anchor or self.anchor
        rules = self.run([PFCTL, '-q', '-a', anchor, '-F', 'rules'])
        tables = self.run([PFCTL, '-q', '-a', anchor, '-F', 'Tables'])
        return rules.ok and tables.ok

    def rules(self, anchor=None):
        return normalize_rules(checked(self.run, [PFCTL, '-a', anchor or self.anchor, '-sr'], 'reading PF rules'))

    def main_rules(self):
        return normalize_rules(checked(self.run, [PFCTL, '-sr'], 'reading PF main ruleset'))

    def enabled(self):
        out = checked(self.run, [PFCTL, '-s', 'info'], 'reading PF status')
        if re.search(r'^Status: Enabled\b', out, re.M):
            return True
        if re.search(r'^Status: Disabled\b', out, re.M):
            return False
        raise DetectError('cannot parse PF status')

    def enable(self):
        result = self.run([PFCTL, '-E'])
        tokens = TOKEN.findall(result.out + '\n' + result.err)
        if not result.ok or len(tokens) != 1:
            raise DetectError('pfctl -E returned no token (%s)' % result.brief())
        return tokens[0]

    def release(self, token):
        if not re.fullmatch(r'\d+', str(token)):
            return False
        return self.run([PFCTL, '-X', str(token)]).ok

    def token_listed(self, token):
        """token 还在 PF 引用列表里返回 True，不在返回 False，查不了返回 None。"""
        result = self.run([PFCTL, '-s', 'References'])
        if not result.ok:
            return None
        return str(token) in (result.out + '\n' + result.err).split()


# ---------------------------------------------------------------- PF 引用 token

class TokenFile:
    def __init__(self, path):
        self.path = Path(path)

    @staticmethod
    def valid(data):
        return (isinstance(data, dict) and re.fullmatch(r'\d+', str(data.get('token', ''))) is not None
                and isinstance(data.get('boot'), str))

    def load(self):
        try:
            data = read_json(self.path, 64 * 1024)
        except (OSError, ValueError):
            return None
        return data if self.valid(data) else None

    def save(self, token, boot):
        payload = {'token': str(token), 'boot': boot or '', 'pid': os.getpid(), 'time': time.time()}
        atomic_write(self.path, json.dumps(payload).encode(), 0o600)

    def claim(self):
        """把 token 文件改名认领。改名是原子的，disable 和守护进程同时释放时只有一方拿到。"""
        tmp = self.path.with_name('%s.%d.%d.release' % (self.path.name, os.getpid(), threading.get_ident()))
        try:
            os.rename(str(self.path), str(tmp))
        except FileNotFoundError:
            return None, None
        try:
            data = read_json(tmp, 64 * 1024)
        except (OSError, ValueError):
            data = None
        return data, tmp


def acquire_token(pf, tokens, boot):
    """同一次开机内复用自己存下的 token；它不在引用列表里就重新 -E。从不释放来历不明的 token。"""
    data = tokens.load()
    if data and boot and data['boot'] == boot and pf.token_listed(data['token']):
        return data['token'], True
    token = pf.enable()
    tokens.save(token, boot)
    return token, False


def release_token(pf, tokens, boot):
    data, tmp = tokens.claim()
    if tmp is None:
        return 'none'
    outcome = 'failed'
    try:
        if not TokenFile.valid(data):
            outcome = 'invalid'
        elif not boot or data['boot'] != boot:
            outcome = 'stale'
        elif pf.token_listed(data['token']) is False:
            outcome = 'gone'
        elif pf.release(data['token']):
            outcome = 'released'
        return outcome
    finally:
        try:
            if outcome == 'failed' and not os.path.lexists(str(tokens.path)):
                os.rename(str(tmp), str(tokens.path))
            else:
                os.unlink(str(tmp))
        except OSError:
            pass


# ---------------------------------------------------------------- Tailscale 地址

def fetch_json(url, headers=None, timeout=10.0, limit=2 * 1024 * 1024):
    """不走系统代理：放行模式下直连也会进 Clash TUN。"""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    merged = {'User-Agent': 'AccountNetGuard/' + VERSION}
    merged.update(headers or {})
    with opener.open(urllib.request.Request(url, headers=merged), timeout=timeout) as response:
        if response.status != 200:
            raise ValueError('HTTP %d' % response.status)
        body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError('response too large')
    return json.loads(body.decode('utf-8'))


def _name(value):
    return value.strip().rstrip('.').lower() if isinstance(value, str) else ''


def parse_doh(data, name, rtype):
    code, version = {'A': (1, 4), 'AAAA': (28, 6)}[rtype]
    if not isinstance(data, dict) or data.get('Status') != 0:
        raise ValueError('DoH query %s %s failed' % (name, rtype))
    answers = data.get('Answer', [])
    if not isinstance(answers, list) or not all(isinstance(a, dict) for a in answers):
        raise ValueError('malformed DoH response')
    names = {_name(name)}
    for _ in range(8):
        aliases = {_name(a.get('data')) for a in answers if a.get('type') == 5 and _name(a.get('name')) in names}
        if aliases <= names:
            break
        names |= aliases
    found = []
    for answer in answers:
        if answer.get('type') != code or _name(answer.get('name')) not in names:
            continue
        value = answer.get('data')
        ip = ipaddress.ip_address(value if isinstance(value, str) else '')
        if ip.version != version:
            raise ValueError('DoH returned the wrong address family: %s' % ip)
        found.append(str(ip))
    return found


def resolve(fetch, name):
    found = []
    for rtype in ('A', 'AAAA'):
        url = DOH_URL + '?' + urllib.parse.urlencode({'name': name, 'type': rtype})
        found += parse_doh(fetch(url, {'accept': 'application/dns-json'}), name, rtype)
    if not found:
        raise ValueError('no addresses for %s' % name)
    return found


def parse_derpmap(data):
    """返回 (地址列表, 需要另外解析的主机名列表)。"""
    regions = data.get('Regions') if isinstance(data, dict) else None
    if not isinstance(regions, dict) or not regions:
        raise ValueError('derpmap has no Regions')
    addresses, hosts = [], []
    for region in regions.values():
        nodes = region.get('Nodes') if isinstance(region, dict) else None
        if not isinstance(nodes, list):
            raise ValueError('malformed derpmap Nodes')
        for node in nodes:
            if not isinstance(node, dict):
                raise ValueError('malformed derpmap node')
            empty = 0
            for key, version in (('IPv4', 4), ('IPv6', 6)):
                value = node.get(key, '')
                if value in ('', None):
                    empty += 1
                    continue
                if value == 'none':
                    continue
                if not isinstance(value, str):
                    raise ValueError('malformed derpmap address')
                ip = ipaddress.ip_address(value)
                if ip.version != version:
                    raise ValueError('derpmap %s is not IPv%d: %s' % (key, version, value))
                addresses.append(str(ip))
            host = _name(node.get('HostName'))
            if empty == 2 and HOSTNAME.fullmatch(host):
                hosts.append(host)
    return addresses, sorted(set(hosts))


def validate_addresses(values, what='addresses'):
    """全部是公网地址、不为空、不超过上限，才算通过。"""
    result = set()
    for value in values:
        ip = ipaddress.ip_address(value)
        if not is_public(ip):
            raise ValueError('%s: non-public address %s' % (what, ip))
        result.add(ip)
    if not result:
        raise ValueError('%s: none found' % what)
    if len(result) > MAX_ADDRESSES:
        raise ValueError('%s: more than %d' % (what, MAX_ADDRESSES))
    return [str(ip) for ip in sorted(result, key=lambda ip: (ip.version, int(ip)))]


def fetch_derp(fetch):
    addresses, hosts = parse_derpmap(fetch(DERPMAP_URL, {}))
    if len(hosts) > MAX_HOSTNAMES:
        raise ValueError('too many DERP hostnames to resolve')
    for host in hosts:
        addresses += resolve(fetch, host)
    return validate_addresses(addresses, 'DERP addresses')


def fetch_control(fetch):
    addresses = []
    for host in CONTROL_HOSTS:
        addresses += resolve(fetch, host)
    return validate_addresses(addresses, 'control server addresses')


def empty_cache():
    return {'version': 1, 'sources': {}}


def check_cache(data):
    if not isinstance(data, dict) or data.get('version') != 1 or not isinstance(data.get('sources'), dict):
        raise ValueError('malformed cache')
    total = set()
    for name, source in data['sources'].items():
        if name not in SOURCES or not isinstance(source, dict):
            raise ValueError('unknown cache source: %r' % (name,))
        updated = source.get('updated')
        if isinstance(updated, bool) or not isinstance(updated, (int, float)) \
                or not isinstance(source.get('addresses'), list):
            raise ValueError('malformed cache source %s' % name)
        total.update(validate_addresses(source['addresses'], 'cached addresses'))
    if len(total) > MAX_ADDRESSES:
        raise ValueError('cached addresses: more than %d' % MAX_ADDRESSES)
    return data


def load_cache(path):
    """没有缓存返回 None。缓存损坏抛 ValueError，调用方按没有缓存处理，只放行隧道地址段。"""
    try:
        data = read_json(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError('cannot read cache: %s' % exc)
    return check_cache(data)


def _address_key(text):
    ip = ipaddress.ip_address(text)
    return ip.version, int(ip)


def cache_addresses(cache):
    if not cache:
        return []
    found = set()
    for source in cache['sources'].values():
        found.update(source['addresses'])
    return sorted(found, key=_address_key)


def cache_counts(cache):
    sources = (cache or {}).get('sources', {})
    counts = dict((name, len(sources[name]['addresses']) if name in sources else 0) for name in SOURCES)
    updated = [s['updated'] for s in sources.values()]
    return counts, (max(updated) if updated else None)


def merge_cache(old, fresh, now):
    """按来源合并：拉成功的来源整体替换，失败的来源沿用旧数据。合并后超上限就整个放弃这次结果。"""
    cache = {'version': 1, 'sources': dict((old or empty_cache())['sources'])}
    for name, addresses in fresh.items():
        cache['sources'][name] = {'updated': now, 'addresses': list(addresses)}
    if len(cache_addresses(cache)) > MAX_ADDRESSES:
        raise ValueError('more than %d addresses after merge, refresh discarded' % MAX_ADDRESSES)
    return check_cache(cache)


def refresh_cache(path, fetch=fetch_json, now=None):
    """刷新缓存，返回 (缓存, 错误字典)。只有校验通过才原子替换文件，拉取失败不会清空旧地址。"""
    now = time.time() if now is None else now
    errors = {}
    try:
        old = load_cache(path)
    except ValueError as exc:
        old, errors['cache'] = None, str(exc)
    fresh = {}
    for name, job in (('derp', fetch_derp), ('control', fetch_control)):
        try:
            fresh[name] = job(fetch)
        except Exception as exc:
            errors[name] = '%s: %s' % (type(exc).__name__, exc)
    if not fresh:
        return old, errors
    try:
        cache = merge_cache(old, fresh, now)
    except ValueError as exc:
        errors['merge'] = str(exc)
        return old, errors
    atomic_write(path, json.dumps(cache, indent=1, sort_keys=True).encode(), 0o644)
    return cache, errors


# ---------------------------------------------------------------- 事件

def route_message_relevant(data):
    """路由表或网卡真的变了才算数。RTM_GET、ARP 和克隆路由这类噪声不触发检查。"""
    if len(data) < 4:
        return True
    kind = data[3]
    if kind in ROUTE_CHANGES:
        if len(data) < 12:
            return True
        flags = struct.unpack_from('=i', data, 8)[0]
        return not flags & (RTF_WASCLONED | RTF_LLINFO)
    return kind in LINK_CHANGES


class Events:
    """kqueue 同时等路由 socket 和 mihomo 退出。"""

    def __init__(self):
        self.kq = select.kqueue()
        self.watched = set()
        self.route, self.error = None, None
        try:
            sock = socket.socket(socket.AF_ROUTE, socket.SOCK_RAW, 0)
            sock.setblocking(False)
            self.kq.control([select.kevent(sock.fileno(), select.KQ_FILTER_READ, select.KQ_EV_ADD)], 0)
            self.route = sock
        except OSError as exc:
            self.error = 'cannot open route socket, polling only: %s' % exc

    def watch(self, pids):
        """登记 NOTE_EXIT。有 pid 已经不在了返回 False，调用方应马上重新检查。"""
        alive = True
        for pid in pids:
            if pid in self.watched:
                continue
            event = select.kevent(pid, select.KQ_FILTER_PROC, select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                                  select.KQ_NOTE_EXIT)
            try:
                self.kq.control([event], 0)
                self.watched.add(pid)
            except ProcessLookupError:
                alive = False
            except OSError as exc:
                self.error = 'cannot watch core process, using route messages and polling: %s' % exc
        return alive

    def wait(self, timeout):
        """返回 (路由有变化, 有进程退出)。"""
        events = self.kq.control(None, 16, min(60.0, max(0.0, timeout)))
        route = exited = False
        for event in events:
            if event.filter == select.KQ_FILTER_PROC:
                self.watched.discard(event.ident)
                exited = True
            elif self.route is not None and event.ident == self.route.fileno():
                route = self.drain() or route
        return route, exited

    def drain(self):
        relevant = False
        for _ in range(4096):
            try:
                data = self.route.recv(8192)
            except BlockingIOError:
                break
            except OSError:
                # ENOBUFS 之类说明丢了消息，按有变化处理。
                relevant = True
                break
            if not data:
                break
            relevant = route_message_relevant(data) or relevant
        return relevant

    def close(self):
        if self.route is not None:
            self.route.close()
        self.kq.close()


# ---------------------------------------------------------------- 守护进程

class Log:
    def __init__(self, stream=None, clock=time.monotonic):
        self.stream = stream
        self.clock = clock
        self.seen = {}

    def info(self, text):
        try:
            print('%s %s' % (now_text(), text), file=self.stream or sys.stdout, flush=True)
        except (OSError, ValueError):
            pass

    def error(self, key, text):
        now = self.clock()
        last = self.seen.get(key)
        if last is None or now - last >= ERROR_INTERVAL:
            self.seen[key] = now
            self.info('error: ' + text)


class Daemon:
    def __init__(self, paths=None, run=run, clock=time.monotonic, wall=time.time,
                 fetch=fetch_json, secure=True, stream=None):
        self.paths = paths or Paths()
        self.run, self.clock, self.wall, self.fetch = run, clock, wall, fetch
        self.secure = secure
        self.pf = PF(run)
        self.tokens = TokenFile(self.paths.token)
        self.log = Log(stream, clock)
        self.poll, self.coalesce, self.debounce, self.reconcile_every = POLL, COALESCE, DEBOUNCE, RECONCILE
        self.mode = None            # PF 里实际生效的模式：allow / block / disabled，None 表示不确定
        self.applied = None         # 最后一次成功加载的规则文本，'' 表示已清空，None 表示不确定
        self.fingerprint = None     # 加载后 pfctl -sr 的输出，核对时用来发现别人改了规则
        self.since = self.wall()
        self.reason = 'starting'
        self.health = None
        self.healthy_since = None
        self.wake_at = float('inf')
        self.allow_times = collections.deque()
        self.held = False
        self.boot = None
        self.token = None
        self.cfg, self.cfg_error = None, 'config not loaded yet'
        self.cache = None
        self.problems = {}
        self.last_error = None
        self.next_refresh = 0.0
        self.refresh_thread = None
        self.refresh_results = queue.Queue()
        self.status_key = None
        self.lock_fd = None

    # -- 记录

    def fail(self, key, text):
        self.last_error = {'time': self.wall(), 'message': text}
        self.log.error(key, text)

    def problem(self, key, text):
        if text:
            if self.problems.get(key) != text:
                self.fail(key, text)
            self.problems[key] = text
        else:
            self.problems.pop(key, None)

    # -- 启动

    def prepare(self):
        try:
            if not os.path.isdir(str(self.paths.state)):
                os.mkdir(str(self.paths.state), 0o755)
            os.chmod(str(self.paths.state), 0o755)
            if self.secure:
                check_tree(self.paths.state, True)
                check_tree(self.paths.root, True)
            self.problem('state', None)
        except (OSError, GuardError) as exc:
            self.problem('state', 'state directory: %s' % exc)
        self.trim_log()

    def trim_log(self):
        try:
            if self.paths.log.stat().st_size > LOG_LIMIT:
                os.truncate(str(self.paths.log), 0)
                self.log.info('log over %d MB, truncated' % (LOG_LIMIT // 1024 // 1024))
        except OSError:
            pass

    def take_lock(self):
        try:
            fd = os.open(str(self.paths.lock), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        except OSError:
            return True     # 锁文件都建不了时不拦着自己，保护优先
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        self.lock_fd = fd
        return True

    def startup(self):
        try:
            self.boot = boot_id(self.run)
            self.problem('boot', None)
        except DetectError as exc:
            self.problem('boot', 'no boot ID, PF reference cannot be reused after a restart: %s' % exc)
        self.load_config()
        self.load_cache_file()
        self.check_main_ruleset()
        try:
            current = self.pf.rules()
            self.fingerprint = current
            if not current:
                self.mode, self.applied = 'allow', ''
            elif has_block(current):
                self.mode = 'block'
        except DetectError as exc:
            self.fail('pf-read', str(exc))
        # anchor 为空时不多说；读取失败时上面已经记过错误。
        if self.mode == 'block':
            note = ', anchor holds block rules'
        elif self.mode is None and self.fingerprint:
            note = ', anchor holds unrecognized rules'
        else:
            note = ''
        self.log.info('AccountNetGuard %s started%s' % (VERSION, note))

    def load_config(self):
        try:
            self.cfg = load_config(self.paths.config, self.secure)
            self.cfg_error = None
            self.problem('config', None)
        except ConfigError as exc:
            self.cfg, self.cfg_error = None, str(exc)
            self.problem('config', str(exc))

    def load_cache_file(self):
        try:
            if self.secure and os.path.lexists(str(self.paths.cache)):
                check_trusted(self.paths.cache)
            cache = load_cache(self.paths.cache)
        except (ValueError, GuardError, OSError) as exc:
            cache = None
            self.fail('cache', 'Tailscale address cache unusable, block mode allows only tailnet ranges: %s' % exc)
        self.cache = cache
        hours = (self.cfg or DEFAULTS)['tailscale_refresh_hours']
        _, updated = cache_counts(cache)
        wait = 0.0 if updated is None else max(0.0, updated + hours * 3600 - self.wall())
        self.next_refresh = self.clock() + wait

    def check_main_ruleset(self):
        try:
            ok = MAIN_ANCHOR_RULE in self.pf.main_rules().splitlines()
            text = None if ok else 'PF main ruleset lacks %s, block rules will not take effect' % MAIN_ANCHOR_RULE
        except DetectError as exc:
            text = str(exc)
        self.problem('main', text)

    # -- token

    def ensure_token(self):
        if self.token is not None:
            return
        try:
            self.token, reused = acquire_token(self.pf, self.tokens, self.boot)
            self.problem('token', None)
            if not reused:
                self.log.info('acquired PF reference, token %s' % self.token)
        except (DetectError, OSError) as exc:
            self.problem('token', 'acquiring PF reference failed: %s' % exc)
            return
        if marker_exists(self.paths):
            # disable 恰好在申请期间执行，刚拿到的 token 马上还回去。
            release_token(self.pf, self.tokens, self.boot)
            self.token = None

    def check_pf_enabled(self):
        try:
            enabled = self.pf.enabled()
        except DetectError as exc:
            self.fail('pf-info', str(exc))
            return
        if not enabled:
            self.fail('pf-off', 'PF was disabled, acquiring a new PF reference')
            self.token = None
            self.ensure_token()
        elif self.token is not None and self.pf.token_listed(self.token) is False:
            self.log.info('PF reference token %s is gone, acquiring a new one' % self.token)
            self.token = None
            self.ensure_token()

    # -- 主逻辑

    def step(self):
        now = self.clock()
        self.wake_at = float('inf')
        if marker_exists(self.paths):
            # 停用期间不检测。旧的检测结果也丢掉，免得主循环继续盯着已经退出的 mihomo 空转。
            self.health = None
            self.enter_disabled()
            self.write_status()
            return
        self.ensure_token()
        health = inspect(self.cfg, self.run, self.cfg_error)
        self.health = health
        if health.ok:
            if self.healthy_since is None:
                self.healthy_since = now
        else:
            self.healthy_since = None
        want, why = self.desired(health, now)
        rules = self.render(health) if want == 'block' else ''
        if rules != self.applied or want != self.mode:
            self.apply(want, rules, why)
        else:
            self.reason = why
        self.write_status()

    def desired(self, health, now):
        if not health.ok:
            return 'block', health.reason
        # 本来就没在拦（放行中或刚停用过），继续放行；anchor 被人改过也只是重新清空，不用等。
        if self.mode in ('allow', 'disabled'):
            return 'allow', health.reason
        stable_at = self.healthy_since + self.debounce
        if now < stable_at:
            self.wake_at = stable_at
            return 'block', 'Clash TUN just recovered, confirming'
        while self.allow_times and now - self.allow_times[0] >= ALLOW_WINDOW:
            self.allow_times.popleft()
        if len(self.allow_times) >= ALLOW_BURST:
            self.wake_at = self.allow_times[0] + ALLOW_WINDOW
            if not self.held:
                self.held = True
                self.log.info('allowed %d times in %d s, staying blocked for now' % (ALLOW_BURST, ALLOW_WINDOW))
            return 'block', 'switching too often, allow delayed'
        self.held = False
        return 'allow', health.reason

    def render(self, health):
        try:
            return block_rules(health.tailscale, cache_addresses(self.cache))
        except ValueError as exc:
            self.fail('render', 'cannot build block rules, using minimal block rules: %s' % exc)
            return MINIMAL_RULES

    def apply(self, want, rules, why):
        if marker_exists(self.paths):
            self.enter_disabled()
            return
        if rules:
            ok, detail = self.pf.load(rules)
            if not ok and rules != MINIMAL_RULES:
                self.fail('load', 'loading block rules failed, using minimal block rules: %s' % detail)
                rules = MINIMAL_RULES
                ok, detail = self.pf.load(rules)
            if not ok:
                self.problem('apply', 'loading block rules failed, retrying: %s' % detail)
                return
        elif not self.pf.flush():
            self.problem('apply', 'flushing rules failed, retrying')
            return
        if marker_exists(self.paths):
            self.enter_disabled()
            return
        try:
            self.fingerprint = self.pf.rules()
        except DetectError as exc:
            self.fingerprint = None
            self.fail('pf-read', str(exc))
        if self.fingerprint is not None and has_block(self.fingerprint) != bool(rules):
            self.problem('apply', 'anchor rules do not match after loading, retrying')
            self.applied = None
            return
        self.problem('apply', None)
        self.applied = rules
        if rules:
            self.check_pf_enabled()
        changed = want != self.mode
        self.mode, self.reason = want, why
        tailscale = ', '.join(self.health.tailscale) if self.health and self.health.tailscale else 'none'
        if changed:
            self.since = self.wall()
            if want == 'allow':
                self.allow_times.append(self.clock())
                detail = self.health.summary() if self.health else ''
                self.log.info('allowed: %s' % why + (' (%s)' % detail if detail else ''))
            else:
                self.log.info('blocked: %s (tailscale: %s, %d server addresses)' % (
                    why, tailscale, len(cache_addresses(self.cache))))
        elif want == 'block':
            self.log.info('block rules updated (tailscale: %s)' % tailscale)

    def enter_disabled(self):
        if self.mode != 'disabled' or self.applied != '':
            if self.pf.flush():
                self.applied, self.fingerprint = '', ''
            else:
                self.applied = None
                self.fail('flush', 'flushing rules on disable failed, retrying on next check')
            release_token(self.pf, self.tokens, self.boot)
            self.token = None
            if self.mode != 'disabled':
                self.since = self.wall()
                self.log.info('disabled: disable marker found')
        self.mode, self.reason = 'disabled', 'disable marker present'
        self.healthy_since = None

    def reconcile(self):
        """定期核对：配置、主规则集、PF 是否启用、anchor 规则有没有被别人改。"""
        self.trim_log()
        self.load_config()
        self.check_main_ruleset()
        try:
            current = self.pf.rules()
        except DetectError as exc:
            self.fail('pf-read', str(exc))
            current = None
        if self.mode == 'disabled' or marker_exists(self.paths):
            if current:
                self.log.info('rules appeared in anchor while disabled, flushing')
                self.applied = None
                self.enter_disabled()
            self.write_status(force=True)
            return
        self.check_pf_enabled()
        if current is not None:
            if self.fingerprint is None:
                looks_right = has_block(current) if self.mode == 'block' else current == ''
                if looks_right:
                    self.fingerprint = current
                else:
                    self.applied = None
            elif current != self.fingerprint:
                self.log.info('anchor rules changed since last load, reloading')
                self.applied = None
        self.write_status(force=True)

    # -- Tailscale 地址刷新（后台线程）

    def maybe_refresh(self):
        if self.mode != 'allow' or self.clock() < self.next_refresh:
            return
        if self.refresh_thread is not None and self.refresh_thread.is_alive():
            return
        self.next_refresh = self.clock() + REFRESH_RETRY
        self.refresh_thread = threading.Thread(target=self._refresh, name='tailscale-refresh', daemon=True)
        self.refresh_thread.start()

    def _refresh(self):
        try:
            cache, errors = refresh_cache(self.paths.cache, self.fetch, self.wall())
            self.refresh_results.put((cache, errors))
        except Exception as exc:
            self.refresh_results.put((None, {'refresh': '%s: %s' % (type(exc).__name__, exc)}))

    def collect_refresh(self):
        while True:
            try:
                cache, errors = self.refresh_results.get_nowait()
            except queue.Empty:
                return
            if cache is not None:
                self.cache = cache
            if errors:
                self.fail('refresh', 'Tailscale address refresh incomplete, keeping old addresses: ' +
                          '; '.join('%s: %s' % item for item in sorted(errors.items())))
            else:
                hours = (self.cfg or DEFAULTS)['tailscale_refresh_hours']
                self.next_refresh = self.clock() + hours * 3600
            self.write_status()

    # -- 状态文件

    def status_data(self):
        counts, updated = cache_counts(self.cache)
        return {
            'version': VERSION,
            'pid': os.getpid(),
            'mode': self.mode or 'unknown',
            'reason': self.reason,
            'since': self.since,
            'cores': [core.data() for core in self.health.cores] if self.health else [],
            'tun_interface': self.health.tun if self.health else None,
            'tun_auto': self.health.auto_tun if self.health else None,
            'tailscale_interfaces': self.health.tailscale if self.health else [],
            'derp_count': counts['derp'],
            'control_count': counts['control'],
            'cache_updated': updated,
            'last_error': self.last_error,
            'problems': [self.problems[k] for k in sorted(self.problems)],
            'problem_keys': sorted(self.problems),
            'protected': self.protected(),
            'anchor': ANCHOR,
        }

    def protected(self):
        """规则已按当前模式加载并核对过，PF 引用也拿到了。安装器靠它判断能不能停掉 v1。"""
        return (self.mode in ('allow', 'block') and self.applied is not None
                and self.token is not None and not set(self.problems) & PROTECTION_PROBLEMS)

    def write_status(self, force=False):
        data = self.status_data()
        key = json.dumps(data, sort_keys=True)
        if key == self.status_key and not force:
            return
        data['updated'] = self.wall()
        try:
            atomic_write(self.paths.status, json.dumps(data, ensure_ascii=False, indent=1).encode(), 0o644)
            self.status_key = key
        except OSError as exc:
            self.log.error('status', 'cannot write status file: %s' % exc)

    # -- 主循环

    def on_signal(self, signum, frame):
        # 不清规则：断网中就继续断网，launchd 重新拉起后接着管。
        self.log.info('exiting on signal %d' % signum)
        os._exit(0)

    def serve(self, iterations=None):
        self.prepare()
        if not self.take_lock():
            self.log.info('another daemon is running, exiting')
            time.sleep(5)
            return 1
        signal.signal(signal.SIGTERM, self.on_signal)
        signal.signal(signal.SIGINT, self.on_signal)
        self.startup()
        events = Events()
        self.problem('events', events.error)
        inf = float('inf')
        due, next_poll = self.clock(), inf
        next_reconcile = self.clock() + self.reconcile_every
        last_step = -inf
        count = 0
        try:
            while iterations is None or count < iterations:
                count += 1
                try:
                    now = self.clock()
                    route, exited = events.wait(min(due, next_poll, next_reconcile, self.wake_at) - now)
                    now = self.clock()
                    if exited:
                        due = now
                    if route:
                        due = min(due, max(now + self.coalesce, last_step + ROUTE_GAP))
                    if now >= min(due, next_poll, self.wake_at):
                        self.step()
                        last_step = now = self.clock()
                        due, next_poll = inf, now + self.poll
                        if self.health is not None and not events.watch(self.health.pids):
                            # mihomo 在检测和登记之间退出了，隔一小会儿再查。不立刻查，
                            # 是为了防止某个 pid 一直登记不上时主循环空转。
                            due = now + ROUTE_GAP
                        self.problem('events', events.error)
                    if now >= next_reconcile:
                        self.reconcile()
                        next_reconcile = self.clock() + self.reconcile_every
                        if self.applied is None:
                            due = self.clock()
                    self.collect_refresh()
                    self.maybe_refresh()
                except Exception as exc:
                    self.fail('loop', 'main loop error: %s: %s' % (type(exc).__name__, exc))
                    time.sleep(0.5)
                    due = self.clock()
        finally:
            events.close()
        return 0


# ---------------------------------------------------------------- 命令行

def require_root():
    if os.geteuid() != 0:
        print('this command needs root, run it with sudo', file=sys.stderr)
        return False
    return True


def process_alive(pid):
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OSError, ValueError, TypeError):
        return False
    return True


def core_text(cores):
    """cores 是 Core.data() 的列表。"""
    cores = [core for core in cores or [] if isinstance(core, dict)]
    if not cores:
        return 'not found'
    first = cores[0]
    text = '%s, pid %s, %s' % (first.get('client'), first.get('pid'), first.get('path'))
    return text + (' (+%d more)' % (len(cores) - 1) if len(cores) > 1 else '')


def tun_text(name, auto):
    return '%s (%s)' % (name or 'not detected', 'auto' if auto else 'from config')


def format_status(data, now=None, alive=None):
    now = time.time() if now is None else now
    mode = data.get('mode', 'unknown')
    lines = ['mode: %s (%s)' % (MODE_TEXT.get(mode, mode), data.get('reason', ''))]
    if data.get('since'):
        lines.append('since: %s' % now_text(data['since']))
    # 2.0 的状态文件里没有这几项，升级过程中可能读到。停用时不检测，也不显示。
    if 'cores' in data and mode != 'disabled':
        lines.append('core: %s' % core_text(data.get('cores')))
    if data.get('tun_auto') is not None and mode != 'disabled':
        lines.append('TUN interface: %s' % tun_text(data.get('tun_interface'), data['tun_auto']))
    interfaces = data.get('tailscale_interfaces') or []
    lines.append('Tailscale interface: %s' % (', '.join(interfaces) if interfaces else 'none'))
    if data.get('cache_updated'):
        lines.append('Tailscale servers: DERP %s, control %s, cache updated %s' % (
            data.get('derp_count', 0), data.get('control_count', 0), now_text(data['cache_updated'])))
    else:
        lines.append('Tailscale servers: no cache, block mode allows only %s and %s' % (TAILNET_V4, TAILNET_V6))
    error = data.get('last_error')
    if error:
        lines.append('last error: %s %s' % (now_text(error.get('time')), error.get('message')))
    else:
        lines.append('last error: none')
    for text in data.get('problems') or []:
        lines.append('problem: %s' % text)
    age = max(0, now - data.get('updated', 0))
    line = 'daemon: pid %s, status updated %d s ago' % (data.get('pid'), age)
    if alive is False:
        line += ', process is gone, status may be stale'
    elif age > STATUS_STALE:
        line += ', status is stale, daemon may be stuck or not running'
    lines.append(line)
    return '\n'.join(lines)


def cmd_status(args, paths):
    try:
        data = read_json(paths.status, 1024 * 1024)
    except FileNotFoundError:
        print('no status file %s: daemon is not running or not installed' % paths.status)
        if marker_exists(paths):
            print('disable marker present: %s' % paths.marker)
        return 1
    except (OSError, ValueError) as exc:
        print('cannot read status file: %s' % exc)
        return 1
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=1))
        return 0
    print(format_status(data, alive=process_alive(data.get('pid'))))
    if marker_exists(paths) and data.get('mode') != 'disabled':
        print('disable marker present, daemon will flush rules on next check: %s' % paths.marker)
    return 0


def disable(paths=None, run=run, sleep=time.sleep, out=print):
    """紧急关闭：不依赖守护进程，也不拿守护进程的锁。"""
    paths = paths or Paths()
    pf, tokens = PF(run), TokenFile(paths.token)
    marked = False
    try:
        atomic_write(paths.marker, ('disabled %s\n' % now_text()).encode(), 0o644)
        marked = True
        out('wrote disable marker %s, it persists across reboots' % paths.marker)
    except OSError as exc:
        out('writing disable marker failed: %s. Flushing rules anyway, but the daemon may reload them.' % exc)
    first = pf.flush()
    out('flush %s: %s' % (ANCHOR, 'done' if first else 'failed'))
    try:
        boot = boot_id(run)
    except DetectError:
        boot = None
    out('PF reference: %s' % RELEASE_TEXT[release_token(pf, tokens, boot)])
    sleep(1.0)
    second = pf.flush()
    out('flush again after 1 s: %s' % ('done' if second else 'failed'))
    if marked and second:
        out('all traffic allowed now. To restore protection: sudo %s -I "%s" enable' % (PYTHON, INSTALLED))
        return 0
    out('not fully done. In an emergency run sudo %s -a %s -F rules, or sudo %s -d to turn off PF entirely.' % (
        PFCTL, ANCHOR, PFCTL))
    return 1


def enable(paths=None, out=print):
    paths = paths or Paths()
    if not marker_exists(paths):
        out('no disable marker, nothing to do')
        return 0
    try:
        os.unlink(str(paths.marker))
    except OSError as exc:
        out('cannot remove disable marker %s: %s' % (paths.marker, exc))
        return 1
    out('removed disable marker. The daemon resumes checks within 2 s and blocks if Clash TUN is not ok.')
    try:
        data = read_json(paths.status, 1024 * 1024)
        if time.time() - data.get('updated', 0) > STATUS_STALE or not process_alive(data.get('pid')):
            out('note: status file is stale, the daemon may not be running; check with status')
    except (OSError, ValueError):
        out('note: no status file, the daemon may not be running')
    return 0


def teardown(paths=None, run=run, out=print):
    """卸载用：清空 anchor，释放自己的 PF 引用。"""
    paths = paths or Paths()
    pf = PF(run)
    ok = pf.flush()
    out('flush %s: %s' % (ANCHOR, 'done' if ok else 'failed'))
    try:
        boot = boot_id(run)
    except DetectError:
        boot = None
    out('PF reference: %s' % RELEASE_TEXT[release_token(pf, TokenFile(paths.token), boot)])
    return ok


def cmd_refresh(args, paths):
    cache, errors = refresh_cache(paths.cache)
    counts, updated = cache_counts(cache)
    print('DERP %d, control %d, cache updated %s' % (
        counts['derp'], counts['control'], now_text(updated) if updated else 'never'))
    for name, text in sorted(errors.items()):
        print('failed: %s: %s' % (name, text))
    return 0 if not errors else 1


def cli_config(args, paths):
    given = getattr(args, 'config', None)
    path = Path(given) if given else paths.config
    if not given and not path.exists():
        return dict(DEFAULTS), 'defaults (%s not found)' % path, None
    try:
        return load_config(path), str(path), None
    except ConfigError as exc:
        return None, str(path), str(exc)


def cmd_rules(args, paths):
    cfg, _, error = cli_config(args, paths)
    health = inspect(cfg, run, error)
    try:
        cache = load_cache(Path(args.cache) if args.cache else paths.cache)
    except ValueError as exc:
        print('# cache unusable: %s' % exc)
        cache = None
    sys.stdout.write(block_rules(health.tailscale, cache_addresses(cache)))
    return 0


# 识别不到时提示去哪开 TUN。界面上的名称取自各客户端源码里的简体中文翻译。
CLIENT_APPS = (
    ('Clash Party', ('Clash Party.app', 'Mihomo Party.app'),
     'turn on the "TUN" switch in the sidebar; the first time, click "Authorize Core" on the TUN page'),
    ('Clash Verge Rev', ('Clash Verge.app',), 'install the service ("Service Mode") in Settings, then turn on "Tun Mode"'),
    ('FlClash', ('FlClash.app',), 'turn on "TUN" and grant permission when asked'),
    ('ClashX Meta', ('ClashX Meta.app',), 'install the helper when asked, then tick "Tun Mode" in the menu bar menu'),
)
BREW_MIHOMO = ('/opt/homebrew/opt/mihomo/bin/mihomo', '/usr/local/opt/mihomo/bin/mihomo')
BREW_HOW = 'enable tun in the mihomo config (enable: true) and run it as root, e.g. sudo brew services start mihomo'


def installed_clients(exists=os.path.exists, app_dirs=None):
    """返回 [(客户端, 怎么开 TUN)]：装在 /Applications 或 ~/Applications 里的已知客户端，和 Homebrew 的 mihomo。"""
    if app_dirs is None:
        app_dirs = ['/Applications'] + sorted(glob.glob('/Users/*/Applications'))
    found = []
    for name, apps, how in CLIENT_APPS:
        if any(exists(posixpath.join(directory, app)) for directory in app_dirs for app in apps):
            found.append((name, how))
    if any(exists(path) for path in BREW_MIHOMO):
        found.append(('Homebrew mihomo', BREW_HOW))
    return found


def setup_hints(health, cfg, clients):
    """Clash TUN 识别不到时的提示：装了哪个客户端、去哪开 TUN、怎么手动配置。"""
    if health.ok or cfg is None:
        return []
    lines = ['%s is installed: %s.' % item for item in clients]
    if not clients:
        lines.append('no known client found (%s, or Homebrew mihomo).' % ', '.join(c[0] for c in CLIENT_APPS))
    if not health.cores and cfg['mihomo_path'] == AUTO:
        lines.append('client is open but no core found: run ps -axww -o pid=,comm=, find the core, '
                     'and put the full path it shows into mihomo_path in the config.')
    elif not health.cores:
        lines.append('mihomo_path must match the command shown by ps -axww -o pid=,comm= exactly; '
                     'if unsure, set it back to "auto".')
    elif cfg['tun_interface'] != AUTO:
        lines.append('core is running, but %s does not qualify: TUN may be off or the interface name changed; '
                     'if unsure, set tun_interface back to "auto".' % cfg['tun_interface'])
    else:
        lines.append('core is running, but routes do not go through Clash TUN: TUN may be off, '
                     'or another VPN holds the default route. Check the interface line of route -n get 1.1.1.1.')
    lines.append('for manual settings, see the configuration section of the README.')
    return lines


OK, NOTE, FAIL = 'ok', 'note', 'FAIL'     # doctor 每行的级别


def doctor(args, paths, run=run, out=print, clients=None):
    """只读预检：不加载规则，不改任何文件，不发网络请求。"""
    bad = []

    def say(level, text):
        out('%-7s  %s' % (level, text))
        if level == FAIL:
            bad.append(text)

    out('AccountNetGuard %s doctor (read-only)' % VERSION)
    say(OK if sys.version_info >= (3, 9) else FAIL,
        'Python %s (%s)' % (sys.version.split()[0], sys.executable))
    cfg, source, error = cli_config(args, paths)
    if cfg:
        say(OK, 'config: %s' % source)
    else:
        say(FAIL, 'invalid config: %s' % error)
    health = inspect(cfg, run, error)
    if cfg:
        mode = 'auto' if cfg['mihomo_path'] == AUTO else 'from config'
        if not health.cores:
            say(NOTE, 'core (%s): not found' % mode)
        for core in health.cores:
            say(OK, 'core (%s): %s' % (mode, core_text([core.data()])))
        say(OK if health.ok else NOTE, 'TUN interface: %s' % tun_text(health.tun, health.auto_tun))
    say(OK if health.ok else NOTE, 'Clash TUN: %s' % ('ok' if health.ok else health.reason))
    say('verdict', 'Clash TUN ok, the daemon will flush rules and allow all traffic' if health.ok
        else 'Clash TUN not ok, the daemon will block')
    for line in setup_hints(health, cfg, installed_clients() if clients is None else clients):
        say(NOTE, line)
    say(OK if health.tailscale else NOTE, 'Tailscale interface: %s' % (
        ', '.join(health.tailscale) if health.tailscale else 'none'))
    try:
        cache = load_cache(paths.cache)
    except ValueError as exc:
        cache = None
        say(FAIL, 'Tailscale address cache is corrupt: %s' % exc)
    counts, updated = cache_counts(cache)
    if updated:
        say(OK, 'Tailscale servers: DERP %d, control %d, cache updated %s' % (
            counts['derp'], counts['control'], now_text(updated)))
    else:
        say(NOTE, 'Tailscale servers: no cache, block mode allows only %s and %s' % (TAILNET_V4, TAILNET_V6))
    pf = PF(run)
    ok, detail = pf.check(block_rules(health.tailscale, cache_addresses(cache)))
    say(OK if ok else FAIL, 'block rule syntax (pfctl -n): %s' % ('passed' if ok else detail))
    if os.geteuid() != 0:
        say(NOTE, 'not root, skipped PF status, anchor and v1 checks; run with sudo to include them')
    else:
        doctor_root(pf, run, say)
    installed = INSTALLED.exists() and PLIST.exists()
    say(OK if installed else NOTE, 'installed' if installed else 'not installed')
    if marker_exists(paths):
        say(NOTE, 'disable marker present: %s' % paths.marker)
    say('result', '%d failed' % len(bad) if bad else 'no failures')
    return 1 if bad else 0


def doctor_root(pf, run, say):
    try:
        enabled = pf.enabled()
        say(OK if enabled else NOTE, 'PF: %s' % ('enabled' if enabled else 'disabled, the daemon enables it while running'))
    except DetectError as exc:
        say(FAIL, str(exc))
    try:
        main = pf.main_rules().splitlines()
        say(OK if MAIN_ANCHOR_RULE in main else FAIL, 'PF main ruleset %s %s' % (
            'has' if MAIN_ANCHOR_RULE in main else 'lacks', MAIN_ANCHOR_RULE))
    except DetectError as exc:
        say(FAIL, str(exc))
    try:
        current = pf.rules()
        if not current:
            say(OK, 'anchor %s: empty (allow)' % ANCHOR)
        else:
            say(OK if has_block(current) else FAIL, 'anchor %s: %d rules (%s)' % (
                ANCHOR, len(current.splitlines()), 'block' if has_block(current) else 'unrecognized'))
    except DetectError as exc:
        say(FAIL, str(exc))
    try:
        left = pf.rules(OLD_ANCHOR)
    except DetectError:
        left = ''
    if left:
        say(FAIL, 'v1 anchor %s still has %d rules, install.py will flush them' % (OLD_ANCHOR, len(left.splitlines())))
    for label in OLD_LABELS:
        if run([LAUNCHCTL, 'print', 'system/' + label]).ok:
            say(FAIL, 'v1 launchd job %s is still loaded, install.py will stop it' % label)


def main(argv=None):
    parser = argparse.ArgumentParser(prog='accountnetguard.py',
                                     description='Block all traffic on this Mac when Clash TUN is not working; '
                                                 'only loopback, LAN and Tailscale stay allowed.')
    sub = parser.add_subparsers(dest='command')
    sub.add_parser('daemon', help='run as the daemon (started by launchd)')
    status = sub.add_parser('status', help='show status, no root needed')
    status.add_argument('--json', action='store_true', help='print the raw JSON')
    check = sub.add_parser('doctor', help='read-only check')
    check.add_argument('--config', help='config file, default: config.json in the install directory')
    show = sub.add_parser('rules', help='print the rules that would be loaded on block')
    show.add_argument('--config', help='config file, default: config.json in the install directory')
    show.add_argument('--cache', help='Tailscale address cache file')
    sub.add_parser('disable', help='emergency off: flush rules and stay disabled, also after reboot')
    sub.add_parser('enable', help='remove the disable marker, restore protection')
    sub.add_parser('refresh', help='refresh the Tailscale address cache now')
    sub.add_parser('teardown', help='flush rules and release the PF reference (used by uninstall)')
    args = parser.parse_args(argv)
    paths = Paths()
    if args.command is None:
        parser.print_help()
        return 2
    if args.command == 'status':
        return cmd_status(args, paths)
    if args.command == 'doctor':
        return doctor(args, paths)
    if args.command == 'rules':
        return cmd_rules(args, paths)
    if not require_root():
        return 1
    if args.command == 'daemon':
        return Daemon(paths).serve()
    if args.command == 'disable':
        return disable(paths)
    if args.command == 'enable':
        return enable(paths)
    if args.command == 'refresh':
        return cmd_refresh(args, paths)
    return 0 if teardown(paths) else 1


if __name__ == '__main__':
    sys.exit(main())
