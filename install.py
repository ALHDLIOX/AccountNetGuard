#!/usr/bin/python3
"""安装或升级 AccountNetGuard v2，并停掉 v1。可以重复运行。

    sudo /usr/bin/python3 -I install.py
    sudo /usr/bin/python3 -I install.py --config /path/to/config.local.json

不加 --config 时，仓库根目录有 config.local.json 就用它覆盖 config.example.json 里的字段。
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import sys
import time

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent
SOURCE = BASE / 'src' / 'accountnetguard.py'
EXAMPLE = BASE / 'config.example.json'
LOCAL = BASE / 'config.local.json'
PLUTIL = '/usr/bin/plutil'
LAUNCH_DAEMONS = Path('/Library/LaunchDaemons')
# 只用来检查 pfctl 能不能解析断网规则，不会加载。
SAMPLE_INFRA = ('199.38.181.104', '2607:f740:f::bc')


def load_guard(path=SOURCE):
    spec = importlib.util.spec_from_file_location('accountnetguard', str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load_guard()


class InstallError(Exception):
    pass


def say(text=''):
    print(text, flush=True)


def plist_data():
    return {
        'Label': guard.LABEL,
        'ProgramArguments': [guard.PYTHON, '-I', '-B', str(guard.INSTALLED), 'daemon'],
        'RunAtLoad': True,
        'KeepAlive': True,
        'ThrottleInterval': 2,
        'ProcessType': 'Interactive',
        'UserName': 'root',
        'WorkingDirectory': str(guard.ROOT),
        'StandardOutPath': str(guard.LOG),
        'StandardErrorPath': str(guard.LOG),
        'EnvironmentVariables': {'PATH': guard.ENV['PATH'], 'LANG': 'en_US.UTF-8'},
    }


def config_bytes(cfg):
    return (json.dumps(cfg, indent=2, ensure_ascii=False) + '\n').encode('utf-8')


def loaded(label, run):
    return run([guard.LAUNCHCTL, 'print', 'system/' + label]).ok


def installed_config(path=None):
    """读已安装的配置。没有或读不了返回 None。"""
    try:
        return guard.load_config(path or guard.Paths().config)
    except guard.ConfigError:
        return None


def config_changes(old, new):
    show = lambda value: json.dumps(value, ensure_ascii=False)
    return ['%s: %s -> %s' % (key, show(old.get(key)), show(new.get(key)))
            for key in guard.DEFAULTS if old.get(key) != new.get(key)]


def describe(health):
    """识别结果，每项一行。"""
    lines = ['core: %s' % guard.core_text([core.data() for core in health.cores])]
    lines.append('TUN interface: %s' % guard.tun_text(health.tun, health.auto_tun))
    return lines


# ---------------------------------------------------------------- 第 1 步：检查

def check_config(cfg, old, run, clients=None, out=say):
    """列出配置改了什么、识别到了什么，返回检测结果。

    old 是已安装的配置（没有就是 None）。新配置识别不到 Clash TUN、已安装的配置却可以时
    停下来，不然一装上就会断网。
    """
    changes = config_changes(old, cfg) if old else []
    if changes:
        out('config differs from the installed one:')
        for line in changes:
            out('  ' + line)
        out('to keep the old values, put them in config.local.json in the repository root and run install.py again')
    core = cfg['mihomo_path']
    for path in ([] if core == guard.AUTO else [core] if isinstance(core, str) else core):
        if not os.path.exists(path):
            out('note: %s in mihomo_path does not exist; with a wrong path the daemon stays blocked' % path)
    health = guard.inspect(cfg, run)
    for line in describe(health):
        out(line)
    if health.ok:
        out('Clash TUN: ok, nothing is blocked after install')
        return health
    if changes and guard.inspect(old, run).ok:
        raise InstallError('the new config does not detect Clash TUN (%s) but the installed config does, '
                           'so installing would block at once. To keep the installed config, put the old values '
                           'listed above in config.local.json and install again' % health.reason)
    out('warning: Clash TUN is not ok (%s); after install the Mac is blocked at once, only LAN and Tailscale work' % health.reason)
    for line in guard.setup_hints(health, cfg, guard.installed_clients() if clients is None else clients):
        out('  ' + line)
    return health


def preflight(local, run=None, clients=None, installed=None):
    """installed 是已安装的配置，默认读安装目录里的 config.json。"""
    run = run or guard.run
    if sys.platform != 'darwin':
        raise InstallError('macOS only')
    if os.geteuid() != 0:
        raise InstallError('run it as sudo /usr/bin/python3 -I install.py')
    if sys.version_info < (3, 9):
        raise InstallError('needs Python 3.9 or later, run it with /usr/bin/python3')
    payload = SOURCE.read_bytes()
    compile(payload, str(SOURCE), 'exec')
    cfg = guard.merge_config_files(EXAMPLE, local)
    say('config: %s%s' % (EXAMPLE, ', overridden by %s' % local if local else ''))
    for directory in (guard.ROOT.parent, LAUNCH_DAEMONS, guard.LOG.parent, guard.STATE.parent):
        guard.check_tree(directory, True)
    pf = guard.PF(run)
    ok, detail = pf.check(guard.block_rules(['utun9'], SAMPLE_INFRA))
    if not ok:
        raise InstallError('pfctl rejects the generated block rules: %s' % detail)
    if guard.MAIN_ANCHOR_RULE not in pf.main_rules().splitlines():
        raise InstallError('PF main ruleset lacks %s, block rules would not take effect. '
                           'Restore /etc/pf.conf to the system default first' % guard.MAIN_ANCHOR_RULE)
    say('pfctl check: passed, main ruleset has %s' % guard.MAIN_ANCHOR_RULE)
    check_config(cfg, installed_config() if installed is None else installed, run, clients)
    if guard.marker_exists(guard.Paths()):
        say('warning: disable marker %s is present, nothing is blocked after install; run enable to restore protection' % guard.Paths().marker)
    return payload, cfg


# ---------------------------------------------------------------- 第 2 步：复制文件

def install_files(payload, run=None):
    """写程序和启动项。配置要等旧的守护进程停了再写（见 start），旧代码读不懂新配置。"""
    run = run or guard.run
    root = str(guard.ROOT)
    if os.path.lexists(root):
        if os.path.islink(root) or not os.path.isdir(root):
            raise InstallError('%s exists but is not a directory' % root)
    else:
        os.mkdir(root, 0o755)
    os.chown(root, 0, 0)
    os.chmod(root, 0o755)
    guard.check_tree(guard.ROOT, True)
    guard.atomic_write(guard.INSTALLED, payload, 0o644)
    guard.atomic_write(guard.PLIST, plistlib.dumps(plist_data()), 0o644)
    result = run([PLUTIL, '-lint', str(guard.PLIST)])
    if not result.ok:
        raise InstallError('plist check failed: %s' % result.brief())
    say('wrote %s and %s, config is written in step 4' % (guard.INSTALLED, guard.PLIST))


# ---------------------------------------------------------------- 第 3 步：Tailscale 地址

def refresh(run=None):
    run = run or guard.run
    result = run([guard.PYTHON, '-I', '-B', str(guard.INSTALLED), 'refresh'], timeout=90)
    for line in result.out.splitlines():
        say('  ' + line)
    if not result.ok:
        say('not all Tailscale server addresses were fetched (%s). The daemon retries every 30 minutes '
            'while allowing; without a cache, Tailscale only keeps tunnels that are already up during block.'
            % result.brief())
    return result.ok


# ---------------------------------------------------------------- 第 4 步：启动

def start(run=None, sleep=time.sleep, wall=time.time, paths=None, cfg=None):
    """停掉正在运行的 v2 守护进程，写配置，再启动新的。

    旧的守护进程每 30 秒重读一次配置，旧代码不认 "auto"，读到会按配置无效断网，
    所以配置要等它停了才写。
    """
    run = run or guard.run
    paths = paths or guard.Paths()
    began = wall()
    if loaded(guard.LABEL, run):
        result = run([guard.LAUNCHCTL, 'bootout', 'system/' + guard.LABEL], timeout=30)
        say('stop running v2 daemon: %s, rules stay until the new one takes over' % ('done' if result.ok else result.brief()))
        for _ in range(20):
            if not loaded(guard.LABEL, run):
                break
            sleep(0.5)
        else:
            raise InstallError('the running v2 daemon did not stop within 10 s, config left unchanged. Run install.py again later')
    if cfg is not None:
        guard.atomic_write(paths.config, config_bytes(cfg), 0o644)
        say('wrote config %s' % paths.config)
    result = None
    for _ in range(5):
        result = run([guard.LAUNCHCTL, 'bootstrap', 'system', str(guard.PLIST)], timeout=30)
        if result.ok:
            break
        sleep(1.0)
    else:
        raise InstallError('launchctl bootstrap failed: %s' % result.brief())
    say('started %s' % guard.LABEL)
    data = None
    for _ in range(40):
        try:
            fresh = guard.read_json(paths.status, 1024 * 1024)
        except (OSError, ValueError):
            fresh = None
        if isinstance(fresh, dict) and fresh.get('updated', 0) >= began and fresh.get('mode') in guard.MODE_TEXT:
            data = fresh
            if data['mode'] == 'disabled':
                raise InstallError('v2 is disabled, v1 left running. Run enable, then install again')
            if data.get('protected') is True:
                return data
        sleep(0.25)
    if data is None:
        raise InstallError('the daemon wrote no status file within 10 s, check the log %s' % guard.LOG)
    raise InstallError('v2 did not confirm its rules within 10 s, v1 left running: %s' % (
        '; '.join(data.get('problems') or []) or 'mode %s' % data['mode']))


# ---------------------------------------------------------------- 第 5 步：停掉 v1

def old_state(directory=None):
    """读 v1 的运行状态 state.json 和 enable.txt（pfctl -E 的输出）。"""
    directory = Path(directory or guard.OLD_STATE)
    data, text = None, ''
    try:
        data = guard.read_json(directory / 'state.json', 1024 * 1024)
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        return None, ''
    try:
        with open(str(directory / 'enable.txt'), 'rb') as stream:
            text = stream.read(64 * 1024).decode('utf-8', 'replace')
    except OSError:
        pass
    return data, text


def old_token_plan(data, text, boot, own=None, done=()):
    """决定要不要释放 v1 申请的 PF 引用。返回 (token 或 None, 说明)。

    只释放本次开机内、v1 自己记下且没释放过的那个 token。来历对不上的一律不动：
    多留一个引用只是让 PF 保持启用，释放错了才会伤到别的程序。
    """
    if not isinstance(data, dict):
        return None, 'no v1 state, skipped'
    tokens = guard.TOKEN.findall(text or '')
    if not tokens and re.fullmatch(r'\d+', str(data.get('token', ''))):
        tokens = [str(data['token'])]
    if not tokens:
        return None, 'v1 recorded no token, skipped'
    try:
        old_boot = guard.parse_boottime(str(data.get('boot_id', '')))
    except guard.DetectError:
        return None, 'v1 state has no boot ID, not released'
    if not boot or old_boot != boot:
        return None, 'v1 token is from a previous boot, not released'
    # v1 恢复时先释放 token，记下 released，再把 phase 改成 recovered。
    if data.get('released') or data.get('phase') == 'recovered':
        return None, 'v1 already released it, skipped'
    token = tokens[-1]
    if own is not None and token == str(own):
        return None, 'same as the v2 token, not released'
    if token in done:
        return None, 'already released during this boot, skipped'
    return token, 'release token %s' % token


def load_record(path):
    try:
        data = guard.read_json(path, 1024 * 1024)
    except (OSError, ValueError):
        return {'released': []}
    if not isinstance(data, dict) or not isinstance(data.get('released'), list):
        return {'released': []}
    return data


def release_old_token(pf, run, out=say, paths=None, state=None):
    paths = paths or guard.Paths()
    data, text = old_state(state)
    # v1 记的是 kern.boottime，只能拿同一种值比。开机后校时过的话对不上，就不释放，这是安全的一边。
    try:
        boot = guard.boottime(run)
    except guard.DetectError:
        boot = None
    own = (guard.TokenFile(paths.token).load() or {}).get('token')
    record_path = paths.root / 'migration.json'
    record = load_record(record_path)
    done = [str(item.get('token')) for item in record['released']
            if isinstance(item, dict) and item.get('boot') == boot]
    token, why = old_token_plan(data, text, boot, own, done)
    if token is None:
        out('v1 PF reference: %s' % why)
        return True
    listed = pf.token_listed(token)
    if listed is False:
        out('v1 PF reference: token %s no longer listed by PF, skipped' % token)
        return True
    if listed is None:
        out('v1 PF reference: cannot list PF references, token %s not released yet' % token)
        return False
    # 先记下再释放：中途出错也不会在下次运行时重复释放同一个值。
    record['released'].append({'token': token, 'boot': boot, 'time': time.time()})
    guard.atomic_write(record_path, json.dumps(record, indent=1).encode(), 0o644)
    if not pf.release(token):
        out('v1 PF reference: releasing token %s failed, PF stays enabled until the next reboot, which is harmless' % token)
        return True
    out('v1 PF reference: released token %s' % token)
    return True


def flush_old_anchor(pf, out=say, anchor=None):
    """清空 v1 的 anchor。v1 的规则按 UID 匹配，留着就有内核死锁的风险。"""
    anchor = anchor or guard.OLD_ANCHOR
    try:
        left = pf.rules(anchor)
    except guard.DetectError:
        return True
    if not left:
        return True
    out('v1 anchor %s has %d rules:' % (anchor, len(left.splitlines())))
    for line in left.splitlines():
        out('    ' + line)
    flushed = pf.flush(anchor)
    try:
        flushed = flushed and not pf.rules(anchor)
    except guard.DetectError:
        flushed = False
    out('  flush: %s' % ('done' if flushed else 'failed'))
    return flushed


def migrate(run=None, out=say, paths=None, daemons=LAUNCH_DAEMONS, state=None):
    run = run or guard.run
    paths = paths or guard.Paths()
    pf = guard.PF(run)
    problems = []
    for label in guard.OLD_LABELS:
        if loaded(label, run):
            result = run([guard.LAUNCHCTL, 'bootout', 'system/' + label], timeout=30)
            if result.ok or not loaded(label, run):
                out('stopped v1 job %s' % label)
            else:
                problems.append('cannot stop v1 job %s: %s' % (label, result.brief()))
        plist = Path(daemons) / (label + '.plist')
        if os.path.lexists(str(plist)):
            target = guard.archive_file(plist, paths.archive)
            out('moved v1 launchd plist %s to %s, v1 will not start after reboot' % (plist, target))
    if not flush_old_anchor(pf, out):
        problems.append('v1 anchor %s not flushed' % guard.OLD_ANCHOR)
    if not release_old_token(pf, run, out, paths, state):
        problems.append('v1 PF reference not handled')
    return problems


# ---------------------------------------------------------------- 入口

def main(argv=None):
    parser = argparse.ArgumentParser(description='Install or upgrade AccountNetGuard v2, which blocks this Mac when '
                                                 'Clash TUN is not working, and stop v1.')
    parser.add_argument('--config', help='local config whose fields override config.example.json; '
                        'default: config.local.json in the repository root, if present')
    parser.add_argument('--skip-refresh', action='store_true', help='do not fetch Tailscale server addresses')
    args = parser.parse_args(argv)
    local = Path(args.config) if args.config else (LOCAL if LOCAL.exists() else None)
    say('step 1/6: check')
    payload, cfg = preflight(local)
    say('step 2/6: copy program and launchd plist')
    install_files(payload)
    say('step 3/6: fetch Tailscale server addresses')
    if args.skip_refresh:
        say('skipped')
    else:
        refresh()
    say('step 4/6: write config, start daemon')
    data = start(cfg=cfg)
    say('step 5/6: stop v1')
    problems = migrate()
    say('step 6/6: status')
    try:
        data = guard.read_json(guard.Paths().status, 1024 * 1024)
    except (OSError, ValueError):
        pass
    say(guard.format_status(data, alive=guard.process_alive(data.get('pid'))))
    if problems:
        say('')
        for text in problems:
            say('not done: ' + text)
        say('v2 is running. Handle the items above by hand, see the v1 migration section in docs/recovery.md.')
        return 1
    say('')
    say('installed. Acceptance test: docs/verification.md. Troubleshooting: docs/recovery.md.')
    say('emergency off: sudo %s -I "%s" disable' % (guard.PYTHON, guard.INSTALLED))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as exc:
        print('install stopped: %s' % exc, file=sys.stderr)
        print('finished steps are not rolled back. Fix the problem and run install.py again, or run uninstall.py; '
              'see docs/recovery.md.', file=sys.stderr)
        sys.exit(1)
