#!/usr/bin/python3
"""卸载 AccountNetGuard v2：停掉守护进程，清空规则，释放 PF 引用。

    sudo /usr/bin/python3 -I uninstall.py

安装目录里的配置、地址缓存和归档（含 v1 的启动项）都留着，日志也留着。
卸载不会恢复 v1，回滚步骤见 docs/recovery.md。
"""
import importlib.util
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parent / 'src' / 'accountnetguard.py'


def load_guard(path=SOURCE):
    spec = importlib.util.spec_from_file_location('accountnetguard', str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load_guard()


def uninstall(paths=None, run=None, out=print, plist=None):
    paths = paths or guard.Paths()
    run = run or guard.run
    plist = Path(plist or guard.PLIST)
    # 先写停用标记：bootout 万一失败，还在运行的守护进程也不会再加载规则。
    wrote_marker = False
    if os.path.isdir(str(paths.root)) and not guard.marker_exists(paths):
        guard.atomic_write(paths.marker, b'uninstalling\n', 0o644)
        wrote_marker = True
    target = 'system/' + guard.LABEL
    stopped = True
    if run([guard.LAUNCHCTL, 'print', target]).ok:
        result = run([guard.LAUNCHCTL, 'bootout', target], timeout=30)
        stopped = result.ok or not run([guard.LAUNCHCTL, 'print', target]).ok
        out('stop daemon: %s' % ('done' if stopped else result.brief()))
    else:
        out('daemon is not running')
    flushed = guard.teardown(paths, run, out)
    if os.path.lexists(str(plist)):
        moved = guard.archive_file(plist, paths.archive)
        out('moved launchd plist to %s' % moved)
    try:
        os.unlink(str(paths.status))
    except OSError:
        pass
    if wrote_marker and stopped:
        os.unlink(str(paths.marker))
    if not stopped:
        out('daemon did not stop. Disable marker %s is kept, so it loads no rules; it will not start after reboot.' % paths.marker)
    out('kept install directory %s and log %s; delete them by hand once no longer needed' % (paths.root, paths.log))
    if os.path.isdir(str(paths.archive)) and any(
            name.startswith(label + '.plist') for name in os.listdir(str(paths.archive)) for label in guard.OLD_LABELS):
        out('v1, stopped when v2 was installed, is not restored. To go back, see the v1 rollback section in docs/recovery.md.')
    return 0 if stopped and flushed else 1


def main():
    if sys.platform != 'darwin' or os.geteuid() != 0:
        print('run it on macOS as sudo /usr/bin/python3 -I uninstall.py', file=sys.stderr)
        return 1
    return uninstall()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as exc:
        print('uninstall stopped: %s' % exc, file=sys.stderr)
        print('emergency off: sudo /sbin/pfctl -a %s -F rules, see docs/recovery.md' % guard.ANCHOR, file=sys.stderr)
        sys.exit(1)
