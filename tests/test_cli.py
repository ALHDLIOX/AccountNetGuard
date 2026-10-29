"""命令行：disable、enable、teardown、status、doctor、rules。系统命令由 FakeSystem 模拟。"""
import argparse
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

from support import BASE, BOOT, MIHOMO, V2_0_CONFIG, FakeSystem, guard, make_paths, write_config

TOKEN = '18446744073709000007'


class CliCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = make_paths(self.temp.name)
        write_config(self.paths)
        self.sys = FakeSystem()
        self.lines = []

    def hold_token(self, boot=BOOT):
        self.sys.tokens, self.sys.enabled = [TOKEN], True
        self.paths.token.write_text(json.dumps({'token': TOKEN, 'boot': boot}))

    def output(self):
        return '\n'.join(self.lines)


class DisableTests(CliCase):
    def test_disable_flushes_releases_and_marks(self):
        self.sys.anchors[guard.ANCHOR] = ['block return out quick inet all']
        self.hold_token()
        code = guard.disable(self.paths, run=self.sys, sleep=lambda s: None, out=self.lines.append)
        self.assertEqual(code, 0)
        self.assertTrue(self.paths.marker.exists())
        self.assertEqual(self.sys.rules(), '')
        self.assertEqual(self.sys.tokens, [])
        self.assertFalse(self.paths.token.exists())
        self.assertEqual(self.sys.count('pf-flush'), 4)
        self.assertIn('released', self.output())

    def test_disable_releases_own_token_after_clock_step(self):
        # 开机后校时会让 kern.boottime 变，开机标识不能受影响（2026-10-29 真机上 disable 因此没释放 token）
        self.hold_token()
        self.sys.boottime = '{ sec = 1793258160, usec = 1 } Thu Oct 29 00:16:00 2026'
        guard.disable(self.paths, run=self.sys, sleep=lambda s: None, out=self.lines.append)
        self.assertEqual(self.sys.tokens, [])
        self.assertIn(guard.RELEASE_TEXT['released'], self.output())

    def test_disable_never_releases_token_of_another_boot(self):
        self.hold_token(boot='00000000-0000-0000-0000-000000000001')
        guard.disable(self.paths, run=self.sys, sleep=lambda s: None, out=self.lines.append)
        self.assertEqual(self.sys.tokens, [TOKEN])
        self.assertEqual(self.sys.count('pf-release'), 0)
        self.assertIn(guard.RELEASE_TEXT['stale'], self.output())

    def test_disable_skips_token_no_longer_listed(self):
        self.hold_token()
        self.sys.tokens = []
        guard.disable(self.paths, run=self.sys, sleep=lambda s: None, out=self.lines.append)
        self.assertEqual(self.sys.count('pf-release'), 0)
        self.assertIn(guard.RELEASE_TEXT['gone'], self.output())

    def test_disable_still_flushes_without_marker(self):
        shutil.rmtree(str(self.paths.root))
        self.sys.anchors[guard.ANCHOR] = ['block return out quick inet all']
        code = guard.disable(self.paths, run=self.sys, sleep=lambda s: None, out=self.lines.append)
        self.assertEqual(code, 1)
        self.assertEqual(self.sys.rules(), '')
        self.assertIn('writing disable marker failed', self.output())
        self.assertIn('-F rules', self.output())

    def test_disable_reports_flush_failure(self):
        self.sys.override['pf-flush'] = guard.Result(1, '', 'pfctl: boom\n')
        code = guard.disable(self.paths, run=self.sys, sleep=lambda s: None, out=self.lines.append)
        self.assertEqual(code, 1)
        self.assertIn('pfctl -d', self.output())

    def test_failed_release_keeps_token_file(self):
        self.hold_token()
        self.sys.override['pf-release'] = guard.Result(1, '', 'pfctl: boom\n')
        guard.disable(self.paths, run=self.sys, sleep=lambda s: None, out=self.lines.append)
        self.assertTrue(self.paths.token.exists())
        self.assertIn(guard.RELEASE_TEXT['failed'], self.output())
        self.assertEqual([p.name for p in self.paths.state.iterdir()], ['token.json'])

    def test_enable(self):
        self.assertEqual(guard.enable(self.paths, out=self.lines.append), 0)
        self.assertIn('no disable marker', self.output())
        self.paths.marker.write_text('disabled\n')
        self.assertEqual(guard.enable(self.paths, out=self.lines.append), 0)
        self.assertFalse(self.paths.marker.exists())
        self.assertIn('no status file', self.output())

    def test_teardown(self):
        self.sys.anchors[guard.ANCHOR] = ['block return out quick inet all']
        self.hold_token()
        self.assertTrue(guard.teardown(self.paths, run=self.sys, out=self.lines.append))
        self.assertEqual(self.sys.rules(), '')
        self.assertEqual(self.sys.tokens, [])


class StatusTests(CliCase):
    def test_missing_status_file(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = guard.cmd_status(argparse.Namespace(json=False), self.paths)
        self.assertEqual(code, 1)
        self.assertIn('no status file', stream.getvalue())

    def test_status_json(self):
        self.paths.status.write_text(json.dumps({'mode': 'allow', 'updated': 1.0, 'pid': 1}))
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = guard.cmd_status(argparse.Namespace(json=True), self.paths)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stream.getvalue())['mode'], 'allow')

    def test_format_status_warnings(self):
        data = {'mode': 'block', 'reason': 'Clash core is not running', 'since': 1000.0, 'updated': 1000.0, 'pid': 99,
                'tailscale_interfaces': [], 'cache_updated': None,
                'last_error': {'time': 1000.0, 'message': 'load failed'}, 'problems': ['PF main ruleset lacks anchor']}
        text = guard.format_status(data, now=1000.0 + guard.STATUS_STALE + 5, alive=True)
        self.assertIn('mode: block (Clash core is not running)', text)
        self.assertIn('Tailscale interface: none', text)
        self.assertIn('no cache', text)
        self.assertIn('last error: ', text)
        self.assertIn('problem: PF main ruleset lacks anchor', text)
        self.assertIn('status is stale', text)
        self.assertIn('process is gone', guard.format_status(data, now=1000.0, alive=False))

    def test_format_status_shows_detection(self):
        data = {'mode': 'allow', 'reason': 'Clash TUN ok', 'updated': 1000.0, 'pid': 99,
                'cores': [{'pid': 881, 'path': MIHOMO, 'client': 'Clash Party'},
                          {'pid': 882, 'path': '/opt/homebrew/bin/mihomo', 'client': 'Homebrew'}],
                'tun_interface': 'utun1500', 'tun_auto': True, 'tailscale_interfaces': ['utun3']}
        text = guard.format_status(data, now=1000.0, alive=True)
        self.assertIn('core: Clash Party, pid 881, %s (+1 more)' % MIHOMO, text)
        self.assertIn('TUN interface: utun1500 (auto)', text)
        data.update(cores=[], tun_interface=None, mode='block', reason='Clash core is not running')
        text = guard.format_status(data, now=1000.0, alive=True)
        self.assertIn('core: not found', text)
        self.assertIn('TUN interface: not detected (auto)', text)
        data.update(tun_interface='utun1500', tun_auto=False)
        self.assertIn('TUN interface: utun1500 (from config)', guard.format_status(data, now=1000.0, alive=True))

    def test_format_status_of_2_0_status_file(self):
        # 升级过程中可能读到 2.0 写的状态文件，里面没有内核和 TUN 两项。
        data = {'mode': 'allow', 'reason': 'Clash TUN ok', 'updated': 1000.0, 'pid': 99,
                'tailscale_interfaces': ['utun3']}
        text = guard.format_status(data, now=1000.0, alive=True)
        self.assertNotIn('core:', text)
        self.assertNotIn('TUN interface:', text)
        self.assertIn('Tailscale interface: utun3', text)

    def test_format_status_disabled_hides_detection(self):
        data = {'mode': 'disabled', 'reason': 'disable marker present', 'updated': 1000.0, 'pid': 99,
                'cores': [], 'tun_interface': None, 'tun_auto': None}
        text = guard.format_status(data, now=1000.0, alive=True)
        self.assertNotIn('core:', text)
        self.assertNotIn('TUN interface:', text)


class DoctorTests(CliCase):
    def doctor(self, config=None, clients=()):
        args = argparse.Namespace(config=str(config) if config else str(self.paths.config))
        code = guard.doctor(args, self.paths, run=self.sys, out=self.lines.append, clients=list(clients))
        return code

    def test_healthy_machine(self):
        self.assertEqual(self.doctor(), 0, self.output())
        self.assertIn('core (auto): Clash Party, pid 881, %s' % MIHOMO, self.output())
        self.assertIn('TUN interface: utun1500 (auto)', self.output())
        self.assertIn('Clash TUN ok, the daemon will flush rules', self.output())
        self.assertIn('no failures', self.output())
        self.assertNotIn('README', self.output())

    def test_v2_0_config(self):
        self.paths.config.write_text(json.dumps(V2_0_CONFIG))
        self.assertEqual(self.doctor(), 0, self.output())
        self.assertIn('core (from config): Clash Party', self.output())
        self.assertIn('TUN interface: utun1500 (from config)', self.output())

    def test_unhealthy_tun_is_not_an_error(self):
        self.sys.mihomo = False
        self.assertEqual(self.doctor(), 0, self.output())
        self.assertIn('the daemon will block', self.output())
        self.assertIn('core (auto): not found', self.output())
        self.assertIn('TUN interface: not detected (auto)', self.output())

    def test_hints_name_the_installed_client(self):
        self.sys.mihomo = False
        self.doctor(clients=[('Clash Party', 'turn on TUN')])
        self.assertIn('note     Clash Party is installed: turn on TUN.', self.output())
        self.assertIn('ps -axww -o pid=,comm=', self.output())
        self.assertIn('README', self.output())

    def test_hints_without_any_client(self):
        self.sys.mihomo = False
        self.doctor()
        self.assertIn('no known client found', self.output())

    def test_invalid_config(self):
        self.paths.config.write_text('{"version": 3}')
        self.assertEqual(self.doctor(), 1)
        self.assertIn('invalid config', self.output())

    def test_rule_syntax_failure(self):
        self.sys.override['pf-check'] = guard.Result(1, '', 'stdin:1: syntax error\n')
        self.assertEqual(self.doctor(), 1)
        self.assertIn('syntax error', self.output())

    def test_doctor_changes_nothing(self):
        before = sorted(os.listdir(str(self.paths.root))) + sorted(os.listdir(str(self.paths.state)))
        self.doctor()
        after = sorted(os.listdir(str(self.paths.root))) + sorted(os.listdir(str(self.paths.state)))
        self.assertEqual(before, after)
        changing = {'pf-load', 'pf-flush', 'pf-enable', 'pf-release', 'launchctl-bootout', 'launchctl-bootstrap'}
        self.assertFalse(changing & set(self.sys.kinds()))


class SetupHintTests(unittest.TestCase):
    def health(self, ok=False, cores=True, tun='utun1500', auto=True):
        found = [guard.Core(881, MIHOMO, 'Clash Party')] if cores else []
        return guard.Health(ok, 'reason', found, ['utun3'], tun if ok else None, auto)

    def test_installed_clients(self):
        present = {'/Applications/Clash Verge.app', '/Users/someone/Applications/FlClash.app',
                   '/Applications/Mihomo Party.app', '/opt/homebrew/opt/mihomo/bin/mihomo'}
        found = guard.installed_clients(present.__contains__, ['/Applications', '/Users/someone/Applications'])
        self.assertEqual([name for name, _ in found],
                         ['Clash Party', 'Clash Verge Rev', 'FlClash', 'Homebrew mihomo'])
        self.assertTrue(all(how for _, how in found))
        self.assertEqual(guard.installed_clients(lambda path: False, ['/Applications']), [])
        found = guard.installed_clients({'/Applications/ClashX Meta.app'}.__contains__, ['/Applications'])
        self.assertIn('Tun Mode', found[0][1])

    def test_no_hints_when_healthy_or_without_config(self):
        cfg = dict(guard.DEFAULTS)
        self.assertEqual(guard.setup_hints(self.health(ok=True), cfg, []), [])
        self.assertEqual(guard.setup_hints(self.health(), None, []), [])

    def test_hint_for_each_case(self):
        auto = dict(guard.DEFAULTS)
        fixed = guard.validate_config(V2_0_CONFIG)
        cases = [
            (auto, self.health(cores=False), 'ps -axww -o pid=,comm='),
            (fixed, self.health(cores=False), 'exactly'),
            (fixed, self.health(auto=False), 'utun1500 does not qualify'),
            (auto, self.health(), 'route -n get 1.1.1.1'),
        ]
        for cfg, health, needle in cases:
            with self.subTest(needle=needle):
                lines = guard.setup_hints(health, cfg, [('FlClash', 'turn on "TUN"')])
                self.assertEqual(lines[0], 'FlClash is installed: turn on "TUN".')
                self.assertTrue(any(needle in line for line in lines), lines)
                self.assertIn('README', lines[-1])


class MainTests(unittest.TestCase):
    def test_no_command_prints_help(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(guard.main([]), 2)

    @unittest.skipIf(os.geteuid() == 0, '以 root 运行时不会被拦')
    def test_privileged_commands_need_root(self):
        for command in ('daemon', 'disable', 'enable', 'refresh', 'teardown'):
            with self.subTest(command=command):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(guard.main([command]), 1)

    def test_rules_command_prints_block_rules(self):
        stream = io.StringIO()
        args = argparse.Namespace(config=str(BASE / 'config.example.json'), cache='/nonexistent/cache.json')
        with contextlib.redirect_stdout(stream):
            guard.cmd_rules(args, guard.Paths())
        self.assertTrue(stream.getvalue().rstrip().endswith('block return out quick inet6 all'))


if __name__ == '__main__':
    unittest.main()
