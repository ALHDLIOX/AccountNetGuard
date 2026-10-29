"""安装、迁移和卸载的逻辑。launchctl、pfctl 由 FakeSystem 模拟，路径全部换成临时目录。"""
import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock

from support import BASE, BOOT, BOOT_TEXT, BOOT_TIME, MIHOMO, V2_0_CONFIG, FakeSystem, guard, load, make_paths

installer = load('accountnetguard_install', BASE / 'install.py')
installer.guard = guard
uninstaller = load('accountnetguard_uninstall', BASE / 'uninstall.py')
uninstaller.guard = guard

OLD_TOKEN = '18446744073709000100'
OWN_TOKEN = '18446744073709000200'
OLD_LABEL = 'org.accountnetguard.daemon'


class NamingTests(unittest.TestCase):
    def test_v2_names_do_not_collide_with_v1(self):
        self.assertNotIn(guard.LABEL, guard.OLD_LABELS)
        self.assertNotEqual(guard.ANCHOR, guard.OLD_ANCHOR)
        self.assertNotEqual(guard.ROOT, guard.OLD_ROOT)
        self.assertNotEqual(guard.STATE, guard.OLD_STATE)
        self.assertNotEqual(str(guard.LOG), '/private/var/log/AccountNetGuard.log')

    def test_names_stay_the_same_for_in_place_upgrade(self):
        self.assertEqual(guard.LABEL, 'org.accountnetguard2.daemon')
        self.assertEqual(guard.ANCHOR, 'com.apple/010.accountnetguard2')
        self.assertEqual(str(guard.ROOT), '/Library/Application Support/AccountNetGuard2')
        self.assertEqual(str(guard.STATE), '/private/var/run/AccountNetGuard2')
        self.assertEqual(str(guard.PLIST), '/Library/LaunchDaemons/org.accountnetguard2.daemon.plist')
        self.assertEqual(guard.OLD_LABELS, (OLD_LABEL,))
        self.assertEqual(guard.OLD_ANCHOR, 'com.apple/002.account-uid-guard')

    def test_anchor_is_evaluated_before_apple_anchors(self):
        names = ['250.ApplicationFirewall', '200.AirDrop', guard.ANCHOR.split('/', 1)[1]]
        self.assertEqual(sorted(names)[0], guard.ANCHOR.split('/', 1)[1])
        self.assertTrue(guard.ANCHOR.startswith('com.apple/'))

    def test_plist(self):
        data = installer.plist_data()
        self.assertEqual(plistlib.loads(plistlib.dumps(data)), data)
        self.assertEqual(data['Label'], guard.LABEL)
        self.assertEqual(data['ProgramArguments'],
                         ['/usr/bin/python3', '-I', '-B', str(guard.INSTALLED), 'daemon'])
        self.assertIs(data['KeepAlive'], True)
        self.assertIs(data['RunAtLoad'], True)
        self.assertEqual(data['UserName'], 'root')
        self.assertLessEqual(data['ThrottleInterval'], 5)
        self.assertEqual(data['StandardOutPath'], str(guard.LOG))

    @unittest.skipIf(os.geteuid() == 0, '以 root 运行时这一步会继续往下检查')
    def test_preflight_needs_root(self):
        with self.assertRaises(installer.InstallError):
            installer.preflight(None)


def v1_state(**fields):
    """v1 的 state.json：boot_id 是 kern.boottime 的原文。"""
    data = {'boot_id': BOOT_TEXT, 'uid': 501, 'phase': 'active', 'enable_started': True}
    data.update(fields)
    return data


class OldTokenPlanTests(unittest.TestCase):
    def state(self, **fields):
        return v1_state(**fields)

    def plan(self, data, text='pf enabled\nToken : %s\n' % OLD_TOKEN, boot=BOOT_TIME, own=OWN_TOKEN, done=()):
        return installer.old_token_plan(data, text, boot, own, done)

    def test_release_active_old_token(self):
        self.assertEqual(self.plan(self.state())[0], OLD_TOKEN)

    def test_last_token_wins(self):
        text = 'Token : 1\nToken : %s\n' % OLD_TOKEN
        self.assertEqual(self.plan(self.state(), text=text)[0], OLD_TOKEN)

    def test_token_recorded_in_state_file(self):
        self.assertEqual(self.plan(self.state(token=OLD_TOKEN, released=False), text='')[0], OLD_TOKEN)

    def test_refusals(self):
        cases = {
            'no state': (None, {}),
            'no token': (self.state(), {'text': ''}),
            'other boot': (self.state(boot_id='{ sec = 1700000000, usec = 1 } Tue'), {}),
            'no boot id': (self.state(boot_id=None), {}),
            'unknown boot now': (self.state(), {'boot': None}),
            'released': (self.state(released=True), {}),
            'recovered': (self.state(phase='recovered'), {}),
            'released, token in state': (self.state(token=OLD_TOKEN, released=True), {'text': ''}),
            'own token': (self.state(), {'own': OLD_TOKEN}),
            'done': (self.state(), {'done': [OLD_TOKEN]}),
        }
        for name, (data, extra) in cases.items():
            with self.subTest(name=name):
                token, why = self.plan(data, **extra)
                self.assertIsNone(token)
                self.assertTrue(why)


class MigrationCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.paths = make_paths(base / 'v2')
        self.old_state = base / 'old-state'
        self.old_state.mkdir()
        self.daemons = base / 'LaunchDaemons'
        self.daemons.mkdir()
        self.sys = FakeSystem()
        self.sys.tokens, self.sys.enabled = [OLD_TOKEN, OWN_TOKEN], True
        self.paths.token.write_text(json.dumps({'token': OWN_TOKEN, 'boot': BOOT}))
        self.lines = []

    def write_old_state(self, **fields):
        (self.old_state / 'state.json').write_text(json.dumps(v1_state(**fields)))
        (self.old_state / 'enable.txt').write_text('No ALTQ support in kernel\npf enabled\nToken : %s\n' % OLD_TOKEN)

    def output(self):
        return '\n'.join(self.lines)


class ReleaseOldTokenTests(MigrationCase):
    def release(self):
        pf = guard.PF(self.sys)
        return installer.release_old_token(pf, self.sys, self.lines.append, self.paths, self.old_state)

    def test_releases_once(self):
        self.write_old_state()
        self.assertTrue(self.release())
        self.assertEqual(self.sys.tokens, [OWN_TOKEN])
        record = json.loads((self.paths.root / 'migration.json').read_text())
        self.assertEqual(record['released'][0]['token'], OLD_TOKEN)
        # 假设这个值后来被别的程序重新拿到，再跑一次安装也不能再释放。
        self.sys.tokens.append(OLD_TOKEN)
        self.assertTrue(self.release())
        self.assertIn(OLD_TOKEN, self.sys.tokens)
        self.assertEqual(self.sys.count('pf-release'), 1)

    def test_not_listed_is_skipped(self):
        self.write_old_state()
        self.sys.tokens = [OWN_TOKEN]
        self.assertTrue(self.release())
        self.assertEqual(self.sys.count('pf-release'), 0)
        self.assertIn('no longer listed by PF', self.output())

    def test_unreadable_references_is_skipped(self):
        self.write_old_state()
        self.sys.override['pf-refs'] = guard.Result(1, '', 'pfctl: boom\n')
        self.assertFalse(self.release())
        self.assertEqual(self.sys.count('pf-release'), 0)

    def test_already_released_by_v1(self):
        self.write_old_state(released=True, phase='recovered')
        self.assertTrue(self.release())
        self.assertEqual(self.sys.count('pf-release'), 0)
        self.assertIn('already released', self.output())

    def test_no_old_state(self):
        self.assertTrue(self.release())
        self.assertIn('no v1 state', self.output())

    def test_broken_old_state(self):
        (self.old_state / 'state.json').write_text('{')
        self.assertEqual(installer.old_state(self.old_state), (None, ''))

    def test_state_without_enable_file(self):
        (self.old_state / 'state.json').write_text(json.dumps(v1_state(token=OLD_TOKEN)))
        data, text = installer.old_state(self.old_state)
        self.assertEqual((data['token'], text), (OLD_TOKEN, ''))
        self.assertTrue(self.release())
        self.assertEqual(self.sys.tokens, [OWN_TOKEN])


class MigrateTests(MigrationCase):
    def setUp(self):
        super().setUp()
        self.write_old_state()
        self.sys.loaded_labels = {OLD_LABEL}
        (self.daemons / (OLD_LABEL + '.plist')).write_bytes(plistlib.dumps({'Label': OLD_LABEL}))
        self.old_rules = ['block drop out quick proto tcp all user = 501 no state']
        self.sys.anchors[guard.OLD_ANCHOR] = list(self.old_rules)

    def migrate(self):
        return installer.migrate(self.sys, self.lines.append, self.paths, self.daemons, self.old_state)

    def test_full_migration(self):
        self.assertEqual(self.migrate(), [])
        self.assertNotIn(OLD_LABEL, self.sys.loaded_labels)
        self.assertFalse((self.daemons / (OLD_LABEL + '.plist')).exists())
        self.assertTrue((self.paths.archive / (OLD_LABEL + '.plist')).exists())
        self.assertEqual(self.sys.rules(guard.OLD_ANCHOR), '')
        self.assertIn(self.old_rules[0], self.output())
        self.assertEqual(self.sys.tokens, [OWN_TOKEN])

    def test_other_anchors_are_left_alone(self):
        self.sys.anchors['com.apple/250.ApplicationFirewall'] = ['block drop in quick all']
        self.migrate()
        self.assertEqual(self.sys.rules('com.apple/250.ApplicationFirewall'), 'block drop in quick all')
        flushed = {argv[argv.index('-a') + 1] for kind, argv in self.sys.calls if kind == 'pf-flush'}
        self.assertEqual(flushed, {guard.OLD_ANCHOR})

    def test_flush_failure_is_reported(self):
        self.sys.override['pf-flush'] = guard.Result(1, '', 'pfctl: boom\n')
        problems = self.migrate()
        self.assertTrue(any(guard.OLD_ANCHOR in text for text in problems), problems)

    def test_nothing_to_migrate(self):
        self.sys.loaded_labels = set()
        os.unlink(str(self.daemons / (OLD_LABEL + '.plist')))
        os.unlink(str(self.old_state / 'state.json'))
        self.sys.anchors[guard.OLD_ANCHOR] = []
        self.assertEqual(self.migrate(), [])
        self.assertEqual(self.sys.count('launchctl-bootout') + self.sys.count('pf-flush'), 0)

    def test_rerun_is_harmless(self):
        self.migrate()
        calls = len(self.sys.calls)
        self.lines = []
        self.assertEqual(self.migrate(), [])
        self.assertEqual(self.sys.count('pf-release'), 1)
        self.assertEqual(self.sys.count('launchctl-bootout'), 1)
        self.assertGreater(len(self.sys.calls), calls)

    def test_archive_keeps_older_copy(self):
        self.paths.archive.mkdir()
        (self.paths.archive / (OLD_LABEL + '.plist')).write_text('older')
        self.migrate()
        names = sorted(p.name for p in self.paths.archive.iterdir())
        self.assertEqual(len(names), 2)
        self.assertEqual((self.paths.archive / (OLD_LABEL + '.plist')).read_text(), 'older')

    def test_bootout_failure_is_reported(self):
        self.sys.override['launchctl-bootout'] = guard.Result(5, '', 'Boot-out failed: 5: Input/output error\n')
        problems = self.migrate()
        self.assertEqual(len(problems), 1)
        self.assertIn(OLD_LABEL, problems[0])


class StartTests(MigrationCase):
    def fake_daemon_starts(self, mode='allow', protected=True, problems=()):
        def on_bootstrap():
            self.paths.status.write_text(json.dumps({'mode': mode, 'updated': 2000.0, 'pid': os.getpid(),
                                                     'protected': protected, 'problems': list(problems)}))
        self.sys.on_bootstrap = on_bootstrap

    def start(self, cfg=None):
        with mock.patch.object(installer, 'say', self.lines.append):
            return installer.start(self.sys, sleep=lambda s: None, wall=lambda: 1000.0, paths=self.paths, cfg=cfg)

    def test_fresh_start(self):
        self.fake_daemon_starts()
        self.assertEqual(self.start()['mode'], 'allow')
        self.assertEqual(self.sys.count('launchctl-bootout'), 0)
        self.assertIn(guard.LABEL, self.sys.loaded_labels)

    def test_upgrade_restarts(self):
        self.sys.loaded_labels.add(guard.LABEL)
        self.fake_daemon_starts('block')
        self.assertEqual(self.start()['mode'], 'block')
        self.assertEqual(self.sys.count('launchctl-bootout'), 1)
        self.assertIn('stop running v2 daemon: done', self.output())

    def test_unprotected_daemon_stops_install(self):
        self.fake_daemon_starts('allow', protected=False, problems=['loading block rules failed, retrying: busy'])
        with self.assertRaises(installer.InstallError) as caught:
            self.start()
        self.assertIn('v1 left running', str(caught.exception))
        self.assertIn('loading block rules failed', str(caught.exception))

    def test_disabled_daemon_stops_install(self):
        self.fake_daemon_starts('disabled', protected=False)
        with self.assertRaises(installer.InstallError) as caught:
            self.start()
        self.assertIn('enable', str(caught.exception))

    def test_stale_status_is_not_accepted(self):
        self.paths.status.write_text(json.dumps({'mode': 'allow', 'updated': 10.0, 'pid': 1}))
        with self.assertRaises(installer.InstallError):
            self.start()

    def test_config_written_after_old_daemon_stops(self):
        # 2.0 的守护进程每 30 秒重读配置，读到 "auto" 会当成配置无效而断网，所以要等它停了再写。
        self.paths.config.write_text(json.dumps(V2_0_CONFIG))
        self.sys.loaded_labels.add(guard.LABEL)
        seen = []

        def bootout(argv, input):
            seen.append(json.loads(self.paths.config.read_text()))
            self.sys.loaded_labels.discard(guard.LABEL)
            return guard.Result(0, '', '')
        self.sys.override['launchctl-bootout'] = bootout
        self.fake_daemon_starts()
        cfg = dict(guard.DEFAULTS)
        self.start(cfg)
        self.assertEqual(seen, [V2_0_CONFIG])
        self.assertEqual(json.loads(self.paths.config.read_text()), cfg)
        self.assertIn('wrote config', self.output())

    def test_old_daemon_that_will_not_stop_keeps_old_config(self):
        self.paths.config.write_text(json.dumps(V2_0_CONFIG))
        self.sys.loaded_labels.add(guard.LABEL)
        self.sys.override['launchctl-bootout'] = guard.Result(0, '', '')
        with self.assertRaises(installer.InstallError) as caught:
            self.start(dict(guard.DEFAULTS))
        self.assertIn('did not stop', str(caught.exception))
        self.assertEqual(json.loads(self.paths.config.read_text()), V2_0_CONFIG)
        self.assertEqual(self.sys.count('launchctl-bootstrap'), 0)

    def test_fresh_install_writes_config(self):
        self.fake_daemon_starts()
        self.start(dict(guard.DEFAULTS))
        self.assertEqual(json.loads(self.paths.config.read_text()), guard.DEFAULTS)

    def test_bootstrap_failure(self):
        self.sys.override['launchctl-bootstrap'] = guard.Result(5, '', 'Bootstrap failed: 5\n')
        with self.assertRaises(installer.InstallError):
            self.start()
        self.assertEqual(self.sys.count('launchctl-bootstrap'), 5)


class CheckConfigTests(unittest.TestCase):
    """安装前的配置检查：列出改动，识别不到时给提示，新配置会马上断网而旧配置不会时停下。"""

    def setUp(self):
        self.sys = FakeSystem()
        self.lines = []
        self.auto = dict(guard.DEFAULTS)
        self.old = guard.validate_config(V2_0_CONFIG)

    def check(self, cfg, old=None, clients=()):
        return installer.check_config(cfg, old, self.sys, list(clients), self.lines.append)

    def output(self):
        return '\n'.join(self.lines)

    def test_upgrade_from_v2_0_to_auto(self):
        health = self.check(self.auto, self.old)
        self.assertTrue(health.ok)
        self.assertIn('tun_interface: "utun1500" -> "auto"', self.output())
        self.assertIn('mihomo_path: "%s" -> "auto"' % MIHOMO, self.output())
        self.assertIn('config.local.json', self.output())
        self.assertIn('core: Clash Party, pid 881, %s' % MIHOMO, self.output())
        self.assertIn('TUN interface: utun1500 (auto)', self.output())
        self.assertIn('nothing is blocked after install', self.output())

    def test_same_config_lists_no_changes(self):
        self.check(self.old, dict(self.old))
        self.assertNotIn('config differs from the installed one', self.output())
        self.assertIn('TUN interface: utun1500 (from config)', self.output())

    def test_refuses_when_only_the_installed_config_works(self):
        custom = '/opt/clash/clash-core'
        self.sys.core = custom
        old = guard.validate_config(dict(V2_0_CONFIG, mihomo_path=custom))
        with self.assertRaises(installer.InstallError) as caught:
            self.check(self.auto, old)
        self.assertIn('but the installed config does', str(caught.exception))

    def test_both_failing_only_warns(self):
        self.sys.mihomo = False
        health = self.check(self.auto, self.old, [('Clash Party', 'turn on TUN')])
        self.assertFalse(health.ok)
        self.assertIn('the Mac is blocked at once', self.output())
        self.assertIn('Clash Party is installed: turn on TUN.', self.output())

    def test_fresh_install_without_clash(self):
        self.sys.mihomo = False
        self.check(self.auto)
        self.assertIn('no known client found', self.output())
        self.assertNotIn('config differs from the installed one', self.output())

    def test_missing_configured_paths_are_flagged(self):
        cfg = guard.validate_config({'mihomo_path': ['/nonexistent/mihomo', MIHOMO]})
        self.check(cfg)
        self.assertIn('/nonexistent/mihomo in mihomo_path does not exist', self.output())


class InstalledConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'config.json'

    def test_reads_v2_0_config(self):
        self.path.write_text(json.dumps(V2_0_CONFIG))
        self.assertEqual(installer.installed_config(self.path), V2_0_CONFIG)

    def test_missing_or_broken_is_none(self):
        self.assertIsNone(installer.installed_config(self.path))
        self.path.write_text('{')
        self.assertIsNone(installer.installed_config(self.path))

    def test_changes(self):
        self.assertEqual(installer.config_changes(V2_0_CONFIG, dict(V2_0_CONFIG)), [])
        changes = installer.config_changes(V2_0_CONFIG, guard.DEFAULTS)
        self.assertEqual(len(changes), 2)


class UninstallTests(MigrationCase):
    def setUp(self):
        super().setUp()
        self.sys.tokens = [OWN_TOKEN]
        self.sys.loaded_labels = {guard.LABEL}
        self.sys.anchors[guard.ANCHOR] = ['block return out quick inet all']
        self.plist = self.daemons / (guard.LABEL + '.plist')
        self.plist.write_bytes(plistlib.dumps(installer.plist_data()))
        self.paths.status.write_text('{}')

    def uninstall(self):
        return uninstaller.uninstall(self.paths, self.sys, self.lines.append, self.plist)

    def test_uninstall(self):
        self.assertEqual(self.uninstall(), 0, self.output())
        self.assertNotIn(guard.LABEL, self.sys.loaded_labels)
        self.assertEqual(self.sys.rules(), '')
        self.assertEqual(self.sys.tokens, [])
        self.assertFalse(self.plist.exists())
        self.assertTrue((self.paths.archive / self.plist.name).exists())
        self.assertFalse(self.paths.status.exists())
        self.assertFalse(self.paths.marker.exists())
        self.assertTrue(self.paths.root.exists())

    def test_marker_written_before_bootout(self):
        seen = []

        def bootout(argv, input):
            seen.append(self.paths.marker.exists())
            self.sys.loaded_labels.discard(guard.LABEL)
            return guard.Result(0, '', '')
        self.sys.override['launchctl-bootout'] = bootout
        self.uninstall()
        self.assertEqual(seen, [True])

    def test_bootout_failure_keeps_marker(self):
        self.sys.override['launchctl-bootout'] = guard.Result(5, '', 'Boot-out failed\n')
        self.assertEqual(self.uninstall(), 1)
        self.assertTrue(self.paths.marker.exists())
        self.assertEqual(self.sys.rules(), '')

    def test_user_disable_marker_is_kept(self):
        self.paths.marker.write_text('disabled by user\n')
        self.uninstall()
        self.assertEqual(self.paths.marker.read_text(), 'disabled by user\n')

    def test_rollback_hint_only_after_v1_migration(self):
        self.uninstall()
        self.assertNotIn('v1 rollback', self.output())
        self.paths.archive.mkdir(exist_ok=True)
        (self.paths.archive / (OLD_LABEL + '.plist')).write_text('v1')
        self.lines = []
        self.uninstall()
        self.assertIn('v1 rollback', self.output())


if __name__ == '__main__':
    unittest.main()
