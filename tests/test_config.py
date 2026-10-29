"""配置校验，以及特权文件的所有者和权限检查。"""
import json
import os
from pathlib import Path
import tempfile
import unittest

from support import BASE, MIHOMO, V2_0_CONFIG, guard


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def write(self, name, data):
        path = self.dir / name
        path.write_text(json.dumps(data))
        return path

    def test_example_matches_defaults(self):
        self.assertEqual(guard.load_config(BASE / 'config.example.json'), guard.DEFAULTS)

    def test_example_uses_auto(self):
        cfg = guard.load_config(BASE / 'config.example.json')
        self.assertEqual((cfg['tun_interface'], cfg['mihomo_path']), ('auto', 'auto'))

    def test_local_overrides_example(self):
        local = self.write('local.json', {'tun_interface': 'utun9', 'probe_addresses': ['9.9.9.9']})
        cfg = guard.merge_config_files(BASE / 'config.example.json', local)
        self.assertEqual(cfg['tun_interface'], 'utun9')
        self.assertEqual(cfg['probe_addresses'], ['9.9.9.9'])
        self.assertEqual(cfg['mihomo_path'], guard.AUTO)

    def test_missing_fields_use_defaults(self):
        self.assertEqual(guard.validate_config({'version': 2}), guard.DEFAULTS)

    def test_v2_0_config_still_valid(self):
        # 2.0 装好的配置原样可用，升级时守护进程读到它不会断网。
        path = self.write('config.json', V2_0_CONFIG)
        self.assertEqual(guard.load_config(path), V2_0_CONFIG)

    def test_core_path_forms(self):
        cases = [
            ('auto', 'auto'),
            ('', 'auto'),
            (MIHOMO, MIHOMO),
            ([MIHOMO], [MIHOMO]),
            ([MIHOMO, '/opt/homebrew/bin/mihomo'], [MIHOMO, '/opt/homebrew/bin/mihomo']),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(guard.validate_config({'mihomo_path': value})['mihomo_path'], expected)

    def test_tun_forms(self):
        for value in ('auto', 'utun0', 'utun1500', 'utun99999'):
            with self.subTest(value=value):
                self.assertEqual(guard.validate_config({'tun_interface': value})['tun_interface'], value)

    def test_rejects_bad_values(self):
        bad = [
            [],
            {'version': 1},
            {'version': True},
            {'uid': 501},
            {'tun_interface': 'en0'},
            {'tun_interface': 'utun1500 all; pass'},
            {'tun_interface': 'Auto'},
            {'tun_interface': ''},
            {'tun_interface': None},
            {'tun_interface': ['utun1500']},
            {'mihomo_path': 'mihomo'},
            {'mihomo_path': 'AUTO'},
            {'mihomo_path': '/a\nb'},
            {'mihomo_path': None},
            {'mihomo_path': 5},
            {'mihomo_path': []},
            {'mihomo_path': ['mihomo']},
            {'mihomo_path': ['auto']},
            {'mihomo_path': [MIHOMO, 5]},
            {'mihomo_path': ['/x' * 600]},
            {'mihomo_path': ['/opt/mihomo'] * (guard.MAX_CORE_PATHS + 1)},
            {'mihomo_path': {'path': MIHOMO}},
            {'probe_addresses': []},
            {'probe_addresses': ['192.168.1.1']},
            {'probe_addresses': ['198.18.0.1']},
            {'probe_addresses': ['2606:4700:4700::1111']},
            {'probe_addresses': ['001.1.1.1']},
            {'probe_addresses': ['1.1.1.1'] * 9},
            {'tailscale_refresh_hours': 0},
            {'tailscale_refresh_hours': 169},
            {'tailscale_refresh_hours': True},
        ]
        for value in bad:
            data = value if not isinstance(value, dict) else dict({'version': 2}, **value)
            with self.subTest(value=value):
                with self.assertRaises(guard.ConfigError):
                    guard.validate_config(data)

    def test_v1_config_is_rejected(self):
        v1 = {'version': 1, 'uid': 501, 'tun': 'utun1500', 'core_path': MIHOMO,
              'allow_connected_lan': True, 'tailscale': None}
        with self.assertRaises(guard.ConfigError):
            guard.validate_config(v1)

    def test_missing_or_broken_file(self):
        with self.assertRaises(guard.ConfigError):
            guard.load_config(self.dir / 'nope.json')
        broken = self.dir / 'broken.json'
        broken.write_text('{')
        with self.assertRaises(guard.ConfigError):
            guard.load_config(broken)

    @unittest.skipIf(os.geteuid() == 0, '以 root 运行时文件本来就属于 root')
    def test_secure_load_rejects_user_owned_file(self):
        path = self.write('config.json', {'version': 2})
        with self.assertRaises(guard.ConfigError):
            guard.load_config(path, secure=True)


class TrustTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def test_system_directories(self):
        for path in ('/', '/Library', '/Library/LaunchDaemons', '/private/var/run', '/private/var/log'):
            with self.subTest(path=path):
                guard.check_trusted(path, True)

    def test_rejects_symlink_and_wrong_type(self):
        link = self.dir / 'link'
        os.symlink('/etc/hosts', str(link))
        with self.assertRaises(guard.GuardError):
            guard.check_trusted(link)
        with self.assertRaises(guard.GuardError):
            guard.check_trusted('/etc/hosts', True)

    @unittest.skipIf(os.geteuid() == 0, '以 root 运行时文件本来就属于 root')
    def test_rejects_user_owned(self):
        path = self.dir / 'file'
        path.write_text('x')
        with self.assertRaises(guard.GuardError):
            guard.check_trusted(path)


if __name__ == '__main__':
    unittest.main()
