"""解析 ps、ifconfig、route、sysctl 和 pfctl 的输出。"""
import unittest

from support import BOOT, BOOT_TEXT, BOOT_TIME, EN0, LO0, MIHOMO, ROUTE_TEXT, TAILSCALE, FakeSystem, guard


class IfconfigTests(unittest.TestCase):
    def setUp(self):
        text = LO0 + EN0 + TAILSCALE.format(name='utun3') + (
            'utun1500: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n'
            '\tinet 198.18.0.1 --> 198.18.0.1 netmask 0xfffffffc\n')
        self.ifaces = guard.parse_ifconfig(text)

    def test_flags_and_addresses(self):
        self.assertIn('UP', self.ifaces['utun1500']['flags'])
        self.assertEqual(self.ifaces['utun1500']['inet'], ['198.18.0.1'])
        self.assertEqual(self.ifaces['en0']['inet'], ['192.168.1.20'])
        self.assertEqual(self.ifaces['utun3']['inet'], ['100.64.10.20'])
        self.assertIn('fd7a:115c:a1e0::a:14', self.ifaces['utun3']['inet6'])
        self.assertIn('fe80::a:b:c:d', self.ifaces['utun3']['inet6'])

    def test_tailscale_interface_found_by_address(self):
        self.assertEqual(guard.tailscale_interfaces(self.ifaces, 'utun1500'), ['utun3'])
        # 自动识别 TUN 时不排除任何网卡：Clash TUN 没有 100.64.0.0/10 的地址，本来就不会算进来。
        self.assertEqual(guard.tailscale_interfaces(self.ifaces), ['utun3'])
        self.assertTrue(guard.has_tailnet_address(self.ifaces['utun3']))
        self.assertFalse(guard.has_tailnet_address(self.ifaces['utun1500']))

    def test_clash_tun_never_counted_as_tailscale(self):
        self.ifaces['utun1500']['inet'].append('100.64.0.1')
        self.assertEqual(guard.tailscale_interfaces(self.ifaces, 'utun1500'), ['utun3'])
        self.assertEqual(guard.tailscale_interfaces(self.ifaces, 'utun3'), ['utun1500'])

    def test_non_utun_with_cgnat_address_ignored(self):
        self.ifaces['en0']['inet'].append('100.64.1.1')
        self.assertEqual(guard.tailscale_interfaces(self.ifaces, 'utun1500'), ['utun3'])

    def test_garbage_is_an_error(self):
        with self.assertRaises(guard.DetectError):
            guard.parse_ifconfig('')
        with self.assertRaises(guard.DetectError):
            guard.parse_ifconfig('nothing useful here\n')


class RouteTests(unittest.TestCase):
    def test_interface(self):
        text = ROUTE_TEXT.format(address='1.1.1.1', interface='utun1500')
        self.assertEqual(guard.parse_route_interface(text), 'utun1500')

    def test_missing_interface(self):
        with self.assertRaises(guard.DetectError):
            guard.parse_route_interface('route: writing to routing socket: not in table\n')


class PsTests(unittest.TestCase):
    def test_rows(self):
        text = FakeSystem().do_ps([], None).out
        self.assertEqual(guard.parse_ps(text), [
            (1, '/sbin/launchd'), (517, '/Library/PrivilegedHelperTools/party.mihomo.helper'), (881, MIHOMO)])

    def test_command_keeps_spaces(self):
        self.assertEqual(guard.parse_ps('  42 /Applications/Clash Verge.app/Contents/MacOS/verge-mihomo  \n'),
                         [(42, '/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo')])

    def test_junk_lines_skipped(self):
        self.assertEqual(guard.parse_ps('  PID COMM\nabc /bin/x\n   7\n    1 /sbin/launchd\n'), [(1, '/sbin/launchd')])

    def test_empty_output_is_an_error(self):
        for text in ('', '\n', 'garbage\n'):
            with self.subTest(text=text), self.assertRaises(guard.DetectError):
                guard.parse_ps(text)


class BootAndTokenTests(unittest.TestCase):
    def test_boot_id(self):
        self.assertEqual(guard.parse_boot_id(BOOT.lower() + '\n'), BOOT)
        for text in ('', 'kern.bootsessionuuid: unknown', BOOT_TEXT, BOOT + 'X'):
            with self.subTest(text=text), self.assertRaises(guard.DetectError):
                guard.parse_boot_id(text)

    def test_boottime(self):
        self.assertEqual(guard.parse_boottime(BOOT_TEXT), BOOT_TIME)
        with self.assertRaises(guard.DetectError):
            guard.parse_boottime('kern.boottime: unknown')

    def test_token_from_enable_output(self):
        text = 'No ALTQ support in kernel\npf enabled\nToken : 18446744073709551615\n'
        self.assertEqual(guard.TOKEN.findall(text), ['18446744073709551615'])

    def test_enable_needs_exactly_one_token(self):
        fake = FakeSystem()
        pf = guard.PF(fake)
        self.assertEqual(pf.enable(), fake.tokens[0])
        fake.override['pf-enable'] = guard.Result(0, '', 'pf enabled\n')
        with self.assertRaises(guard.DetectError):
            pf.enable()

    def test_token_listed(self):
        fake = FakeSystem()
        fake.tokens = ['18446744073709000042']
        pf = guard.PF(fake)
        self.assertTrue(pf.token_listed('18446744073709000042'))
        self.assertFalse(pf.token_listed('18446744073709000043'))
        fake.override['pf-refs'] = guard.Result(1, '', 'pfctl: Permission denied\n')
        self.assertIsNone(pf.token_listed('18446744073709000042'))

    def test_release_rejects_non_numeric(self):
        fake = FakeSystem()
        self.assertFalse(guard.PF(fake).release('1; rm -rf /'))
        self.assertEqual(fake.count('pf-release'), 0)

    def test_pf_status(self):
        fake = FakeSystem()
        pf = guard.PF(fake)
        self.assertFalse(pf.enabled())
        fake.enabled = True
        self.assertTrue(pf.enabled())
        fake.override['pf-info'] = guard.Result(0, 'garbage\n', '')
        with self.assertRaises(guard.DetectError):
            pf.enabled()


class ResultTests(unittest.TestCase):
    def test_brief_drops_pfctl_warning(self):
        result = guard.Result(1, '', 'pfctl: Use of -f option, could result in flushing of rules\n'
                                     'present in the main ruleset added by the system at startup.\n'
                                     'See /etc/pf.conf for further details.\n'
                                     'stdin:3: syntax error\n')
        self.assertEqual(result.brief(), 'exit 1: stdin:3: syntax error')

    def test_brief_timeout(self):
        self.assertTrue(guard.Result(None, '', '', timed_out=True).brief().startswith('timed out'))


if __name__ == '__main__':
    unittest.main()
