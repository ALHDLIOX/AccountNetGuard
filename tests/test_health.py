"""判定 Clash TUN 是否正常：任何一步不满足或出错都算不正常。"""
import unittest

from support import MIHOMO, V2_0_CONFIG, FakeSystem, guard, vpn_interface

CLASHX = '/Users/someone/Library/Application Support/com.metacubex.ClashX.meta'
HELPER = 'com.metacubex.ClashX.ProxyConfigHelper'

# (ps 显示的命令, 应该标出的客户端)
KNOWN_CORES = [
    (MIHOMO, 'Clash Party'),
    ('/Applications/Clash Party.app/Contents/Resources/sidecar/mihomo-alpha', 'Clash Party'),
    ('/Applications/Clash Party.app/Contents/Resources/sidecar/mihomo-smart', 'Clash Party'),
    ('/Applications/Mihomo Party.app/Contents/Resources/sidecar/mihomo', 'Clash Party'),
    ('/Users/someone/Applications/Clash Party.app/Contents/Resources/sidecar/mihomo', 'Clash Party'),
    ('/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo', 'Clash Verge Rev'),
    ('/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo-alpha', 'Clash Verge Rev'),
    ('/Library/Application Support/clash-verge-service/cores/verge-mihomo', 'Clash Verge Rev'),
    ('/Library/Application Support/clash-verge-service/cores/verge-mihomo-alpha', 'Clash Verge Rev'),
    ('/Applications/FlClash.app/Contents/MacOS/FlClashCore', 'FlClash'),
    (CLASHX + '/.private_core/' + HELPER + '.meta', 'ClashX Meta'),
    (CLASHX + '/' + HELPER + '.meta', 'ClashX Meta'),
    ('/opt/homebrew/opt/mihomo/bin/mihomo', 'Homebrew'),
    ('/opt/homebrew/bin/mihomo', 'Homebrew'),
    ('/opt/homebrew/Cellar/mihomo/1.2.3/bin/mihomo', 'Homebrew'),
    ('/usr/local/opt/mihomo/bin/mihomo', 'Homebrew'),
    ('/usr/local/Cellar/mihomo/1.2.3/bin/mihomo', 'Homebrew'),
    ('/usr/local/bin/mihomo', guard.UNKNOWN_CLIENT),
    ('/Users/someone/clash/mihomo', guard.UNKNOWN_CLIENT),
    ('mihomo', guard.UNKNOWN_CLIENT),          # 在 shell 里直接运行时只有文件名
    ('./mihomo-alpha', guard.UNKNOWN_CLIENT),
]
NOT_CORES = [
    '/sbin/launchd',
    '/Library/PrivilegedHelperTools/party.mihomo.helper',
    '/Library/PrivilegedHelperTools/' + HELPER,
    '/Library/PrivilegedHelperTools/io.github.clashverge.helper',
    '/usr/local/bin/mihomo-old',
    '/usr/local/bin/mihomo.sh',
    '/Applications/Clash Party.app/Contents/Resources/sidecar/mihomo/',
]


class FindCoresTests(unittest.TestCase):
    def test_auto_knows_every_client(self):
        for pid, (command, client) in enumerate(KNOWN_CORES, 100):
            with self.subTest(command=command):
                cores = guard.find_cores([(1, '/sbin/launchd'), (pid, command)], guard.AUTO)
                self.assertEqual([core.data() for core in cores], [{'pid': pid, 'path': command, 'client': client}])

    def test_auto_ignores_helpers_and_lookalikes(self):
        rows = list(enumerate(NOT_CORES, 10))
        self.assertEqual(guard.find_cores(rows, guard.AUTO), [])

    def test_explicit_path_must_match_exactly(self):
        rows = [(10, MIHOMO), (11, MIHOMO + '-old'), (12, '/opt/homebrew/bin/mihomo')]
        self.assertEqual([core.pid for core in guard.find_cores(rows, MIHOMO)], [10])
        self.assertEqual(guard.find_cores(rows, '/usr/local/bin/mihomo'), [])

    def test_explicit_list(self):
        custom = '/opt/clash/clash-core'
        rows = [(10, MIHOMO), (11, custom), (12, '/opt/homebrew/bin/mihomo')]
        cores = guard.find_cores(rows, [custom, MIHOMO])
        self.assertEqual([(core.pid, core.client) for core in cores],
                         [(10, 'Clash Party'), (11, guard.CONFIGURED_CLIENT)])

    def test_number_of_cores_is_capped(self):
        rows = [(pid, 'mihomo') for pid in range(100, 130)]
        self.assertEqual(len(guard.find_cores(rows, guard.AUTO)), guard.MAX_CORES)

    def test_client_names_cover_the_core_names(self):
        for command, client in KNOWN_CORES:
            self.assertIn(command.rsplit('/', 1)[-1], guard.CORE_NAMES)


class HealthCase(unittest.TestCase):
    def setUp(self):
        self.fake = FakeSystem()
        self.cfg = dict(guard.DEFAULTS)

    def inspect(self):
        return guard.inspect(self.cfg, self.fake)

    def assertUnhealthy(self, needle):
        health = self.inspect()
        self.assertFalse(health.ok, health.reason)
        self.assertIn(needle, health.reason)
        return health


class InspectTests(HealthCase):
    def test_defaults_are_auto(self):
        self.assertEqual(guard.DEFAULTS['tun_interface'], guard.AUTO)
        self.assertEqual(guard.DEFAULTS['mihomo_path'], guard.AUTO)

    def test_healthy(self):
        health = self.inspect()
        self.assertTrue(health.ok, health.reason)
        self.assertEqual(health.pids, [881])
        self.assertEqual(health.cores[0].client, 'Clash Party')
        self.assertEqual((health.tun, health.auto_tun), ('utun1500', True))
        self.assertEqual(health.tailscale, ['utun3'])
        self.assertEqual(health.summary(), 'core pid 881 Clash Party, tun utun1500')
        routes = [argv[-1] for kind, argv in self.fake.calls if kind == 'route']
        self.assertEqual(routes, ['1.1.1.1', '8.8.8.8'])

    def test_mihomo_not_running(self):
        self.fake.mihomo = False
        health = self.assertUnhealthy('Clash core is not running')
        self.assertEqual(health.cores, [])

    def test_any_known_client_counts(self):
        for command, _ in KNOWN_CORES:
            with self.subTest(command=command):
                self.fake.core = command
                self.assertTrue(self.inspect().ok)

    def test_helper_alone_is_not_a_core(self):
        self.fake.core = '/Library/PrivilegedHelperTools/' + HELPER
        self.assertUnhealthy('Clash core is not running')

    def test_tun_missing(self):
        self.fake.tun_exists = False
        self.assertUnhealthy('utun1500 does not exist')

    def test_tun_down(self):
        self.fake.tun_up = False
        self.assertUnhealthy('is not up')

    def test_tun_without_address(self):
        self.fake.tun_inet = False
        self.assertUnhealthy('has no IPv4 address')

    def test_route_not_via_tun(self):
        self.fake.route_via = 'en0'
        health = self.assertUnhealthy('via en0')
        self.assertIsNone(health.tun)

    def test_second_probe_checked(self):
        def route(argv, input):
            via = 'utun1500' if argv[-1] == '1.1.1.1' else 'en0'
            return guard.Result(0, '  interface: %s\n' % via, '')
        self.fake.override['route'] = route
        self.assertUnhealthy('8.8.8.8')

    def test_route_command_fails(self):
        self.fake.override['route'] = guard.Result(1, '', 'route: writing to routing socket: not in table\n')
        self.assertUnhealthy('route lookup for 1.1.1.1 failed')

    def test_route_timeout(self):
        self.fake.override['route'] = guard.Result(None, '', '', timed_out=True)
        self.assertUnhealthy('timed out')

    def test_ps_fails(self):
        self.fake.override['ps'] = guard.Result(1, '', 'ps: boom\n')
        self.assertUnhealthy('Clash core check failed')

    def test_ps_garbage(self):
        self.fake.override['ps'] = guard.Result(0, 'garbage\n', '')
        self.assertUnhealthy('cannot parse ps output')

    def test_ifconfig_fails(self):
        self.fake.override['ifconfig'] = guard.Result(None, '', '', timed_out=True)
        self.assertUnhealthy('interface check failed')

    def test_detector_exception_is_unhealthy(self):
        def boom(argv, input):
            raise RuntimeError('unexpected')
        self.fake.override['ps'] = boom
        self.assertUnhealthy('unexpected')

    def test_no_config_is_unhealthy_but_still_finds_tailscale(self):
        health = guard.inspect(None, self.fake, 'config file not found')
        self.assertFalse(health.ok)
        self.assertIn('invalid config', health.reason)
        self.assertEqual(health.tailscale, ['utun3'])
        self.assertEqual(self.fake.count('route'), 0)
        self.assertEqual(self.fake.count('ps'), 0)


class AutoTunTests(HealthCase):
    """tun_interface 是 auto：探测地址实际走哪个 utun，就认哪个。"""

    def assertUnhealthy(self, needle):
        health = super().assertUnhealthy(needle)
        self.assertTrue(health.auto_tun)
        self.assertIsNone(health.tun)
        return health

    def test_any_utun_number(self):
        self.fake.tun = self.fake.route_via = 'utun7'
        health = self.inspect()
        self.assertTrue(health.ok, health.reason)
        self.assertEqual(health.tun, 'utun7')

    def test_tailscale_interface_is_never_the_tun(self):
        self.fake.route_via = 'utun3'
        self.assertUnhealthy('Tailscale interface utun3')

    def test_tun_with_tailnet_address_is_treated_as_tailscale(self):
        # Clash TUN 的地址如果在 100.64.0.0/10 里，自动识别会把它当成 Tailscale，要写死网卡名。
        self.fake.tun_address = '100.64.0.1'
        self.assertUnhealthy('Tailscale interface utun1500')
        self.cfg['tun_interface'] = 'utun1500'
        health = self.inspect()
        self.assertTrue(health.ok, health.reason)
        self.assertNotIn('utun1500', health.tailscale)

    def test_probes_must_use_the_same_interface(self):
        self.fake.extra_ifconfig = vpn_interface('utun8')
        self.fake.route_via = {'1.1.1.1': 'utun1500', '8.8.8.8': 'utun8'}
        self.assertUnhealthy('route to 8.8.8.8 goes via utun8, not utun1500')

    def test_route_via_missing_utun(self):
        self.fake.route_via = 'utun9'
        self.assertUnhealthy('utun9 does not exist')

    def test_route_via_tun_that_is_down(self):
        self.fake.tun_up = False
        self.assertUnhealthy('utun1500 is not up')

    def test_route_via_tun_without_ipv4(self):
        self.fake.tun_inet = False
        self.assertUnhealthy('utun1500 has no IPv4 address')

    def test_route_via_physical_interface(self):
        self.fake.route_via = 'en0'
        self.assertUnhealthy('route to 1.1.1.1 goes via en0, not Clash TUN')

    def test_route_failure_is_unhealthy(self):
        self.fake.override['route'] = guard.Result(1, '', 'route: writing to routing socket: not in table\n')
        self.assertUnhealthy('route lookup for 1.1.1.1 failed')

    def test_other_vpn_holding_the_route_is_a_known_gap(self):
        # 已知局限：Clash 开着但没开 TUN，别的 VPN 占了默认路由，auto 会误判为正常。写死网卡名就不会。
        self.fake.tun_exists = False
        self.fake.extra_ifconfig = vpn_interface('utun8')
        self.fake.route_via = 'utun8'
        health = self.inspect()
        self.assertTrue(health.ok)
        self.assertEqual(health.tun, 'utun8')
        self.cfg['tun_interface'] = 'utun1500'
        self.assertFalse(self.inspect().ok)


class FixedConfigTests(HealthCase):
    """写死网卡名和内核路径（2.0 的配置），行为和以前一样。"""

    def setUp(self):
        super().setUp()
        self.cfg = guard.validate_config(V2_0_CONFIG)

    def test_v2_0_config(self):
        health = self.inspect()
        self.assertTrue(health.ok, health.reason)
        self.assertEqual((health.tun, health.auto_tun), ('utun1500', False))
        self.assertEqual([core.client for core in health.cores], ['Clash Party'])

    def test_other_core_at_another_path_is_not_counted(self):
        self.fake.core = '/opt/homebrew/bin/mihomo'
        self.assertIn('Clash core is not running', self.inspect().reason)

    def test_fixed_tun_must_carry_every_probe(self):
        self.fake.extra_ifconfig = vpn_interface('utun8')
        self.fake.route_via = 'utun8'
        health = self.inspect()
        self.assertFalse(health.ok)
        self.assertIn('not utun1500', health.reason)
        self.assertEqual(health.tun, 'utun1500')

    def test_custom_tun_name(self):
        self.cfg['tun_interface'] = 'utun7'
        self.fake.tun = 'utun7'
        self.fake.route_via = 'utun7'
        self.assertTrue(self.inspect().ok)

    def test_fixed_tun_missing(self):
        self.fake.tun_exists = False
        health = self.inspect()
        self.assertIn('utun1500 does not exist', health.reason)
        self.assertEqual(self.fake.count('route'), 0)

    def test_path_list(self):
        self.cfg['mihomo_path'] = ['/opt/clash/clash-core', MIHOMO]
        self.assertTrue(self.inspect().ok)
        self.fake.core = '/opt/clash/clash-core'
        health = self.inspect()
        self.assertTrue(health.ok)
        self.assertEqual(health.cores[0].client, guard.CONFIGURED_CLIENT)


if __name__ == '__main__':
    unittest.main()
