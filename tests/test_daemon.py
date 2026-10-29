"""守护进程的状态切换。系统命令全部由 FakeSystem 模拟，时间由测试推进。"""
import io
import json
import os
import signal
import tempfile
import unittest
from unittest import mock

from support import (BOOT, MIHOMO, V2_0_CONFIG, FakeFetch, FakeSystem, guard, make_paths, sample_cache,
                     vpn_interface, write_config)


class DaemonCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = make_paths(self.temp.name)
        write_config(self.paths)
        self.sys = FakeSystem()
        self.now = [100.0]
        self.wall = [1793260000.0]
        self.log = io.StringIO()
        self.fetch = FakeFetch()

    def daemon(self, start=True):
        d = guard.Daemon(self.paths, run=self.sys, clock=lambda: self.now[0], wall=lambda: self.wall[0],
                         fetch=self.fetch, secure=False, stream=self.log)
        if start:
            d.startup()
        return d

    def advance(self, seconds):
        self.now[0] += seconds
        self.wall[0] += seconds

    def blocked(self):
        return guard.has_block(self.sys.rules())

    def status(self):
        return json.loads(self.paths.status.read_text())


class SwitchTests(DaemonCase):
    def test_blocks_immediately_when_tun_is_down(self):
        self.sys.tun_exists = False
        d = self.daemon()
        d.step()
        self.assertEqual(d.mode, 'block')
        self.assertTrue(self.blocked())
        self.assertEqual(self.sys.count('pf-enable'), 1)
        self.assertTrue(self.sys.enabled)
        self.assertIn('utun1500 does not exist', d.reason)

    def test_healthy_start_does_not_touch_rules(self):
        d = self.daemon()
        d.step()
        self.assertEqual(d.mode, 'allow')
        self.assertEqual(self.sys.count('pf-load'), 0)
        self.assertEqual(self.sys.count('pf-flush'), 0)
        self.assertIs(self.status()['protected'], True)

    def test_failure_blocks_at_once_recovery_waits_for_debounce(self):
        d = self.daemon()
        d.step()
        self.sys.mihomo = False
        self.advance(0.1)
        d.step()
        self.assertEqual(d.mode, 'block')
        self.assertTrue(self.blocked())
        self.sys.mihomo = True
        self.advance(0.1)
        d.step()
        self.assertEqual(d.mode, 'block')
        self.assertIn('confirming', d.reason)
        self.assertAlmostEqual(d.wake_at, self.now[0] + guard.DEBOUNCE)
        self.advance(guard.DEBOUNCE / 2)
        d.step()
        self.assertTrue(self.blocked())
        self.advance(guard.DEBOUNCE / 2 + 0.01)
        d.step()
        self.assertEqual(d.mode, 'allow')
        self.assertFalse(self.blocked())
        self.assertLessEqual(guard.DEBOUNCE, 1.0)

    def test_flicker_during_debounce_restarts_it(self):
        self.sys.tun_up = False
        d = self.daemon()
        d.step()
        self.sys.tun_up = True
        d.step()
        self.advance(0.5)
        self.sys.tun_up = False
        d.step()
        self.sys.tun_up = True
        self.advance(0.1)
        d.step()
        self.advance(0.5)
        d.step()
        self.assertEqual(d.mode, 'block')
        self.advance(0.31)
        d.step()
        self.assertEqual(d.mode, 'allow')

    def test_flapping_is_rate_limited(self):
        d = self.daemon()
        d.step()
        for _ in range(guard.ALLOW_BURST):
            self.sys.route_via = 'en0'
            d.step()
            self.sys.route_via = 'utun1500'
            d.step()
            self.advance(guard.DEBOUNCE)
            d.step()
            self.assertEqual(d.mode, 'allow')
            self.advance(1.0)
        self.sys.route_via = 'en0'
        d.step()
        self.sys.route_via = 'utun1500'
        d.step()
        self.advance(guard.DEBOUNCE)
        d.step()
        self.assertEqual(d.mode, 'block')
        self.assertIn('switching too often', d.reason)
        self.advance(guard.ALLOW_WINDOW)
        d.step()
        self.assertEqual(d.mode, 'allow')

    def test_unchanged_block_is_not_reloaded(self):
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        loads = self.sys.count('pf-load')
        for _ in range(5):
            self.advance(guard.POLL)
            d.step()
        self.assertEqual(self.sys.count('pf-load'), loads)

    def test_tailscale_interface_change_reloads(self):
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        self.assertIn('pass out quick on utun3 all no state', self.sys.rules())
        self.sys.tailscale = 'utun5'
        d.step()
        self.assertIn('pass out quick on utun5 all no state', self.sys.rules())
        self.assertNotIn('utun3', self.sys.rules())
        self.sys.tailscale = None
        d.step()
        self.assertNotIn(' on utun', self.sys.rules())
        self.assertTrue(self.blocked())

    def test_cache_addresses_used_in_rules(self):
        self.paths.cache.write_text(json.dumps(sample_cache()))
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        self.assertIn('pass out quick proto udp to <tailscale_infra> port 3478 no state', self.sys.rules())

    def test_allow_log_names_core_and_tun(self):
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        self.sys.mihomo = True
        d.step()
        self.advance(guard.DEBOUNCE)
        d.step()
        self.assertEqual(d.mode, 'allow')
        self.assertIn('allowed: Clash TUN ok (core pid 881 Clash Party, tun utun1500)', self.log.getvalue())

    def test_auto_tun_follows_new_interface_name(self):
        # 客户端重启后 TUN 换了编号，auto 照样认。
        d = self.daemon()
        d.step()
        self.sys.tun = self.sys.route_via = 'utun6'
        d.step()
        self.assertEqual(d.mode, 'allow')
        self.assertEqual(self.status()['tun_interface'], 'utun6')

    def test_route_moving_to_another_vpn_blocks(self):
        d = self.daemon()
        d.step()
        self.sys.extra_ifconfig = vpn_interface('utun8')
        self.sys.route_via = {'1.1.1.1': 'utun1500', '8.8.8.8': 'utun8'}
        d.step()
        self.assertEqual(d.mode, 'block')
        self.assertTrue(self.blocked())

    def test_broken_cache_still_blocks(self):
        self.paths.cache.write_text('{"version": 1, "sources": {"derp": {"updated": 1, "addresses": ["10.0.0.1"]}}}')
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        self.assertTrue(self.blocked())
        self.assertNotIn('tailscale_infra', self.sys.rules())


class FailClosedTests(DaemonCase):
    def test_invalid_config_blocks(self):
        self.paths.config.write_text('{"version": 2, "tun_interface": "en0"}')
        d = self.daemon()
        d.step()
        self.assertEqual(d.mode, 'block')
        self.assertIn('invalid config', d.reason)

    def test_missing_config_blocks(self):
        self.paths.config.unlink()
        d = self.daemon()
        d.step()
        self.assertTrue(self.blocked())

    def test_detection_errors_block(self):
        cases = {
            'ps': guard.Result(1, '', 'ps: error\n'),
            'ifconfig': guard.Result(None, '', '', timed_out=True),
            'route': guard.Result(None, '', '', timed_out=True),
        }
        for kind, result in cases.items():
            with self.subTest(kind=kind):
                self.sys = FakeSystem()
                self.sys.override[kind] = result
                d = self.daemon()
                d.step()
                self.assertEqual(d.mode, 'block')
                self.assertTrue(self.blocked())

    def test_load_failure_falls_back_to_minimal_rules(self):
        self.paths.cache.write_text(json.dumps(sample_cache()))
        self.sys.on_load = lambda text: guard.Result(1, '', 'stdin:2: syntax error\n') if guard.TABLE in text else None
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        self.assertEqual(d.mode, 'block')
        self.assertTrue(self.blocked())
        self.assertEqual(self.sys.rules().strip(), '\n'.join(
            line for line in guard.MINIMAL_RULES.splitlines() if not line.startswith('#')))
        self.assertIn('minimal block rules', self.log.getvalue())

    def test_total_load_failure_is_retried(self):
        self.sys.on_load = lambda text: guard.Result(1, '', 'DIOCADDRULE: Device busy\n')
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        self.assertNotEqual(d.mode, 'block')
        self.assertTrue(any('loading block rules failed' in text for text in d.problems.values()))
        self.assertIs(self.status()['protected'], False)
        loads = self.sys.count('pf-load')
        self.sys.on_load = None
        self.advance(guard.POLL)
        d.step()
        self.assertGreater(self.sys.count('pf-load'), loads)
        self.assertEqual(d.mode, 'block')
        self.assertNotIn('apply', d.problems)
        self.assertIs(self.status()['protected'], True)

    def test_stuck_pfctl_does_not_hang_the_loop(self):
        self.sys.override['pf-load'] = guard.Result(None, '', 'pfctl did not exit after kill, gave up waiting', timed_out=True)
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        self.assertIn('apply', d.problems)
        self.assertIn('timed out', d.problems['apply'])

    def test_verify_mismatch_retries(self):
        self.sys.mihomo = False
        d = self.daemon()
        self.sys.on_load = lambda text: guard.Result(0, '', '')
        d.step()
        self.assertIsNone(d.applied)
        self.assertIn('do not match after loading', d.problems['apply'])

    def test_signal_keeps_rules(self):
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        flushes = self.sys.count('pf-flush')
        with mock.patch.object(guard.os, '_exit', side_effect=SystemExit):
            with self.assertRaises(SystemExit):
                d.on_signal(signal.SIGTERM, None)
        self.assertEqual(self.sys.count('pf-flush'), flushes)
        self.assertTrue(self.blocked())

    def test_restart_while_blocked_keeps_blocking(self):
        self.sys.mihomo = False
        self.daemon().step()
        self.sys.mihomo = True
        d = self.daemon()
        self.assertEqual(d.mode, 'block')
        d.step()
        self.assertTrue(self.blocked())
        self.advance(guard.DEBOUNCE)
        d.step()
        self.assertFalse(self.blocked())

    def test_unknown_anchor_content_is_replaced(self):
        self.sys.anchors[guard.ANCHOR] = ['pass out quick all no state']
        d = self.daemon()
        self.assertIsNone(d.mode)
        d.step()
        self.assertTrue(self.blocked())
        self.advance(guard.DEBOUNCE)
        d.step()
        self.assertEqual(self.sys.rules(), '')


class V2_0ConfigTests(DaemonCase):
    """升级后守护进程读到的可能还是 2.0 的配置（写死网卡名和路径），行为不变。"""

    def setUp(self):
        super().setUp()
        self.paths.config.write_text(json.dumps(V2_0_CONFIG))

    def test_allows_and_blocks_as_before(self):
        d = self.daemon()
        d.step()
        self.assertEqual(d.mode, 'allow')
        self.assertIsNone(d.cfg_error)
        data = self.status()
        self.assertEqual((data['tun_interface'], data['tun_auto']), ('utun1500', False))
        self.sys.mihomo = False
        d.step()
        self.assertEqual(d.mode, 'block')

    def test_switch_to_auto_on_reconcile(self):
        d = self.daemon()
        d.step()
        write_config(self.paths)
        d.reconcile()
        d.step()
        self.assertEqual(d.mode, 'allow')
        self.assertIs(self.status()['tun_auto'], True)


class DisableTests(DaemonCase):
    def test_marker_releases_everything(self):
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        token = d.token
        self.paths.marker.write_text('disabled\n')
        d.step()
        self.assertEqual(d.mode, 'disabled')
        self.assertFalse(self.blocked())
        self.assertNotIn(token, self.sys.tokens)
        self.assertFalse(self.paths.token.exists())
        self.assertEqual(self.status()['mode'], 'disabled')

    def test_marker_before_first_step(self):
        self.paths.marker.write_text('disabled\n')
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        self.assertEqual(d.mode, 'disabled')
        self.assertEqual(self.sys.count('pf-load'), 0)
        self.assertEqual(self.sys.count('pf-enable'), 0)

    def test_marker_written_during_load(self):
        def on_load(text):
            self.paths.marker.write_text('disabled\n')
        self.sys.on_load = on_load
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        self.assertEqual(d.mode, 'disabled')
        self.assertFalse(self.blocked())
        self.assertEqual(self.sys.tokens, [])

    def test_enable_resumes_protection(self):
        self.paths.marker.write_text('disabled\n')
        d = self.daemon()
        d.step()
        os.unlink(str(self.paths.marker))
        self.sys.mihomo = False
        d.step()
        self.assertEqual(d.mode, 'block')
        self.assertTrue(self.blocked())
        self.assertEqual(len(self.sys.tokens), 1)

    def test_enable_with_healthy_tun_allows_without_debounce(self):
        self.paths.marker.write_text('disabled\n')
        d = self.daemon()
        d.step()
        os.unlink(str(self.paths.marker))
        d.step()
        self.assertEqual(d.mode, 'allow')
        self.assertEqual(self.sys.count('pf-load'), 0)

    def test_rules_reappearing_while_disabled_are_flushed(self):
        self.paths.marker.write_text('disabled\n')
        d = self.daemon()
        d.step()
        self.sys.anchors[guard.ANCHOR] = ['block return out quick inet all']
        d.reconcile()
        self.assertFalse(self.blocked())


class TokenTests(DaemonCase):
    def save_token(self, token, boot):
        self.paths.token.write_text(json.dumps({'token': token, 'boot': boot, 'pid': 1, 'time': 1.0}))

    def test_reuse_same_boot_listed_token(self):
        self.sys.tokens, self.sys.enabled = ['18446744073709000001'], True
        self.save_token('18446744073709000001', BOOT)
        d = self.daemon()
        d.step()
        self.assertEqual(d.token, '18446744073709000001')
        self.assertEqual(self.sys.count('pf-enable'), 0)

    def test_token_from_other_boot_is_never_released(self):
        self.sys.tokens, self.sys.enabled = ['18446744073709000001'], True
        self.save_token('18446744073709000001', '1700000000.000001')
        d = self.daemon()
        d.step()
        self.assertEqual(self.sys.count('pf-enable'), 1)
        self.assertEqual(self.sys.count('pf-release'), 0)
        self.assertIn('18446744073709000001', self.sys.tokens)
        self.assertEqual(json.loads(self.paths.token.read_text())['boot'], BOOT)

    def test_unlisted_token_is_replaced(self):
        self.save_token('18446744073709000001', BOOT)
        d = self.daemon()
        d.step()
        self.assertEqual(self.sys.count('pf-enable'), 1)
        self.assertEqual(self.sys.count('pf-release'), 0)
        self.assertNotEqual(d.token, '18446744073709000001')

    def test_unknown_boot_never_reuses(self):
        self.sys.override['sysctl'] = guard.Result(1, '', 'sysctl: unknown oid\n')
        self.sys.tokens, self.sys.enabled = ['18446744073709000001'], True
        self.save_token('18446744073709000001', '')
        d = self.daemon()
        d.step()
        self.assertEqual(self.sys.count('pf-enable'), 1)
        self.assertIn('boot', d.problems)

    def test_pf_disabled_by_someone_else(self):
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        self.sys.enabled, self.sys.tokens = False, []
        d.reconcile()
        self.assertTrue(self.sys.enabled)
        self.assertEqual(self.sys.count('pf-enable'), 2)
        self.assertEqual(json.loads(self.paths.token.read_text())['token'], d.token)

    def test_token_lost_while_pf_still_enabled(self):
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        self.sys.tokens = ['18446744073709999999']
        d.reconcile()
        self.assertEqual(self.sys.count('pf-enable'), 2)
        self.assertEqual(self.sys.count('pf-release'), 0)


class ReconcileTests(DaemonCase):
    def test_flushed_block_is_reloaded(self):
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        self.sys.anchors[guard.ANCHOR] = []
        d.reconcile()
        self.assertIsNone(d.applied)
        d.step()
        self.assertTrue(self.blocked())

    def test_rules_added_while_allowed_are_flushed(self):
        d = self.daemon()
        d.step()
        self.sys.anchors[guard.ANCHOR] = ['block return out quick inet all']
        d.reconcile()
        d.step()
        self.assertEqual(self.sys.rules(), '')

    def test_config_reloaded(self):
        d = self.daemon()
        d.step()
        self.paths.config.write_text('{"version": 2, "tun_interface": "utun9"}')
        d.reconcile()
        d.step()
        self.assertEqual(d.mode, 'block')
        self.assertIn('utun9', d.reason)

    def test_main_ruleset_without_anchor_is_reported(self):
        self.sys.main = 'scrub-anchor "com.apple/*" all fragment reassemble\n'
        d = self.daemon()
        d.step()
        self.assertIn('main', d.problems)
        self.assertTrue(any('main ruleset' in text for text in self.status()['problems']))


class StatusTests(DaemonCase):
    def test_status_file(self):
        self.paths.cache.write_text(json.dumps(sample_cache()))
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        data = self.status()
        self.assertEqual(data['mode'], 'block')
        self.assertEqual(data['tailscale_interfaces'], ['utun3'])
        self.assertEqual(data['derp_count'], 3)
        self.assertEqual(data['control_count'], 2)
        self.assertEqual(data['anchor'], guard.ANCHOR)
        self.assertEqual(data['pid'], os.getpid())
        self.assertEqual(data['cores'], [])
        self.assertIsNone(data['tun_interface'])
        self.assertIs(data['tun_auto'], True)
        text = guard.format_status(data, now=data['updated'] + 1, alive=True)
        self.assertIn('mode: block (Clash core is not running)', text)
        self.assertIn('core: not found', text)
        self.assertIn('Tailscale interface: utun3', text)
        self.assertIn('DERP 3', text)

    def test_status_names_detected_core_and_tun(self):
        d = self.daemon()
        d.step()
        data = self.status()
        self.assertEqual(data['cores'], [{'pid': 881, 'path': MIHOMO, 'client': 'Clash Party'}])
        self.assertEqual((data['tun_interface'], data['tun_auto']), ('utun1500', True))
        text = guard.format_status(data, now=data['updated'] + 1, alive=True)
        self.assertIn('core: Clash Party, pid 881', text)
        self.assertIn('TUN interface: utun1500 (auto)', text)

    def test_status_while_disabled(self):
        self.paths.marker.write_text('disabled\n')
        d = self.daemon()
        d.step()
        data = self.status()
        self.assertEqual((data['cores'], data['tun_interface'], data['tun_auto']), ([], None, None))

    def test_status_written_only_on_change(self):
        d = self.daemon()
        d.step()
        first = self.paths.status.stat().st_mtime_ns
        os.utime(str(self.paths.status), ns=(1, 1))
        self.advance(guard.POLL)
        d.step()
        self.assertEqual(self.paths.status.stat().st_mtime_ns, 1)
        d.reconcile()
        self.assertNotEqual(self.paths.status.stat().st_mtime_ns, 1)
        self.assertNotEqual(first, 1)

    def test_errors_are_rate_limited_in_log(self):
        self.sys.override['pf-rules'] = guard.Result(1, '', 'pfctl: boom\n')
        d = self.daemon()
        for _ in range(5):
            d.reconcile()
        self.assertEqual(self.log.getvalue().count('reading PF rules failed'), 1)


class RefreshTests(DaemonCase):
    def test_background_refresh_updates_cache(self):
        d = self.daemon()
        d.step()
        self.assertEqual(d.mode, 'allow')
        d.maybe_refresh()
        d.refresh_thread.join(5)
        d.collect_refresh()
        counts, _ = guard.cache_counts(d.cache)
        self.assertEqual(counts['control'], 4)
        self.assertTrue(self.paths.cache.exists())
        self.assertEqual(self.status()['control_count'], 4)
        self.assertGreater(d.next_refresh, self.now[0] + 3600)

    def test_no_refresh_while_blocked(self):
        self.sys.mihomo = False
        d = self.daemon()
        d.step()
        d.maybe_refresh()
        self.assertIsNone(d.refresh_thread)

    def test_failed_refresh_keeps_cache_and_retries_later(self):
        self.paths.cache.write_text(json.dumps(sample_cache(now=1.0)))
        self.fetch.failing.update(('derp', 'control'))
        d = self.daemon()
        d.step()
        d.maybe_refresh()
        d.refresh_thread.join(5)
        d.collect_refresh()
        self.assertEqual(d.cache, sample_cache(now=1.0))
        self.assertAlmostEqual(d.next_refresh, self.now[0] + guard.REFRESH_RETRY)
        self.assertIn('keeping old addresses', self.log.getvalue())


class FakeEvents:
    """不碰 kqueue：wait 直接把测试时钟拨到超时点；登记进程一律失败，像 pid 已经不在了。"""
    error = None

    def __init__(self, case):
        self.case = case

    def watch(self, pids):
        return not pids

    def wait(self, timeout):
        self.case.advance(max(0.0, timeout))
        return False, False

    def close(self):
        pass


class ServeTests(DaemonCase):
    def setUp(self):
        super().setUp()
        handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
        self.addCleanup(lambda: [signal.signal(sig, handler) for sig, handler in handlers.items()])

    def serve(self, d, iterations):
        try:
            return d.serve(iterations=iterations)
        finally:
            if d.refresh_thread is not None:
                d.refresh_thread.join(5)
            if d.lock_fd is not None:
                os.close(d.lock_fd)

    def test_serve_runs_with_real_events(self):
        self.sys.mihomo_pid = os.getpid()
        d = guard.Daemon(self.paths, run=self.sys, fetch=self.fetch, secure=False, stream=self.log)
        d.poll = 0.02
        self.assertEqual(self.serve(d, 6), 0)
        self.assertNotIn('main loop error', self.log.getvalue())
        self.assertEqual(self.status()['mode'], 'allow')
        self.assertEqual(d.health.pids, [os.getpid()])

    def record_steps(self, d, after_first=None):
        original, times = d.step, []

        def step():
            original()
            times.append(self.now[0])
            if len(times) == 1 and after_first:
                after_first()
        d.step = step
        return times

    def serve_with_fake_events(self, d, iterations):
        with mock.patch.object(guard, 'Events', lambda: FakeEvents(self)):
            self.serve(d, iterations)

    def test_unwatchable_mihomo_does_not_spin(self):
        # ps 一直报 mihomo 在，kqueue 却一直登记不上（比如僵尸进程），主循环也不能空转。
        d = self.daemon(start=False)
        times = self.record_steps(d)
        self.serve_with_fake_events(d, 9)
        gaps = [b - a for a, b in zip(times, times[1:])]
        self.assertGreaterEqual(len(gaps), 3)
        self.assertGreaterEqual(min(gaps), guard.ROUTE_GAP - 1e-6)

    def test_disabled_daemon_stops_watching_mihomo(self):
        d = self.daemon(start=False)
        times = self.record_steps(d, lambda: self.paths.marker.write_text('disabled\n'))
        self.serve_with_fake_events(d, 6)
        self.assertEqual(d.mode, 'disabled')
        self.assertIsNone(d.health)
        gaps = [b - a for a, b in zip(times[1:], times[2:])]
        self.assertGreaterEqual(len(gaps), 2)
        self.assertGreaterEqual(min(gaps), d.poll - 1e-6)

    def test_second_instance_exits(self):
        first = guard.Daemon(self.paths, run=self.sys, secure=False, stream=self.log)
        self.assertTrue(first.take_lock())
        self.addCleanup(os.close, first.lock_fd)
        second = guard.Daemon(self.paths, run=self.sys, secure=False, stream=self.log)
        with mock.patch.object(guard.time, 'sleep'):
            self.assertEqual(second.serve(iterations=1), 1)
        self.assertIn('another daemon', self.log.getvalue())

    def test_loop_survives_exceptions(self):
        d = guard.Daemon(self.paths, run=self.sys, fetch=self.fetch, secure=False, stream=self.log)
        d.poll = 0.02
        calls = []
        original = d.step

        def step():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError('unexpected')
            original()
        d.step = step
        with mock.patch.object(guard.time, 'sleep'):
            self.serve(d, 4)
        self.assertIn('main loop error', self.log.getvalue())
        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(d.mode, 'allow')


if __name__ == '__main__':
    unittest.main()
