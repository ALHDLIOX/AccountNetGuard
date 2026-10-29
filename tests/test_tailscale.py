"""Tailscale 控制服务器和 DERP 地址：解析、校验、按来源合并和缓存。"""
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import unittest

from support import DERPMAP, FakeFetch, doh_answer, guard, sample_cache


class ParseTests(unittest.TestCase):
    def test_derpmap(self):
        addresses, hosts = guard.parse_derpmap(DERPMAP)
        self.assertIn('199.38.181.104', addresses)
        self.assertIn('2607:f740:f::bc', addresses)
        self.assertIn('2607:f740:0:3f::288', addresses)
        self.assertNotIn('none', addresses)
        # 只有两个地址都没写的节点才需要另外解析主机名。
        self.assertEqual(hosts, ['derp2x.example.com'])

    def test_derpmap_rejects_wrong_shapes(self):
        for data in ({}, {'Regions': {}}, {'Regions': {'1': {'Nodes': 'x'}}},
                     {'Regions': {'1': {'Nodes': [{'IPv4': '2607:f740:f::bc'}]}}},
                     {'Regions': {'1': {'Nodes': [{'IPv4': 'bogus'}]}}}, []):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    guard.parse_derpmap(data)

    def test_doh_follows_cname(self):
        records = [('login.tailscale.com', 5, 'edge.example.net.'), ('edge.example.net.', 1, '192.200.0.112'),
                   ('unrelated.example.org', 1, '192.0.2.1')]
        found = guard.parse_doh(doh_answer(records, 'login.tailscale.com', 'A'), 'login.tailscale.com', 'A')
        self.assertEqual(found, ['192.200.0.112'])

    def test_doh_errors(self):
        with self.assertRaises(ValueError):
            guard.parse_doh({'Status': 2}, 'x.example.com', 'A')
        with self.assertRaises(ValueError):
            guard.parse_doh({'Status': 0, 'Answer': 'x'}, 'x.example.com', 'A')
        wrong = doh_answer([('x.example.com', 1, '2606:b740:49::112')], 'x.example.com', 'A')
        with self.assertRaises(ValueError):
            guard.parse_doh(wrong, 'x.example.com', 'A')

    def test_validate_addresses(self):
        self.assertEqual(guard.validate_addresses(['199.38.181.104', '199.38.181.104', '2607:f740:f::bc']),
                         ['199.38.181.104', '2607:f740:f::bc'])
        for value in ('10.1.2.3', '192.168.1.1', '198.18.0.5', '100.100.1.1', '127.0.0.1', '224.0.0.1',
                      'fd7a:115c:a1e0::1', 'fe80::1', '::1', '2001:db8::1', '::ffff:1.2.3.4'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    guard.validate_addresses([value])
        with self.assertRaises(ValueError):
            guard.validate_addresses([])
        too_many = [str(ipaddress.ip_address('11.0.0.0') + i) for i in range(guard.MAX_ADDRESSES + 1)]
        with self.assertRaises(ValueError):
            guard.validate_addresses(too_many)

    def test_fetch_sources(self):
        fetch = FakeFetch()
        derp = guard.fetch_derp(fetch)
        self.assertIn('203.0.114.9', derp)
        self.assertIn('192.73.252.65', derp)
        control = guard.fetch_control(fetch)
        self.assertEqual(control, ['192.200.0.111', '192.200.0.112', '199.165.136.101', '2606:b740:49::112'])

    def test_fake_ip_answer_rejected(self):
        dns = dict(FakeFetch().dns)
        dns[('log.tailscale.com', 'A')] = [('log.tailscale.com', 1, '198.18.0.42')]
        with self.assertRaises(ValueError):
            guard.fetch_control(FakeFetch(dns=dns))


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.path = self.dir / 'tailscale-cache.json'
        self.fetch = FakeFetch()

    def test_first_refresh_writes_cache(self):
        cache, errors = guard.refresh_cache(self.path, self.fetch, now=1000.0)
        self.assertEqual(errors, {})
        self.assertEqual(guard.load_cache(self.path), cache)
        counts, updated = guard.cache_counts(cache)
        self.assertEqual(updated, 1000.0)
        self.assertEqual(counts['control'], 4)
        self.assertGreater(counts['derp'], 4)
        self.assertEqual(os.listdir(str(self.dir)), ['tailscale-cache.json'])

    def test_failed_source_keeps_old_addresses(self):
        guard.refresh_cache(self.path, self.fetch, now=1000.0)
        old_derp = guard.load_cache(self.path)['sources']['derp']
        self.fetch.failing.add('derp')
        cache, errors = guard.refresh_cache(self.path, self.fetch, now=2000.0)
        self.assertIn('derp', errors)
        self.assertEqual(cache['sources']['derp'], old_derp)
        self.assertEqual(cache['sources']['control']['updated'], 2000.0)
        self.assertEqual(guard.load_cache(self.path), cache)

    def test_total_failure_leaves_file_alone(self):
        guard.refresh_cache(self.path, self.fetch, now=1000.0)
        before = self.path.read_bytes()
        self.fetch.failing.update(('derp', 'control'))
        cache, errors = guard.refresh_cache(self.path, self.fetch, now=2000.0)
        self.assertEqual(set(errors), {'derp', 'control'})
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(guard.cache_counts(cache)[1], 1000.0)

    def test_no_cache_and_total_failure(self):
        self.fetch.failing.update(('derp', 'control'))
        cache, errors = guard.refresh_cache(self.path, self.fetch, now=1.0)
        self.assertIsNone(cache)
        self.assertFalse(self.path.exists())
        self.assertEqual(guard.cache_addresses(cache), [])

    def test_tampered_cache_rejected(self):
        data = sample_cache()
        data['sources']['derp']['addresses'].append('192.168.1.1')
        self.path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            guard.load_cache(self.path)
        cache, errors = guard.refresh_cache(self.path, self.fetch, now=3000.0)
        self.assertIn('cache', errors)
        self.assertNotIn('192.168.1.1', guard.cache_addresses(cache))
        guard.load_cache(self.path)

    def test_unknown_source_rejected(self):
        data = sample_cache()
        data['sources']['extra'] = {'updated': 1.0, 'addresses': ['1.1.1.1']}
        with self.assertRaises(ValueError):
            guard.check_cache(data)

    def test_merge_over_limit_discards_refresh(self):
        big = [str(ipaddress.ip_address('11.0.0.0') + i) for i in range(guard.MAX_ADDRESSES - 2)]
        old = {'version': 1, 'sources': {'derp': {'updated': 1.0, 'addresses': big}}}
        self.path.write_text(json.dumps(old))
        before = self.path.read_bytes()
        self.fetch.failing.add('derp')
        cache, errors = guard.refresh_cache(self.path, self.fetch, now=2.0)
        self.assertIn('merge', errors)
        self.assertEqual(cache, old)
        self.assertEqual(self.path.read_bytes(), before)

    def test_missing_cache_is_none(self):
        self.assertIsNone(guard.load_cache(self.dir / 'missing.json'))


if __name__ == '__main__':
    unittest.main()
