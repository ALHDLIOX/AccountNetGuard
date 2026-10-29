"""断网规则的内容，以及真实 pfctl 的语法检查（pfctl -n 只解析，不加载，不需要 root）。"""
import ipaddress
import os
import re
import unittest

from support import guard, sample_cache

PFCTL = os.path.exists(guard.PFCTL)
INFRA = guard.cache_addresses(sample_cache())


def pf_parse(text):
    return guard.run([guard.PFCTL, '-n', '-v', '-o', 'none', '-a', guard.ANCHOR, '-f', '-'], input=text)


class RuleContentTests(unittest.TestCase):
    def variants(self):
        for tailscale in ((), ('utun3',), ('utun3', 'utun12')):
            for infra in ((), INFRA):
                yield tailscale, infra, guard.block_rules(tailscale, infra)

    def test_never_match_user_or_group(self):
        for _, _, text in self.variants():
            self.assertIsNone(re.search(r'\b(user|group)\b', text), text)

    def test_every_pass_is_quick_and_stateless(self):
        for _, _, text in self.variants():
            for line in text.splitlines():
                if line.startswith('pass'):
                    self.assertTrue(line.startswith('pass out quick '), line)
                    self.assertTrue(line.endswith(' no state'), line)

    def test_blocks_come_last_and_cover_both_families(self):
        for _, _, text in self.variants():
            lines = [line for line in text.splitlines() if line and not line.startswith('#')]
            self.assertEqual(lines[-2:], ['block return out quick inet all', 'block return out quick inet6 all'])
            self.assertEqual(sum(line.startswith('block') for line in lines), 2)
            self.assertTrue(guard.has_block(text))

    def test_only_outbound(self):
        for _, _, text in self.variants():
            for line in text.splitlines():
                if line.startswith(('pass', 'block')):
                    self.assertIn(' out ', line)

    def test_allowed_destinations(self):
        text = guard.block_rules(('utun3',), INFRA)
        for net in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '224.0.0.0/4',
                    'fe80::/10', 'ff00::/8', '100.64.0.0/10', 'fd7a:115c:a1e0::/48'):
            self.assertIn(net, text)
        self.assertIn('pass out quick on lo0 all no state', text)
        self.assertIn('pass out quick on utun3 all no state', text)
        self.assertIn('from any port 68 to any port 67', text)
        self.assertIn('proto tcp to <tailscale_infra> port { 80, 443 }', text)
        self.assertIn('proto udp to <tailscale_infra> port 3478', text)
        self.assertNotIn('fc00::/7', text)
        self.assertNotIn('fd00::/8', text)
        self.assertNotIn('41641', text)

    def test_without_tailscale_or_cache(self):
        text = guard.block_rules()
        self.assertEqual(text, guard.MINIMAL_RULES)
        self.assertNotIn('<tailscale_infra>', text)
        self.assertNotIn(' on utun', text)
        self.assertIn('100.64.0.0/10', text)

    def test_rejects_bad_input(self):
        for name in ('en0', 'utun3 all; pass', '', None, 'utun1234567'):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    guard.block_rules((name,), ())
        for address in ('10.0.0.1', '198.18.0.1', '100.100.100.100', 'fd7a:115c:a1e0::1', '::1', 'not-an-ip'):
            with self.subTest(address=address):
                with self.assertRaises(ValueError):
                    guard.block_rules((), (address,))
        too_many = [str(ipaddress.ip_address('11.0.0.0') + i) for i in range(guard.MAX_ADDRESSES + 1)]
        with self.assertRaises(ValueError):
            guard.block_rules((), too_many)

    def test_has_block_on_pfctl_style_output(self):
        self.assertTrue(guard.has_block('pass out quick on lo0 all no state\nblock return out quick inet all\n'))
        self.assertFalse(guard.has_block('pass out quick on lo0 all no state\n'))
        self.assertFalse(guard.has_block(''))


@unittest.skipUnless(PFCTL, '没有 /sbin/pfctl')
class PfctlSyntaxTests(unittest.TestCase):
    def assertParses(self, text):
        result = pf_parse(text)
        self.assertTrue(result.ok, result.brief())
        return result.out

    def test_all_variants_parse(self):
        for tailscale in ((), ('utun3',), ('utun3', 'utun12')):
            for infra in ((), INFRA):
                with self.subTest(tailscale=tailscale, infra=bool(infra)):
                    self.assertParses(guard.block_rules(tailscale, infra))

    def test_parsed_output_still_recognised(self):
        out = self.assertParses(guard.block_rules(('utun3',), INFRA))
        self.assertTrue(guard.has_block(out))
        self.assertIsNone(re.search(r'\b(user|group)\b', out))
        for line in out.splitlines():
            if line.startswith('pass'):
                self.assertTrue(line.endswith('no state'), line)
        self.assertIn('block return out quick inet6 all', out)

    def test_full_size_table_parses(self):
        v4 = [str(ipaddress.ip_address('11.0.0.0') + i) for i in range(guard.MAX_ADDRESSES // 2)]
        v6 = [str(ipaddress.ip_address('2606:4700::') + i) for i in range(guard.MAX_ADDRESSES // 2)]
        self.assertParses(guard.block_rules(('utun3',), v4 + v6))

    def test_pfctl_really_checks_syntax(self):
        result = pf_parse('pass out quick on lo0 all no state\nthis is not a rule\n')
        self.assertFalse(result.ok)


if __name__ == '__main__':
    unittest.main()
