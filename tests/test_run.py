"""外部命令封装：超时一定返回，子进程卡住也不会无限等待。"""
import time
import unittest

from support import guard


class RunTests(unittest.TestCase):
    def test_output_and_exit_code(self):
        result = guard.run(['/bin/echo', 'hello'])
        self.assertTrue(result.ok)
        self.assertEqual(result.out, 'hello\n')
        result = guard.run(['/bin/sh', '-c', 'echo oops >&2; exit 3'])
        self.assertEqual(result.code, 3)
        self.assertFalse(result.ok)
        self.assertIn('oops', result.brief())

    def test_input(self):
        self.assertEqual(guard.run(['/bin/cat'], input='规则\n').out, '规则\n')

    def test_fixed_environment(self):
        out = guard.run(['/usr/bin/env']).out.splitlines()
        self.assertEqual(sorted(out), sorted('%s=%s' % item for item in guard.ENV.items()))

    def test_missing_program(self):
        result = guard.run(['/nonexistent/program'])
        self.assertIsNone(result.code)
        self.assertFalse(result.ok)
        self.assertIn('cannot run', result.err)

    def test_timeout_kills(self):
        began = time.monotonic()
        result = guard.run(['/bin/sleep', '5'], timeout=0.2, grace=0.5)
        self.assertTrue(result.timed_out)
        self.assertFalse(result.ok)
        self.assertLess(time.monotonic() - began, 2.0)

    def test_grandchild_holding_pipe_is_abandoned(self):
        # sh 被 kill 后，后台的 sleep 还占着输出管道；communicate 等不到 EOF，必须按时放弃。
        began = time.monotonic()
        result = guard.run(['/bin/sh', '-c', 'sleep 3 & sleep 3'], timeout=0.2, grace=0.3)
        elapsed = time.monotonic() - began
        self.assertTrue(result.timed_out)
        self.assertLess(elapsed, 2.0)
        self.assertIn('gave up waiting', result.err)
        proc = guard._ABANDONED[-1]
        proc.wait(timeout=2)
        guard._reap()
        self.assertNotIn(proc, guard._ABANDONED)


if __name__ == '__main__':
    unittest.main()
