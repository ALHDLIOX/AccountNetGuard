"""事件源：kqueue 等进程退出，路由 socket 消息过滤。"""
import struct
import subprocess
import time
import unittest

from support import guard


def message(kind, flags=0, length=92):
    head = struct.pack('=HBBHxxi', length, 5, kind, 0, flags)
    return head + b'\0' * (length - len(head))


class RouteMessageTests(unittest.TestCase):
    def test_real_changes(self):
        for kind in (guard.RTM_ADD, guard.RTM_DELETE, guard.RTM_CHANGE, guard.RTM_REDIRECT):
            self.assertTrue(guard.route_message_relevant(message(kind)), kind)
        for kind in (guard.RTM_NEWADDR, guard.RTM_DELADDR, guard.RTM_IFINFO, guard.RTM_IFINFO2):
            self.assertTrue(guard.route_message_relevant(message(kind, length=40)), kind)

    def test_noise_is_ignored(self):
        rtm_get, rtm_miss, rtm_resolve, rtm_newmaddr = 0x4, 0x7, 0xb, 0xf
        for kind in (rtm_get, rtm_miss, rtm_resolve, rtm_newmaddr):
            self.assertFalse(guard.route_message_relevant(message(kind)), kind)
        self.assertFalse(guard.route_message_relevant(message(guard.RTM_ADD, guard.RTF_WASCLONED)))
        self.assertFalse(guard.route_message_relevant(message(guard.RTM_DELETE, guard.RTF_LLINFO | 0x1)))

    def test_truncated_message_counts_as_change(self):
        self.assertTrue(guard.route_message_relevant(b'\x10\x00'))
        self.assertTrue(guard.route_message_relevant(message(guard.RTM_ADD)[:6]))


class KqueueTests(unittest.TestCase):
    def setUp(self):
        self.events = guard.Events()
        self.addCleanup(self.events.close)

    def test_route_socket_opens(self):
        self.assertIsNone(self.events.error)
        self.assertIsNotNone(self.events.route)

    def test_process_exit_is_reported(self):
        proc = subprocess.Popen(['/bin/sleep', '0.3'])
        self.addCleanup(proc.wait)
        self.assertTrue(self.events.watch([proc.pid]))
        began = time.monotonic()
        exited = False
        while not exited and time.monotonic() - began < 5:
            _, exited = self.events.wait(1.0)
        self.assertTrue(exited)
        self.assertLess(time.monotonic() - began, 2.0)
        self.assertNotIn(proc.pid, self.events.watched)

    def test_gone_process_reported_immediately(self):
        proc = subprocess.Popen(['/usr/bin/true'])
        proc.wait()
        self.assertFalse(self.events.watch([proc.pid]))

    def test_wait_respects_timeout(self):
        began = time.monotonic()
        self.events.wait(0.05)
        self.assertLess(time.monotonic() - began, 1.0)


if __name__ == '__main__':
    unittest.main()
