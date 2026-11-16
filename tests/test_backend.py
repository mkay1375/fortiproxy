import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from app.server import VPNManager, validate_config


CONFIG = {'host': 'vpn.example.test', 'port': 10443, 'username': 'test-user', 'password': 'test-password'}


class ValidationTests(unittest.TestCase):
    def test_ssl_custom_port_no_client_certificate(self):
        config = validate_config(CONFIG)
        self.assertEqual(config['port'], 10443)
        self.assertEqual(config['trusted_cert'], '')

    def test_rejects_config_injection_and_silent_password_changes(self):
        for key, value in [('password', 'secret\nset-dns = 0'), ('username', 'x\rpassword=y'),
                           ('host', 'https://vpn.example.test'), ('password', ' secret '),
                           ('host', '-gateway'), ('trusted_cert', 'invalid')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validate_config({**CONFIG, key: value})

    def test_rejects_bad_ports_and_unknown_options(self):
        for value in [True, 0, 65536, 'abc', 1.5]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_config({**CONFIG, 'port': value})
        with self.assertRaises(ValueError):
            validate_config({**CONFIG, 'insecure-ssl': True})


class FakeProcess:
    pid = 99999999
    def __init__(self):
        self.returncode = None
    def poll(self):
        return self.returncode
    def wait(self, timeout):
        self.returncode = -15


def eventually(predicate):
    for _ in range(100):
        if predicate():
            return
        time.sleep(.02)
    raise AssertionError('condition did not become true')


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.process = FakeProcess()
        self.spawned = []
        self.ready = False
        def spawn(args, **kwargs):
            path = Path(args[-1])
            self.spawned.append((path.read_text(), path.stat().st_mode & 0o777, kwargs))
            return self.process
        self.manager = VPNManager(self.temp.name, timeout=.05, popen=spawn, run=lambda *a, **kw: None)
        self.manager._tunnel_ready = lambda: self.ready
        self.manager._stop = lambda process: process.wait(1)

    def tearDown(self):
        self.manager.disconnect()
        self.temp.cleanup()

    def test_disconnect_cleans_secret_and_stops_process(self):
        self.manager.connect(CONFIG)
        eventually(lambda: bool(self.spawned))
        self.assertEqual(self.spawned[0][1], 0o600)
        self.assertTrue(self.spawned[0][2]['start_new_session'])
        self.assertNotIn('password', json.dumps(self.manager.status()))
        self.manager.disconnect()
        self.assertEqual(self.process.poll(), -15)
        self.assertEqual(list(Path(self.temp.name).glob('connection-*')), [])
        self.assertEqual(self.manager.status()['state'], 'disconnected')

    def test_connected_requires_interface_then_lost_tunnel_cleans_up(self):
        self.manager.timeout = 5
        self.ready = True
        self.manager.connect(CONFIG)
        eventually(lambda: self.manager.status()['state'] == 'connected')
        self.assertEqual(list(Path(self.temp.name).glob('connection-*')), [])
        self.ready = False
        eventually(lambda: self.manager.status()['state'] == 'error')
        self.assertEqual(self.process.poll(), -15)

    def test_timeout_stops_process_and_removes_secret(self):
        self.manager.connect(CONFIG)
        eventually(lambda: self.manager.status()['state'] == 'error')
        self.assertEqual(self.process.poll(), -15)
        self.assertEqual(list(Path(self.temp.name).glob('connection-*')), [])

    def test_cannot_replace_active_connection(self):
        self.manager.connect(CONFIG)
        with self.assertRaises(RuntimeError):
            self.manager.connect(CONFIG)

    def test_disconnect_waits_before_accepting_new_connection(self):
        entered, release = threading.Event(), threading.Event()
        def stop(_):
            entered.set()
            release.wait(2)
        self.manager._stop = stop
        self.manager.connect(CONFIG)
        eventually(lambda: bool(self.spawned))
        thread = threading.Thread(target=self.manager.disconnect)
        thread.start()
        self.assertTrue(entered.wait(2))
        self.assertEqual(self.manager.status()['state'], 'disconnecting')
        with self.assertRaises(RuntimeError):
            self.manager.connect(CONFIG)
        release.set()
        thread.join(3)
        self.assertEqual(self.manager.status()['state'], 'disconnected')


if __name__ == '__main__':
    unittest.main()
