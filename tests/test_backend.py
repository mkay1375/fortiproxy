import json
import http.client
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from app.server import Handler, ThreadingHTTPServer, VPNManager, validate_config


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

    def test_delayed_teardown_finishes_disconnect_after_http_wait(self):
        entered, release = threading.Event(), threading.Event()
        def stop(process):
            entered.set()
            release.wait(2)
            process.wait(1)
        self.manager._stop = stop
        self.manager.connect(CONFIG)
        eventually(lambda: bool(self.spawned))
        worker = self.manager.worker
        join = worker.join
        with patch.object(worker, 'join', side_effect=lambda timeout: join(.01)):
            self.manager.disconnect()
        self.assertTrue(entered.wait(1))
        self.assertEqual(self.manager.status()['state'], 'disconnecting')
        release.set()
        eventually(lambda: self.manager.status()['state'] == 'disconnected')

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


class HTTPBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        result = response.status, response.read()
        connection.close()
        return result

    def test_status_allows_local_mapped_port(self):
        status, body = self.request('GET', '/api/status')
        self.assertEqual(status, 200)
        self.assertNotIn('password', json.loads(body))

    def test_hostile_host_cannot_read_status(self):
        status, _ = self.request('GET', '/api/status', headers={'Host': 'evil.example'})
        self.assertEqual(status, 403)

    def test_changes_require_custom_header_and_matching_origin(self):
        headers = {'Content-Type': 'application/json'}
        self.assertEqual(self.request('POST', '/api/disconnect', '{}', headers)[0], 403)
        headers['X-Fortiproxy-Request'] = '1'
        headers['Origin'] = 'https://evil.example'
        self.assertEqual(self.request('POST', '/api/disconnect', '{}', headers)[0], 403)
        headers['Origin'] = f'http://127.0.0.1:{self.port}'
        self.assertEqual(self.request('POST', '/api/disconnect', '{}', headers)[0], 200)

    def test_unknown_fields_and_large_bodies_rejected_without_connecting(self):
        headers = {'Content-Type': 'application/json', 'X-Fortiproxy-Request': '1'}
        self.assertEqual(self.request('POST', '/api/connect', json.dumps({**CONFIG, 'insecure-ssl': True}), headers)[0], 400)
        self.assertEqual(self.request('POST', '/api/connect', 'x' * 8193, headers)[0], 400)


if __name__ == '__main__':
    unittest.main()
