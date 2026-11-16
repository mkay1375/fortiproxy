import json
import io
import http.client
import os
from pathlib import Path
import subprocess
import socketserver
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from app.server import Handler, ThreadingHTTPServer, VPNManager, ProfileStore, VPNDiagnostics, test_gateway, validate_config


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


class DiagnosticTests(unittest.TestCase):
    def test_errors_are_classified_without_exposing_raw_client_output(self):
        examples = [
            (b'ERROR: Gateway certificate validation failed.', 'certificate validation failed'),
            (b'ERROR: Could not authenticate to gateway.', 'login was rejected'),
            (b'ERROR: Could not read OTP.', 'one-time code'),
            (b'pppd: Could not open /dev/ppp', 'PPP tunnel'),
            (b'ERROR: SSL_connect: handshake failure', 'TLS handshake failed'),
            (b'ERROR: connect: Connection refused', 'could not reach the gateway'),
            (b'pppd: unrecognized option bad-option', 'rejected a connection option'),
        ]
        for output, expected in examples:
            with self.subTest(output=output):
                diagnostics = VPNDiagnostics()
                diagnostics.read(io.BytesIO(output + b' password=super-secret SVPNCOOKIE=private-session'))
                message = diagnostics.message(1)
                self.assertIn(expected, message)
                self.assertNotIn('super-secret', message)
                self.assertNotIn('private-session', message)
                self.assertNotIn('SVPNCOOKIE', message)

    def test_certificate_root_cause_wins_over_later_generic_tls_error(self):
        diagnostics = VPNDiagnostics()
        diagnostics.read(io.BytesIO(b'ERROR: Gateway certificate validation failed.\nERROR: SSL_connect failed.\n'))
        self.assertIn('certificate validation failed', diagnostics.message(1))

    def test_unknown_output_does_not_escape_into_status(self):
        diagnostics = VPNDiagnostics()
        diagnostics.read(io.BytesIO(b'secret-cookie=' + b'x' * 100000))
        self.assertIn('code 7', diagnostics.message(7))
        self.assertNotIn('secret-cookie', diagnostics.message(7))


class GatewayTests(unittest.TestCase):
    def test_reachable_and_closed_local_tcp_port_without_vpn_login(self):
        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                pass
        server = socketserver.TCPServer(('127.0.0.1', 0), TCP)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.assertTrue(test_gateway({'host': '127.0.0.1', 'port': port})['reachable'])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertFalse(test_gateway({'host': '127.0.0.1', 'port': port})['reachable'])

    def test_timeout_is_bounded_and_secret_fields_are_rejected(self):
        with patch('app.server.subprocess.run', side_effect=subprocess.TimeoutExpired('tcp-test', 5)) as run:
            self.assertFalse(test_gateway({'host': 'vpn.example.test', 'port': 10443})['reachable'])
            self.assertEqual(run.call_args.kwargs['timeout'], 5)
        with patch('app.server.subprocess.run') as run:
            for data in [{'host': ''}, {'host': 'bad\nhost'}, {'host': 'vpn.example.test', 'password': 'secret'}]:
                with self.subTest(data=data), self.assertRaises(ValueError):
                    test_gateway(data)
            run.assert_not_called()


class ProfileTests(unittest.TestCase):
    def test_disk_round_trip_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProfileStore(Path(directory) / 'data')
            self.assertEqual(store.load(), {})
            profile = {k: v for k, v in CONFIG.items() if k != 'password'}
            profile.update(name='Office', realm='staff', trusted_cert='a' * 64)
            saved = store.save(profile)
            self.assertEqual(ProfileStore(store.directory).load(), saved)
            self.assertNotIn('password', store.path.read_text())
            self.assertNotIn('otp', store.path.read_text())
            self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(store.directory.stat().st_mode & 0o777, 0o700)

    def test_secrets_and_invalid_updates_cannot_replace_saved_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProfileStore(directory)
            original = store.save({'host': 'vpn.example.test', 'port': 10443})
            for extra in [{'password': 'never-store-this'}, {'otp': '654321'}, {'host': 'bad\nhost'}]:
                with self.subTest(extra=extra), self.assertRaises(ValueError):
                    store.save({**original, **extra})
                self.assertEqual(store.load(), original)
            self.assertEqual(list(Path(directory).glob('.profile-*')), [])

    def test_atomic_write_failure_preserves_previous_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProfileStore(directory)
            original = store.save({'name': 'Original'})
            with patch('app.server.os.replace', side_effect=OSError('disk failure')):
                with self.assertRaises(OSError):
                    store.save({'name': 'Replacement'})
            self.assertEqual(store.load(), original)
            self.assertEqual(list(Path(directory).glob('.profile-*')), [])


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
        self.process.stdout = io.BytesIO(b'INFO:   Tunnel is up and running.\n')
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

    def test_interface_address_alone_does_not_report_connected(self):
        self.process.stdout = io.BytesIO(b'INFO: Negotiating tunnel.\n')
        self.ready = True
        self.manager.connect(CONFIG)
        eventually(lambda: self.manager.status()['state'] == 'error')
        self.assertIn('timed out', self.manager.status()['message'])
        self.assertIsNone(self.manager.status()['connected_at'])

    def test_timeout_stops_process_and_removes_secret(self):
        self.manager.connect(CONFIG)
        eventually(lambda: self.manager.status()['state'] == 'error')
        self.assertEqual(self.process.poll(), -15)
        self.assertEqual(list(Path(self.temp.name).glob('connection-*')), [])

    def test_early_client_exit_reports_safe_certificate_error_and_cleans_secret(self):
        self.process.stdout = io.BytesIO(b'ERROR: Gateway certificate validation failed. password=do-not-display\n')
        self.process.returncode = 1
        self.manager.connect(CONFIG)
        eventually(lambda: self.manager.status()['state'] == 'error')
        self.assertIn('certificate validation failed', self.manager.status()['message'])
        self.assertNotIn('do-not-display', json.dumps(self.manager.status()))
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
        self.profile_directory = tempfile.TemporaryDirectory()
        self.profile_patch = patch('app.server.profiles', ProfileStore(self.profile_directory.name))
        self.profile_patch.start()
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.profile_patch.stop()
        self.profile_directory.cleanup()

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

    def test_profile_api_restores_settings_and_rejects_secrets_and_foreign_requests(self):
        headers = {'Content-Type': 'application/json', 'X-Fortiproxy-Request': '1'}
        profile = {'name': 'Office', 'host': 'vpn.example.test', 'port': 10443, 'username': 'test-user'}
        self.assertEqual(self.request('GET', '/api/profile'), (200, b'{}'))
        self.assertEqual(self.request('POST', '/api/profile', json.dumps(profile), headers)[0], 200)
        for secret in ['password', 'otp']:
            self.assertEqual(self.request('POST', '/api/profile', json.dumps({**profile, secret: 'secret'}), headers)[0], 400)
        code, body = self.request('GET', '/api/profile')
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)['host'], profile['host'])
        self.assertNotIn('password', json.loads(body))
        self.assertNotIn('otp', json.loads(body))
        headers['Origin'] = 'https://foreign.invalid'
        self.assertEqual(self.request('POST', '/api/profile', json.dumps(profile), headers)[0], 403)

    def test_gateway_api_checks_request_boundaries(self):
        headers = {'Content-Type': 'application/json', 'X-Fortiproxy-Request': '1'}
        data = json.dumps({'host': 'vpn.example.test', 'port': 10443})
        with patch('app.server.test_gateway', return_value={'reachable': True, 'message': 'TCP port reachable'}) as check:
            status, body = self.request('POST', '/api/test-gateway', data, headers)
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(body)['reachable'])
            check.assert_called_once_with({'host': 'vpn.example.test', 'port': 10443})
            headers['Origin'] = 'https://foreign.invalid'
            self.assertEqual(self.request('POST', '/api/test-gateway', data, headers)[0], 403)
            self.assertEqual(check.call_count, 1)

    def test_unknown_fields_and_large_bodies_rejected_without_connecting(self):
        headers = {'Content-Type': 'application/json', 'X-Fortiproxy-Request': '1'}
        self.assertEqual(self.request('POST', '/api/connect', json.dumps({**CONFIG, 'insecure-ssl': True}), headers)[0], 400)
        self.assertEqual(self.request('POST', '/api/connect', 'x' * 8193, headers)[0], 400)


if __name__ == '__main__':
    unittest.main()
