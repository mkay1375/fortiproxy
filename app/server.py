"""Local-only HTTP control plane; passwords exist only in a private runtime file."""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent


def validate_config(data):
    if not isinstance(data, dict):
        raise ValueError('Enter a connection configuration.')
    allowed = {'name', 'host', 'port', 'username', 'password', 'realm', 'trusted_cert', 'otp'}
    if set(data) - allowed:
        raise ValueError('Unknown connection field.')
    result = {}
    for key in allowed - {'port'}:
        value = data.get(key, '')
        if not isinstance(value, str) or len(value) > 255 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError(f'Invalid {key.replace("_", " ")}.')
        if value != value.strip():
            raise ValueError(f'Remove leading or trailing spaces from {key.replace("_", " ")}.')
        result[key] = value
    if not result['host'] or not result['username'] or not result['password']:
        raise ValueError('Gateway, username and password are required.')
    host = result['host']
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', x) for x in host.split('.')):
            raise ValueError('Enter an IPv4 address or hostname without a URL or port.')
    port = data.get('port', 443)
    if isinstance(port, bool) or not isinstance(port, (int, str)) or not str(port).isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('Port must be between 1 and 65535.')
    result['port'] = int(port)
    if result['trusted_cert'] and not re.fullmatch('[a-fA-F0-9]{64}', result['trusted_cert']):
        raise ValueError('Trusted certificate must be a 64-character SHA-256 fingerprint.')
    return result


class VPNManager:
    def __init__(self, runtime='/run/fortiproxy', timeout=60, run=subprocess.run, popen=subprocess.Popen):
        self.runtime = Path(runtime)
        self.timeout = timeout
        self.run = run
        self.popen = popen
        self.lock = threading.RLock()
        self.process = None
        self.worker = None
        self.generation = 0
        self.state = 'disconnected'
        self.message = 'Ready to connect.'
        self.connected_at = None

    def status(self):
        with self.lock:
            return {'state': self.state, 'message': self.message, 'connected_at': self.connected_at,
                    'interface': 'ppp0' if self.state == 'connected' else None,
                    'proxies': {'socks': '127.0.0.1:1080', 'http': '127.0.0.1:8888'}}

    def connect(self, data):
        config = validate_config(data)
        with self.lock:
            if self.state in ('connecting', 'connected', 'disconnecting') or (self.worker and self.worker.is_alive()):
                raise RuntimeError('Disconnect the current connection first.')
            self.generation += 1
            generation = self.generation
            self.state, self.message = 'connecting', 'Establishing the SSL VPN tunnel…'
            self.connected_at = None
            self.worker = threading.Thread(target=self._connect, args=(config, generation), daemon=True)
            self.worker.start()
        return self.status()

    def _alive(self, generation):
        return self.generation == generation

    def _tunnel_ready(self):
        result = self.run(['ip', '-j', '-4', 'address', 'show', 'dev', 'ppp0'], capture_output=True, text=True, timeout=3)
        if result.returncode:
            return False
        return any(x.get('addr_info') for x in json.loads(result.stdout))

    def _connect(self, config, generation):
        process = None
        failure = None
        routed = False
        path = self.runtime / f'connection-{generation}.conf'
        try:
            self.runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
            # openfortivpn parses key/value lines; validation forbids line injection.
            lines = [f'{key.replace("_", "-")} = {value}' for key, value in config.items()
                     if key != 'name' and value != '']
            lines += ['set-routes = 0', 'set-dns = 1', 'pppd-use-peerdns = 0',
                      'pppd-ifname = ppp0']
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w') as output:
                output.write('\n'.join(lines) + '\n')
            with self.lock:
                if not self._alive(generation):
                    return
                bootstrap = self.runtime / 'bootstrap-resolv.conf'
                if bootstrap.exists():
                    Path('/etc/resolv.conf').write_text(bootstrap.read_text())
                process = self.popen(['openfortivpn', '-c', str(path)], stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                self.process = process
            started = time.monotonic()
            while True:
                with self.lock:
                    if not self._alive(generation):
                        return
                    if process.poll() is not None:
                        raise RuntimeError('VPN connection ended. Check your credentials, gateway and certificate; reconnect to retry.')
                    ready = self._tunnel_ready()
                    if self.state == 'connecting' and ready:
                        self.run(['ip', 'route', 'replace', 'table', '108', 'default', 'dev', 'ppp0', 'metric', '10'], check=True, capture_output=True, timeout=3)
                        routed = True
                        self.state, self.message = 'connected', 'Tunnel connected. Proxy traffic is restricted to the VPN.'
                        self.connected_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
                        path.unlink(missing_ok=True)
                    elif self.state == 'connected' and not ready:
                        raise RuntimeError('VPN tunnel was lost. Proxy traffic is blocked; reconnect to retry.')
                    elif self.state == 'connecting' and time.monotonic() - started > self.timeout:
                        raise RuntimeError('Connection timed out. Check your settings or enter a fresh one-time code.')
                time.sleep(0.5)
        except Exception as error:
            failure = str(error) if isinstance(error, RuntimeError) else 'Unable to start the VPN. Check the container runtime permissions.'
        finally:
            if routed:
                try:
                    self.run(['ip', 'route', 'del', 'table', '108', 'default', 'dev', 'ppp0', 'metric', '10'], capture_output=True, timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    pass  # The process must still be reaped and secrets removed.
            try:
                if process is not None:
                    self._stop(process)
            finally:
                path.unlink(missing_ok=True)
            with self.lock:
                if self.process is process:
                    self.process = None
                if self._alive(generation) and failure:
                    self.state, self.message = 'error', failure
                    self.connected_at = None
                elif not self._alive(generation) and self.state == 'disconnecting':
                    self.state, self.message = 'disconnected', 'Disconnected. Proxy traffic is blocked.'

    @staticmethod
    def _stop(process):
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        except ProcessLookupError:
            pass
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)

    def disconnect(self):
        with self.lock:
            if self.state == 'disconnecting':
                return self.status()
            self.generation += 1
            worker = self.worker
            self.state, self.message = 'disconnecting', 'Stopping the VPN…'
            self.connected_at = None
        # The worker owns teardown, including the process group and secret file.
        # No new connect is accepted until that teardown has completed.
        if worker is not None:
            worker.join(timeout=12)
            if worker.is_alive():
                return self.status()
        with self.lock:
            self.state, self.message = 'disconnected', 'Disconnected. Proxy traffic is blocked.'
        return self.status()


manager = VPNManager(os.environ.get('FORTIPROXY_RUNTIME', '/run/fortiproxy'))


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / 'web'), **kwargs)

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def do_HEAD(self):
        self.send_error(405)

    def log_message(self, *args):
        pass  # Never log submitted settings, credentials or request paths.

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        super().end_headers()

    def _json(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _local_host(self):
        host = self.headers.get('Host', '')
        try:
            parsed = urlsplit('http://' + host)
            return parsed.hostname in ('localhost', '127.0.0.1', '::1') and (parsed.port is None or 1 <= parsed.port <= 65535) and not parsed.username and parsed.path == '' and not parsed.fragment and not parsed.query
        except ValueError:
            return False

    def do_GET(self):
        if not self._local_host():
            return self._json(403, {'error': 'Use the localhost address to open Fortiproxy.'})
        if self.path == '/api/status':
            return self._json(200, manager.status())
        if self.path.startswith('/api/'):
            return self._json(404, {'error': 'Unknown endpoint.'})
        if '?' in self.path:
            self.path = self.path.split('?', 1)[0]
        if self.path != '/' and not re.fullmatch(r'/[A-Za-z0-9_-]+\.(?:css|js|svg|ico)', self.path):
            return self._json(404, {'error': 'Not found.'})
        super().do_GET()

    def do_POST(self):
        origin = self.headers.get('Origin')
        if not self._local_host() or self.headers.get('X-Fortiproxy-Request') != '1' or (origin and origin != 'http://' + self.headers.get('Host', '')):
            return self._json(403, {'error': 'Request must come from the local Fortiproxy page.'})
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            return self._json(415, {'error': 'Expected JSON.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 8192:
                raise ValueError('Request body is too large or empty.')
            data = json.loads(self.rfile.read(length))
            if self.path == '/api/connect':
                return self._json(202, manager.connect(data))
            if self.path == '/api/disconnect':
                return self._json(200, manager.disconnect())
            return self._json(404, {'error': 'Unknown endpoint.'})
        except (ValueError, json.JSONDecodeError) as error:
            return self._json(400, {'error': str(error)})
        except RuntimeError as error:
            return self._json(409, {'error': str(error)})


def main():
    server = ThreadingHTTPServer((os.environ.get('FORTIPROXY_BIND', '0.0.0.0'), int(os.environ.get('FORTIPROXY_PORT', '8787'))), Handler)
    server.timeout = 1
    stopping = threading.Event()
    def stop(*_):
        stopping.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not stopping.is_set():
            server.handle_request()
    finally:
        manager.disconnect()
        server.server_close()


if __name__ == '__main__':
    main()
