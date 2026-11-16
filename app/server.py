"""Local-only HTTP control plane with explicit, private saved-password opt-in."""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import tempfile
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent


PROFILE_FIELDS = ('name', 'host', 'port', 'username', 'realm', 'trusted_cert', 'ignore_cert', 'otp_mode', 'save_password')


def validate_config(data, *, profile=False):
    if not isinstance(data, dict):
        raise ValueError('Enter a connection configuration.')
    allowed = set(PROFILE_FIELDS) if profile else set(PROFILE_FIELDS) | {'password', 'otp'}
    if set(data) - allowed:
        raise ValueError('Unknown connection field.')
    result = {}
    ignore_cert = data.get('ignore_cert', False)
    if not isinstance(ignore_cert, bool):
        raise ValueError('Ignore certificate validation must be true or false.')
    result['ignore_cert'] = ignore_cert
    save_password = data.get('save_password', False)
    if not isinstance(save_password, bool):
        raise ValueError('Save password must be true or false.')
    result['save_password'] = save_password
    result['otp_mode'] = data.get('otp_mode', 'append')
    if result['otp_mode'] not in ('append', 'separate'):
        raise ValueError('Choose append-to-password or separate-challenge OTP mode.')
    for key in allowed - {'port', 'ignore_cert', 'otp_mode', 'save_password'}:
        value = data.get(key, '')
        if not isinstance(value, str) or len(value) > 255 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError(f'Invalid {key.replace("_", " ")}.')
        if value != value.strip():
            raise ValueError(f'Remove leading or trailing spaces from {key.replace("_", " ")}.')
        result[key] = value
    if not profile and (not result['host'] or not result['username'] or not result['password']):
        raise ValueError('Gateway, username and password are required.')
    host = result['host']
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if host and (len(host) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', x) for x in host.split('.'))):
            raise ValueError('Enter an IPv4 address or hostname without a URL or port.')
    port = data.get('port', 443)
    if isinstance(port, bool) or not isinstance(port, (int, str)) or not str(port).isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('Port must be between 1 and 65535.')
    result['port'] = int(port)
    if result['trusted_cert'] and not re.fullmatch('[a-fA-F0-9]{64}', result['trusted_cert']):
        raise ValueError('Trusted certificate must be a 64-character SHA-256 fingerprint.')
    if not profile:
        credential = result['password'] + (result['otp'] if result['otp_mode'] == 'append' else '')
        if len(credential.encode('utf-8')) > 256:
            raise ValueError('Password plus appended code must fit in 256 UTF-8 bytes.')
        if result['otp_mode'] == 'separate' and len(result['otp'].encode('utf-8')) > 64:
            raise ValueError('A separate one-time code must fit in 64 UTF-8 bytes.')
    return result


def test_gateway(data):
    if not isinstance(data, dict) or set(data) - {'host', 'port'}:
        raise ValueError('Enter only the gateway and port for this test.')
    config = validate_config(data, profile=True)
    if not config['host']:
        raise ValueError('Enter a gateway address to test.')
    # A separate process bounds hostname resolution as well as TCP connect time.
    # This checks TCP reachability only; it never sends VPN login credentials.
    try:
        result = subprocess.run(
            [sys.executable, '-c',
             'import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=4).close()',
             config['host'], str(config['port'])],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        reachable = result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        reachable = False
    return {'reachable': reachable, 'message':
            'Gateway TCP port is reachable. VPN login and TLS were not tested.' if reachable else
            'Gateway TCP port could not be reached. Check the address, port and network access.'}


def gateway_fingerprint(host, port):
    """Accept this attempt's presented certificate without CA/hostname checks.

    The subprocess bounds DNS and TLS time, receives no login credentials, and
    returns only the digest. No observed certificate is persisted or trusted by
    the operating system. The VPN client still uses TLS and this digest.
    """
    probe = """import hashlib,socket,ssl,sys
context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname=False
context.verify_mode=ssl.CERT_NONE
context.minimum_version=ssl.TLSVersion.TLSv1_2
with socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=5) as raw:
    with context.wrap_socket(raw,server_hostname=sys.argv[1]) as peer:
        print(hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest())
"""
    try:
        result = subprocess.run([sys.executable, '-c', probe, host, str(port)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, timeout=8)
        digest = result.stdout.strip()
        if result.returncode or not re.fullmatch('[a-f0-9]{64}', digest):
            raise RuntimeError('Could not read the gateway certificate. Check the gateway address, port and TLS service.')
        return digest
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('Gateway certificate lookup failed or timed out. Check the gateway address, port and network access.') from None


class ProfileStore:
    """Private profile storage; base passwords persist only after explicit opt-in."""
    BINDING_FIELDS = ('host', 'port', 'username', 'realm')

    def __init__(self, directory):
        self.directory = Path(directory)
        self.path = self.directory / 'profile.json'
        self.lock = threading.Lock()

    @classmethod
    def _binding(cls, profile):
        return tuple(profile.get(key) for key in cls.BINDING_FIELDS)

    @staticmethod
    def _public(profile):
        if not profile:
            return {}
        public = {key: value for key, value in profile.items() if key != 'password'}
        public['has_saved_password'] = bool(profile.get('save_password') and profile.get('password'))
        return public

    @staticmethod
    def _validate_profile(data):
        if not isinstance(data, dict):
            raise ValueError('Enter a connection configuration.')
        fields = {key: value for key, value in data.items() if key != 'password'}
        profile = validate_config(fields, profile=True)
        if 'password' in data:
            if not profile['save_password']:
                raise ValueError('Enable Save password before storing a password.')
            password = data['password']
            if password != '':
                # The native credential validation also bounds UTF-8 byte length.
                profile['password'] = validate_config({**profile, 'password': password})['password']
        return profile

    def _read(self):
        try:
            return self._validate_profile(json.loads(self.path.read_text()))
        except FileNotFoundError:
            return {}

    def load(self):
        with self.lock:
            return self._public(self._read())

    def save(self, data):
        profile = self._validate_profile(data)
        with self.lock:
            previous = self._read()
            if (profile['save_password'] and 'password' not in profile
                    and previous.get('save_password') and previous.get('password')
                    and self._binding(profile) == self._binding(previous)):
                profile['password'] = previous['password']
            self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
            self.directory.chmod(0o700)
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(mode='w', dir=self.directory,
                                                 prefix='.profile-', delete=False) as output:
                    temporary = Path(output.name)
                    json.dump(profile, output)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, self.path)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
        return self._public(profile)

    def resolve_connect(self, data):
        """Resolve an omitted base password without returning it through an API."""
        if not isinstance(data, dict) or set(data) - (set(PROFILE_FIELDS) | {'password', 'otp'}):
            raise ValueError('Unknown connection field.')
        config = dict(data)
        if config.get('password', '') != '' or config.get('save_password') is not True:
            return validate_config(config)
        target = validate_config({key: value for key, value in config.items()
                                  if key in PROFILE_FIELDS}, profile=True)
        with self.lock:
            saved = self._read()
            if (not saved.get('save_password') or not saved.get('password')
                    or self._binding(target) != self._binding(saved)):
                raise ValueError('No saved password matches this connection. Enter your password.')
            config['password'] = saved['password']
        return validate_config(config)


class VPNDiagnostics:
    """Drain client output, retaining only a fixed, non-secret error category."""
    RULES = (
        (('certificate validation failed', 'certificate verify failed', 'self-signed certificate', 'hostname mismatch'),
         'Gateway certificate validation failed. Ask your VPN administrator for a verified SHA-256 fingerprint and enter it in Additional settings. TLS verification remains enabled.'),
        (('could not read otp', 'could not read the otp', 'could not read token', 'could not read the token'),
         'The gateway requested a one-time code. Enter a fresh code in Additional settings and reconnect.'),
        (('could not authenticate', 'authentication failed', 'login failed', 'permission denied by gateway'),
         'Gateway login was rejected. Check your username, password, realm and any required one-time code.'),
        (('bad key in configuration', 'bad value in configuration', 'unrecognized option', 'invalid option'),
         'The VPN client rejected a connection option. Check the container client configuration.'),
        (('could not open /dev/ppp', 'pppd:', 'pppd exited', 'ppp support', 'failed to start pppd'),
         'The PPP tunnel could not start or stopped unexpectedly. Check the container PPP device and permissions.'),
        (('ssl_connect', 'tls handshake', 'ssl handshake', 'handshake failure'),
         'The gateway TLS handshake failed. Check the gateway address, port and server TLS requirements.'),
        (('getaddrinfo', 'could not resolve', 'connection refused', 'connection timed out', 'could not connect', 'no route to host', 'network is unreachable'),
         'The VPN client could not reach the gateway. Use Test gateway and check the address, port and network access.'),
    )

    def __init__(self):
        self.category = len(self.RULES)
        self.ready = threading.Event()
        self.lock = threading.Lock()

    def read(self, stream):
        try:
            while True:
                chunk = stream.readline(4096)
                if not chunk:
                    break
                text = chunk.decode('utf-8', errors='replace').lower()
                if text.startswith('info:') and text.split(':', 1)[1].strip() == 'tunnel is up and running.':
                    self.ready.set()
                for index, (patterns, _) in enumerate(self.RULES):
                    if any(pattern in text for pattern in patterns):
                        with self.lock:
                            self.category = min(self.category, index)
                        break
        except (OSError, ValueError):
            pass
        finally:
            stream.close()

    def message(self, returncode):
        with self.lock:
            if self.category < len(self.RULES):
                return self.RULES[self.category][1]
        return f'VPN client exited (code {returncode}). No recognized failure reason was reported. Check the gateway requirements with your VPN administrator.'


class VPNManager:
    def __init__(self, runtime='/run/fortiproxy', timeout=60, run=subprocess.run, popen=subprocess.Popen, certificate_fetch=gateway_fingerprint):
        self.runtime = Path(runtime)
        self.timeout = timeout
        self.run = run
        self.popen = popen
        self.certificate_fetch = certificate_fetch
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
                    'proxies': {'socks': '127.0.0.1:48732', 'http': '127.0.0.1:48733'}}

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
        reader = None
        diagnostics = VPNDiagnostics()
        failure = None
        routed = False
        path = self.runtime / f'connection-{generation}.conf'
        try:
            self.runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
            with self.lock:
                if not self._alive(generation):
                    return
                bootstrap = self.runtime / 'bootstrap-resolv.conf'
                if bootstrap.exists():
                    Path('/etc/resolv.conf').write_text(bootstrap.read_text())
            client = {key: value for key, value in config.items()
                      if key not in ('name', 'ignore_cert', 'otp_mode', 'save_password')}
            if config['otp_mode'] == 'append':
                client['password'] += client.pop('otp', '')
            if config['ignore_cert']:
                client['trusted_cert'] = self.certificate_fetch(config['host'], config['port'])
            # Validation forbids line injection; only native client keys are emitted.
            lines = [f'{key.replace("_", "-")} = {value}' for key, value in client.items() if value != '']
            lines += ['set-routes = 0', 'set-dns = 1', 'pppd-use-peerdns = 0',
                      'pppd-ifname = ppp0']
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w') as output:
                output.write('\n'.join(lines) + '\n')
            with self.lock:
                if not self._alive(generation):
                    return
                process = self.popen(['openfortivpn', '-c', str(path)], stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
                self.process = process
                if getattr(process, 'stdout', None) is not None:
                    reader = threading.Thread(target=diagnostics.read, args=(process.stdout,), daemon=True)
                    reader.start()
            started = time.monotonic()
            while True:
                with self.lock:
                    if not self._alive(generation):
                        return
                    returncode = process.poll()
                    if returncode is not None:
                        if reader is not None:
                            reader.join(timeout=1)
                        raise RuntimeError(diagnostics.message(returncode))
                    ready = self._tunnel_ready()
                    if self.state == 'connecting' and ready and diagnostics.ready.is_set():
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
                if reader is not None:
                    reader.join(timeout=1)
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
profiles = ProfileStore(os.environ.get('FORTIPROXY_DATA', str(ROOT / 'data')))


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
        if self.path == '/api/profile':
            try:
                return self._json(200, profiles.load())
            except (OSError, ValueError):
                return self._json(503, {'error': 'Unable to read saved settings. Check the profile data volume.'})
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
            if self.path == '/api/test-gateway':
                return self._json(200, test_gateway(data))
            if self.path == '/api/profile':
                return self._json(200, profiles.save(data))
            if self.path == '/api/connect':
                return self._json(202, manager.connect(profiles.resolve_connect(data)))
            if self.path == '/api/disconnect':
                return self._json(200, manager.disconnect())
            return self._json(404, {'error': 'Unknown endpoint.'})
        except (ValueError, json.JSONDecodeError) as error:
            return self._json(400, {'error': str(error)})
        except OSError:
            return self._json(503, {'error': 'Unable to save settings. Check the profile data volume.'})
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
