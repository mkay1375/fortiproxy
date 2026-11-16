"""TEST ONLY: minimal Fortinet-framed TLS/PPP peer; not Fortinet FortiGate.

Run only via fortisslvpn_smoke.py on its internal Docker network. This implements
a small test subset: password/cookie login, XML config, LCP/IPCP and IPv4.
Protocol reference: https://github.com/adrienverge/openfortivpn/tree/v1.19.0/src
No vendor image, SAML/MFA/endpoint policies or production security are provided.
"""
import fcntl
import hashlib
import http.server
import os
from pathlib import Path
import select
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time
import urllib.parse

ACTIVE_TUNNELS = set()
TUNNEL_LOCK = threading.Lock()

def drop_tunnels(*_):
    with TUNNEL_LOCK:
        for connection in list(ACTIVE_TUNNELS):
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

signal.signal(signal.SIGUSR1, drop_tunnels)

SERVER_IP = '169.254.2.1'
CLIENT_IP = '10.77.0.2'
MARKER = b'fortiproxy-real-ppp-lab'
ROOT = Path('/tmp/fortiproxy-lab')
ROOT.mkdir(exist_ok=True)
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=fortiproxy-lab.test', '-addext',
                'subjectAltName=DNS:fortiproxy-lab.test,IP:169.254.2.1',
                '-keyout', str(ROOT/'key.pem'), '-out', str(ROOT/'cert.pem')],
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
certificate = ssl.PEM_cert_to_DER_cert((ROOT/'cert.pem').read_text())
(ROOT/'fingerprint').write_text(hashlib.sha256(certificate).hexdigest())
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(ROOT/'cert.pem', ROOT/'key.pem')

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)

tun = os.open('/dev/net/tun', os.O_RDWR)
fcntl.ioctl(tun, 0x400454ca, struct.pack('16sH', b'tunlab', 0x1001))
run('ip', 'address', 'add', SERVER_IP, 'peer', CLIENT_IP, 'dev', 'tunlab')
run('ip', 'link', 'set', 'tunlab', 'up')

class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = MARKER + b' source=' + self.client_address[0].encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        end = 12
        while query[end]:
            end += query[end] + 1
        end += 5
        question = query[12:end]
        is_a = query[end-4:end-2] == b'\x00\x01'
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton(SERVER_IP) if is_a else b''
        sock.sendto(query[:2] + struct.pack('!HHHHH', 0x8180, 1, int(is_a), 0, 0) + question + answer, self.client_address)

for port in (8000, 443):
    server = http.server.HTTPServer(('0.0.0.0', port), HTTP)
    if port == 443:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
dns = socketserver.UDPServer(('0.0.0.0', 53), DNS)
threading.Thread(target=dns.serve_forever, daemon=True).start()

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with context.wrap_socket(self.request, server_side=True) as connection:
                self.connection = connection
                self.connection.settimeout(120)
                reader = connection.makefile('rb', buffering=0)
                while True:
                    first = reader.readline(8192)
                    if not first:
                        return
                    method, path, _ = first.decode('ascii').split()
                    headers = {}
                    while True:
                        line = reader.readline(8192)
                        if line == b'\r\n':
                            break
                        key, value = line.decode('ascii').split(':', 1)
                        headers[key.lower()] = value.strip()
                    length = int(headers.get('content-length', '0'))
                    body = b''
                    while len(body) < length:
                        piece = reader.read(length - len(body))
                        if not piece:
                            return
                        body += piece
                    if path == '/remote/logincheck':
                        fields = urllib.parse.parse_qs(body.decode())
                        valid = fields.get('username') == ['test-user'] and fields.get('credential') == ['test-password']
                        self.respond(b'ret=1' if valid else b'ret=0', cookie=valid)
                        print('LOGIN accepted' if valid else 'LOGIN rejected', flush=True)
                    elif path == '/remote/logout':
                        self.respond(b'logged-out')
                        return
                    elif headers.get('cookie') != 'SVPNCOOKIE=lab-session':
                        self.respond(b'permission denied', status=403)
                    elif path == '/remote/fortisslvpn_xml':
                        self.respond(f'<sslvpn><assigned-addr ipv4="{CLIENT_IP}"/><dns ip="{SERVER_IP}"/><split-tunnel-info></split-tunnel-info></sslvpn>'.encode())
                    elif path == '/remote/sslvpn-tunnel':
                        self.tunnel(reader)
                        return
                    else:
                        self.respond(b'OK')
        except (OSError, ssl.SSLError, ValueError) as error:
            print('SESSION ended: ' + type(error).__name__, flush=True)

    def respond(self, body, status=200, cookie=False):
        headers = f'HTTP/1.1 {status} {"OK" if status == 200 else "Forbidden"}\r\nContent-Length: {len(body)}\r\n'
        if cookie:
            headers += 'Set-Cookie: SVPNCOOKIE=lab-session; path=/\r\n'
        self.connection.sendall(headers.encode() + b'\r\n' + body)

    def tunnel(self, reader):
        # One event loop owns SSL and TUN I/O, with incremental frame parsing
        # and a single owner for the SSL object and its packet buffers.
        incoming, outgoing = bytearray(), bytearray()
        self.connection.setblocking(False)
        os.set_blocking(tun, False)
        deadline = time.monotonic() + 120
        def send(protocol, payload):
            data = struct.pack('!H', protocol) + payload
            outgoing.extend(struct.pack('!HHH', len(data) + 6, 0x5050, len(data)) + data)
        def control(protocol, code, identifier, options=b''):
            send(protocol, struct.pack('!BBH', code, identifier, len(options) + 4) + options)
        lcp_started = False
        ipcp_started = False
        with TUNNEL_LOCK:
            ACTIVE_TUNNELS.add(self.connection)
        print('TUNNEL started', flush=True)
        try:
            while time.monotonic() < deadline:
                readable, writable, _ = select.select([self.connection, tun], [self.connection] if outgoing else [], [], .2)
                if self.connection in readable or self.connection.pending():
                    try:
                        data = self.connection.recv(16384)
                        if not data:
                            return
                        incoming.extend(data)
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                        pass
                if tun in readable:
                    try:
                        send(0x21, os.read(tun, 65535))
                    except BlockingIOError:
                        pass
                if self.connection in writable:
                    try:
                        sent = self.connection.send(outgoing)
                        del outgoing[:sent]
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                        pass
                if len(outgoing) > 1048576:
                    raise ValueError('Test peer output exceeded its limit')
                while len(incoming) >= 6:
                    total, magic, size = struct.unpack('!HHH', incoming[:6])
                    if magic != 0x5050 or total != size + 6 or not 2 <= size <= 4096:
                        raise ValueError('Invalid framing')
                    if len(incoming) < total:
                        break
                    packet = bytes(incoming[6:total])
                    del incoming[:total]
                    protocol = struct.unpack('!H', packet[:2])[0]
                    payload = packet[2:]
                    if protocol == 0x21:
                        os.write(tun, payload)
                        continue
                    code, identifier, length = struct.unpack('!BBH', payload[:4])
                    options = payload[4:length]
                    if protocol == 0xc021:
                        if code == 1:
                            control(protocol, 2, identifier, options)
                            if not lcp_started:
                                control(protocol, 1, 1, b'\x01\x04\x05\x4a\x05\x06\x12\x34\x56\x78')
                                lcp_started = True
                        elif code == 2 and not ipcp_started:
                            control(0x8021, 1, 7, b'\x03\x06' + socket.inet_aton(SERVER_IP))
                            ipcp_started = True
                        elif code == 9:
                            control(protocol, 10, identifier, b'\x12\x34\x56\x78' + options[4:])
                        elif code == 5:
                            control(protocol, 6, identifier, options)
                            return
                    elif protocol == 0x8021:
                        if code == 1:
                            address = None
                            unsupported = []
                            offset = 0
                            while offset + 2 <= len(options):
                                kind, length = options[offset:offset+2]
                                if length < 2:
                                    raise ValueError('Invalid IPCP option')
                                if kind == 3:
                                    address = options[offset+2:offset+length]
                                else:
                                    unsupported.append(options[offset:offset+length])
                                offset += length
                            if unsupported:
                                control(protocol, 4, identifier, b''.join(unsupported))
                            elif address != socket.inet_aton(CLIENT_IP):
                                control(protocol, 3, identifier, b'\x03\x06' + socket.inet_aton(CLIENT_IP))
                            else:
                                control(protocol, 2, identifier, options)
                                print('IPCP client address agreed', flush=True)
                        elif code == 3:
                            control(protocol, 1, 8, options)
                    else:
                        control(0xc021, 8, 33, packet)
        finally:
            with TUNNEL_LOCK:
                ACTIVE_TUNNELS.discard(self.connection)
            print('TUNNEL stopped', flush=True)

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

print('READY: protocol-compatible test fixture, not FortiGate', flush=True)
Server(('0.0.0.0', 8443), Handler).serve_forever()
