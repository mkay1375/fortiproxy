#!/usr/bin/env python3
"""Isolated proxy/firewall smoke, not a FortiGate TLS/PPP handshake test.

Build the application image, then run:
    python3 tests/integration_smoke.py --image fortiproxy:local

Only test-owned Docker resources are changed. No real VPN gateway is contacted.
"""
import argparse
import http.client
import json
import random
import socket
import struct
import subprocess
import time
import uuid

MARKER = b'fortiproxy-isolated-smoke'
SERVER = '''import http.server, socketserver, threading, socket, struct
class HTTP(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200); self.end_headers(); self.wfile.write(b"fortiproxy-isolated-smoke")
 def log_message(self,*args): pass
class UDP(socketserver.BaseRequestHandler):
 def handle(self):
  query, sock = self.request
  if query == b"probe":
   sock.sendto(b"dns-probe",self.client_address); return
  end = 12
  while query[end]: end += query[end] + 1
  end += 5
  question = query[12:end]
  is_a = query[end-4:end-2] == b"\\x00\\x01"
  answer = b"\\xc0\\x0c" + struct.pack("!HHIH",1,1,0,4) + socket.inet_aton("__TARGET__") if is_a else b""
  sock.sendto(query[:2] + struct.pack("!HHHHH",0x8180,1,int(is_a),0,0) + question + answer,self.client_address)
for port in (8000,443):
 threading.Thread(target=http.server.HTTPServer(("0.0.0.0",port),HTTP).serve_forever,daemon=True).start()
socketserver.UDPServer(("0.0.0.0",53),UDP).serve_forever()
'''


def docker(*args, check=True):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=90)
    if check and result.returncode:
        raise RuntimeError(f'Docker {args[0]} failed: {result.stderr.strip()}')
    return result.stdout.strip()


def api(port, method, path, data=None, headers=None):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    body = None if data is None else json.dumps(data)
    request_headers = {'Content-Type': 'application/json', 'X-Fortiproxy-Request': '1'}
    if headers is not None:
        request_headers = headers
    connection.request(method, path, body, request_headers)
    response = connection.getresponse()
    raw = response.read()
    connection.close()
    return response.status, json.loads(raw)


def receive(sock, size):
    result = b''
    while len(result) < size:
        piece = sock.recv(size - len(result))
        if not piece:
            raise OSError('Proxy closed connection')
        result += piece
    return result


def http_proxy(port, target, connect=False):
    with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
        sock.settimeout(4)
        if connect:
            sock.sendall(f'CONNECT {target}:443 HTTP/1.1\r\nHost: {target}:443\r\n\r\n'.encode())
            header = b''
            while b'\r\n\r\n' not in header:
                header += receive(sock, 1)
            if b' 200 ' not in header.split(b'\r\n')[0]:
                return header
            request = f'GET / HTTP/1.0\r\nHost: {target}\r\n\r\n'
        else:
            request = f'GET http://{target}:8000/ HTTP/1.0\r\nHost: {target}:8000\r\n\r\n'
        sock.sendall(request.encode())
        output = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return output
            output += chunk


def socks_proxy(port, target):
    with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
        sock.settimeout(4)
        sock.sendall(b'\x05\x01\x00')
        if receive(sock, 2) != b'\x05\x00':
            raise OSError('SOCKS greeting rejected')
        address = target.encode('ascii')
        sock.sendall(b'\x05\x01\x00\x03' + bytes([len(address)]) + address + struct.pack('!H', 8000))
        reply = receive(sock, 4)
        if reply[1] != 0:
            raise OSError(f'SOCKS connect rejected ({reply[1]})')
        if reply[3] == 1:
            receive(sock, 6)
        elif reply[3] == 4:
            receive(sock, 18)
        else:
            receive(sock, receive(sock, 1)[0] + 2)
        sock.sendall(f'GET / HTTP/1.0\r\nHost: {target}\r\n\r\n'.encode())
        output = b''
        while True:
            piece = sock.recv(4096)
            if not piece:
                return output
            output += piece


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='fortiproxy:local')
    args = parser.parse_args()
    tag = 'fortiproxy-smoke-' + uuid.uuid4().hex[:10]
    network, app, peer = tag + '-net', tag + '-app', tag + '-peer'
    subnet = f'10.203.{random.randrange(1, 250)}'
    target = subnet + '.3'
    try:
        docker('network', 'create', '--internal', '--subnet', subnet + '.0/24', network)
        docker('run', '-d', '--name', peer, '--network', network, '--ip', target,
               '--entrypoint', 'python3', args.image, '-u', '-c', SERVER.replace('__TARGET__', target))
        docker('create', '--name', app, '--cap-add', 'NET_ADMIN', '--network', 'bridge',
               '--tmpfs', '/run', '--tmpfs', '/tmp',
               '-p', '127.0.0.1::8787', '-p', '127.0.0.1::1080', '-p', '127.0.0.1::8080', args.image)
        docker('network', 'connect', '--ip', subnet + '.2', network, app)
        docker('start', app)
        ports = {port: int(docker('port', app, str(port)).rsplit(':', 1)[1]) for port in (8787, 1080, 8080)}
        for _ in range(60):
            try:
                status, body = api(ports[8787], 'GET', '/api/status')
                if status == 200:
                    break
            except (OSError, ValueError, http.client.HTTPException):
                pass
            time.sleep(.5)
        else:
            raise AssertionError('UI API did not start')
        assert body['state'] == 'disconnected', body
        assert api(ports[8787], 'POST', '/api/disconnect', {})[0] == 200
        assert api(ports[8787], 'POST', '/api/connect', {'host': 'invalid\nhost'})[0] == 400
        assert api(ports[8787], 'POST', '/api/disconnect', {}, {'Content-Type': 'application/json'})[0] == 403
        assert api(ports[8787], 'POST', '/api/disconnect', {}, {
            'Content-Type': 'application/json', 'X-Fortiproxy-Request': '1', 'Origin': 'https://foreign.invalid'})[0] == 403
        print('PASS: API startup, validation, disconnect, and cross-origin protection')
        route = json.loads(docker('exec', app, 'ip', '-j', 'route', 'get', target))[0]
        interface = route['dev']
        assert interface not in ('lo', 'ppp0'), route
        docker('exec', app, 'ip', 'link', 'set', interface, 'down')
        docker('exec', app, 'ip', 'link', 'set', interface, 'name', 'ppp0')
        docker('exec', app, 'ip', 'link', 'set', 'ppp0', 'up')
        docker('exec', app, 'sh', '-c', f'printf "nameserver {target}\\noptions timeout:1 attempts:1\\n" > /etc/resolv.conf')
        hostname = 'smoke.fortiproxy.test'
        for kind, fetch in [('HTTP', lambda: http_proxy(ports[8080], hostname)),
                            ('HTTP CONNECT', lambda: http_proxy(ports[8080], hostname, True)),
                            ('SOCKS5', lambda: socks_proxy(ports[1080], hostname))]:
            assert MARKER in fetch(), kind + ' did not reach isolated peer through ppp0'
            print('PASS: ' + kind + ' through synthetic tunnel interface')
        dns_probe = 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b"probe",("' + target + '",53)); assert s.recv(100)==b"dns-probe"'
        docker('exec', '-u', '10001', app, 'python3', '-c', dns_probe)
        print('PASS: proxy UID DNS traffic through synthetic tunnel interface')
        docker('exec', app, 'ip', 'link', 'set', 'ppp0', 'down')
        docker('exec', app, 'ip', 'link', 'set', 'ppp0', 'name', interface)
        docker('exec', app, 'ip', 'link', 'set', interface, 'up')
        direct = 'import urllib.request; assert b"fortiproxy-isolated-smoke" in urllib.request.urlopen("http://' + target + ':8000",timeout=3).read()'
        docker('exec', app, 'python3', '-c', direct)
        for kind, fetch in [('HTTP', lambda: http_proxy(ports[8080], target)),
                            ('HTTP CONNECT', lambda: http_proxy(ports[8080], target, True)),
                            ('SOCKS5', lambda: socks_proxy(ports[1080], target))]:
            try:
                output = fetch()
            except (OSError, TimeoutError):
                output = b''
            assert MARKER not in output, kind + ' leaked through fallback interface'
            print('PASS: ' + kind + ' blocked without tunnel despite working root route')
        dns_blocked = subprocess.run(['docker', 'exec', '-u', '10001', app, 'python3', '-c', dns_probe],
                                     capture_output=True, text=True, timeout=10)
        assert dns_blocked.returncode != 0, 'Proxy UID DNS traffic leaked through fallback interface'
        print('PASS: proxy UID DNS egress blocked without tunnel')
        assert api(ports[8787], 'POST', '/api/disconnect', {})[0] == 200
        print('PASS: final disconnect remains available')
        print('All isolated checks passed. FortiGate authentication/TLS/PPP handshake was not tested.')
    except Exception:
        print('Application logs:\n' + docker('logs', app, check=False))
        raise
    finally:
        docker('rm', '-f', app, peer, check=False)
        docker('network', 'rm', network, check=False)


if __name__ == '__main__':
    main()
