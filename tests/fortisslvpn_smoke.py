#!/usr/bin/env python3
"""Real openfortivpn/pppd test against a minimal protocol peer, NOT FortiGate.

Creates an internal Docker network, a test server, and a separate app container.
No real VPN settings, host networking, production volumes or public ports are used.
All test resources are removed in finally. Use --ui for a real browser session.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


def docker(*args, check=True, input=None, timeout=60):
    result = subprocess.run(['docker', *args], input=input, text=True,
                            capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'Docker {args[0]} failed: {result.stderr.strip()}\n{result.stdout.strip()}')
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='fortiproxy:local')
    parser.add_argument('--ui', action='store_true')
    parser.add_argument('--screenshots', type=Path)
    args = parser.parse_args()
    tests = Path(__file__).resolve().parent
    tag = 'fortiproxy-ppp-' + uuid.uuid4().hex[:10]
    network, server, client = tag + '-net', tag + '-server', tag + '-client'

    def inside(code, user=None):
        command = ['exec', '-i']
        if user is not None:
            command += ['-u', user]
        return docker(*command, client, 'python3', '-', input=
                      "import sys\nsys.path.insert(0, '/lab-tests')\n" + code)

    def api(path, data=None):
        code = "import json,urllib.request\n"
        code += "body=" + repr(None if data is None else json.dumps(data).encode()) + "\n"
        code += "request=urllib.request.Request('http://127.0.0.1:8787'+" + repr(path) + ",body,{'Content-Type':'application/json','X-Fortiproxy-Request':'1'})\n"
        code += "print(json.dumps(json.load(urllib.request.urlopen(request,timeout=20))))\n"
        return json.loads(inside(code))

    def wait_state(expected):
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            status = api('/api/status')
            if status['state'] == expected:
                return status
            if expected == 'connected' and status['state'] == 'error':
                raise AssertionError(status)
            time.sleep(.2)
        raise AssertionError(f'Did not reach {expected}: {status}')

    def proxy_checks(certificate):
        inside("""from integration_smoke import http_proxy,socks_proxy
import http.client,ssl
for name,fetch in [('HTTP',lambda:http_proxy(8080,'fortiproxy-lab.test')),('SOCKS5',lambda:socks_proxy(1080,'fortiproxy-lab.test'))]:
    response=fetch()
    assert b'fortiproxy-real-ppp-lab source=10.77.0.2' in response, name
""" + 'context=ssl.create_default_context(cadata=' + repr(certificate) + ')\n' + """
connection=http.client.HTTPSConnection('127.0.0.1',8080,timeout=5,context=context)
connection.set_tunnel('fortiproxy-lab.test',443)
connection.request('GET','/')
response=connection.getresponse()
assert response.status==200 and b'fortiproxy-real-ppp-lab source=10.77.0.2' in response.read()
connection.close()
""")
        print('PASS: HTTP, SOCKS5 remote DNS, HTTPS CONNECT with verified TLS, and actual PPP source address', flush=True)

    def blocked_checks(server_ip):
        inside("""import urllib.request,socket
from integration_smoke import http_proxy,socks_proxy
""" + 'target=' + repr(server_ip) + '\n' + """
# The root fallback path still works, so a proxy bypass would be detectable.
assert b'fortiproxy-real-ppp-lab' in urllib.request.urlopen('http://'+target+':8000',timeout=3).read()
for name,fetch in [('HTTP',lambda:http_proxy(8080,target)),('SOCKS5',lambda:socks_proxy(1080,target))]:
    try: response=fetch()
    except OSError: response=b''
    assert b'fortiproxy-real-ppp-lab' not in response, name+' bypassed the VPN'
with socket.create_connection(('127.0.0.1',8080),timeout=4) as connection:
    connection.sendall(('CONNECT '+target+':443 HTTP/1.1\\r\\nHost: '+target+'\\r\\n\\r\\n').encode())
    try: response=connection.recv(2048)
    except OSError: response=b''
    assert b' 200 ' not in response.split(b'\\r\\n')[0], 'CONNECT bypassed the VPN'
""")
        print('PASS: all proxy transports blocked without PPP despite a working root fallback route', flush=True)

    try:
        docker('network', 'create', '--internal', network)
        docker('run', '-d', '--name', server, '--network', network, '--cap-add', 'NET_ADMIN',
               '--device', '/dev/net/tun', '--entrypoint', 'python3',
               '-v', f'{tests / "fortisslvpn_server.py"}:/lab-server.py:ro', args.image, '-u', '/lab-server.py')
        docker('run', '-d', '--name', client, '--network', network, '--cap-add', 'NET_ADMIN',
               '--device-cgroup-rule', 'c 108:* rwm', '--tmpfs', '/run', '--tmpfs', '/tmp',
               '-e', 'FORTIPROXY_DATA=/run/profile', '-v', f'{tests}:/lab-tests:ro', args.image)
        for _ in range(60):
            if 'READY:' in docker('logs', server):
                break
            time.sleep(.2)
        else:
            raise AssertionError('Test server did not start')
        wait_state('disconnected')
        pin = docker('exec', server, 'cat', '/tmp/fortiproxy-lab/fingerprint')
        certificate = docker('exec', server, 'cat', '/tmp/fortiproxy-lab/cert.pem')
        server_ip = json.loads(docker('inspect', server))[0]['NetworkSettings']['Networks'][network]['IPAddress']
        config = {'host': server, 'port': 8443, 'username': 'test-user', 'password': 'test-password'}
        assert api('/api/test-gateway', {'host': server, 'port': 8443})['reachable']
        assert not api('/api/test-gateway', {'host': server, 'port': 8444})['reachable']
        print('PASS: gateway TCP reachability and closed-port check', flush=True)
        api('/api/connect', config)
        assert 'certificate validation failed' in wait_state('error')['message']
        assert 'LOGIN accepted' not in docker('logs', server)
        print('PASS: untrusted TLS certificate rejected before login', flush=True)
        config['trusted_cert'] = pin
        api('/api/connect', {**config, 'password': 'wrong-dummy-password'})
        assert 'login was rejected' in wait_state('error')['message']
        print('PASS: wrong password rejected and surfaced safely', flush=True)
        api('/api/connect', config)
        wait_state('connected')
        links = json.loads(docker('exec', client, 'ip', '-j', 'link', 'show', 'dev', 'ppp0'))
        assert links[0]['link_type'] == 'ppp' and 'POINTOPOINT' in links[0]['flags'], links
        inside("from pathlib import Path\nassert not list(Path('/run/fortiproxy').glob('connection-*'))\n")
        print('PASS: certificate pin, password/cookie login, real pppd LCP/IPCP and completed tunnel readiness', flush=True)
        proxy_checks(certificate)
        assert api('/api/disconnect', {})['state'] == 'disconnected'
        blocked_checks(server_ip)
        if args.ui:
            artifacts = (args.screenshots or Path(tempfile.mkdtemp(prefix='fortiproxy-lab-ui-'))).resolve()
            artifacts.mkdir(parents=True, exist_ok=True)
            print(docker('run', '--rm', '--network', f'container:{client}', '--entrypoint', 'node',
                         '-e', f'LAB_GATEWAY={server}', '-e', f'LAB_CERT_PIN={pin}',
                         '-v', f'{tests / "fortisslvpn_ui.cjs"}:/test.cjs:ro',
                         '-v', f'{artifacts}:/artifacts', 'mcr.microsoft.com/playwright/mcp:v0.0.83',
                         '/test.cjs', timeout=90), flush=True)
            print(f'Screenshot: {artifacts / "lab-connected.png"}', flush=True)
        api('/api/connect', config)
        wait_state('connected')
        proxy_checks(certificate)
        docker('exec', server, 'python3', '-c', 'import os,signal; os.kill(1,signal.SIGUSR1)')
        wait_state('error')
        blocked_checks(server_ip)
        print('PASS: reconnect and abrupt server-side tunnel loss, with no fallback leak', flush=True)
        assert api('/api/disconnect', {})['state'] == 'disconnected'
        print('All protocol-lab checks passed. This is NOT a genuine FortiGate/vendor compatibility test.', flush=True)
    except Exception:
        print('Test server events:\n' + docker('logs', server, check=False), flush=True)
        raise
    finally:
        docker('rm', '-f', client, server, check=False)
        docker('network', 'rm', network, check=False)


if __name__ == '__main__':
    main()
