# Fortiproxy

A local web panel for a Fortinet SSL VPN connection, exposed to individual apps
through SOCKS5 and HTTP proxies. The VPN, DNS and routing live inside one Linux
Docker container. macOS network settings are not modified.

## Start

Install Docker Desktop (or use a Linux Docker engine), then run:

```sh
docker compose up --build -d
```

Open **http://localhost:48731**. The localhost ports are `48731` for the web UI,
`48732` for SOCKS5, and `48733` for HTTP/HTTPS proxying. Enter your gateway
address, custom port, username and password, then select **Connect**. **Disconnect** stops the tunnel and blocks
proxy egress. Restarting the container does not reconnect automatically.

Use **Test gateway** to check whether the gateway host and port accept a TCP
connection from the container. This test has a five-second deadline and does not
send credentials or validate TLS certificates or VPN login.

The supported connection type is **SSL VPN**, with password authentication,
optional realm, optional one-time code, no client certificate, and an optional
SHA-256 certificate fingerprint. A custom port such as `10443` is supported.
Browser SSO/SAML, IPsec and client certificates are not supported by this panel.
A configuration screenshot cannot prove that a specific server accepts the
open-source client; server-side policies, MFA or endpoint checks may matter.

Use these proxy addresses in your apps:

| Proxy | Address |
| --- | --- |
| SOCKS5 | `127.0.0.1:48732` |
| HTTP / HTTPS CONNECT | `127.0.0.1:48733` |

For example, after connecting:

```sh
curl --proxy socks5h://127.0.0.1:48732 https://example.com
curl --proxy http://127.0.0.1:48733 https://example.com
```

Use `socks5h` to resolve names inside the container. Apps that resolve names on
the Mac before contacting SOCKS may use the Mac's existing DNS. HTTP CONNECT is
allowed to ports 443 and 563; ordinary HTTP requests are supported. Proxies carry
TCP traffic; they do not provide a general UDP tunnel.

## Credentials and certificates

Connection settings save automatically as you edit and are restored when you open
the UI. The saved fields are connection name, gateway, port, username, realm,
certificate settings and the one-time code format. Passwords and one-time codes are never included
in the saved profile. The mode-0600 `/data/profile.json` file lives in the Compose
`profile-data` named volume and survives container restarts and recreation.
`docker compose down` retains it; `docker compose down -v` deletes it. Local
Python previews use `data/profile.json` (or `FORTIPROXY_DATA`), excluded from Git.

For each connection, the backend writes a private mode-0600 openfortivpn
configuration under `/run`, which is a tmpfs in Compose. The file is removed once connected, on failure or on disconnect.
Credentials remain in process memory while needed; they are not logged or sent
back through the status API. Re-enter credentials for the next connection.

The one-time code field sits beside Password. By default it is appended directly
to the password, with no separator. Additional settings also offers a separate
gateway challenge mode. Neither the password, the code nor the combined value
is included in the saved profile.

Certificate validation is enabled by default. Additional settings includes
**Ignore certificate validation**, which accepts the certificate currently
presented by the gateway without checking its identity. Encryption and TLS 1.2+
stay enabled. This option is saved only when you select it; it is not enabled
automatically. The backend obtains a fresh certificate digest for that attempt
without sending credentials, then supplies it to openfortivpn. The observed
digest is not persisted or added to macOS trust settings. Certificates changing
between that probe and VPN negotiation may still cause the connection to fail.
This is distinct from openfortivpn's `--insecure-ssl`, which relaxes protocol and
cipher restrictions and is not used here.

With validation enabled, normal CA/hostname checks apply, or you can enter a
SHA-256 certificate fingerprint verified with your administrator. Leading or
trailing spaces and control characters are rejected because openfortivpn's
configuration parser would otherwise alter them.

## Isolation

Compose publishes the panel and both proxies only on IPv4 localhost. Do not
change those bindings or share this service with untrusted local users: there
is no proxy or UI login. Any local application can use the proxies while the
VPN is connected. The API checks local Host and same-origin headers and requires
a custom request header for changes.

The container uses bridge networking, `NET_ADMIN` and the Linux PPP device
(major 108), created inside the container when necessary. It does not mount a
Docker socket, credentials directory or host network namespace. No privileged
container is required. A Linux kernel with PPP support is required; Docker
Desktop supplies the Linux kernel on macOS. Startup fails rather than silently
running without firewall protection.

Proxy processes run as UID 10001 with no capabilities. Firewall rules allow new
proxy traffic only through `ppp0`, including DNS, and allow replies to incoming
proxy connections through Docker. Marked policy routing and tunnel source translation direct new proxy
connections through the VPN without changing routes used by the web panel or
VPN gateway transport. An unreachable fallback and UID firewall remain in place
when the tunnel disappears. Incoming VPN peers cannot access the panel or
proxies, and IP forwarding is blocked. IPv6 proxy egress is blocked. Internet availability
still depends on the VPN gateway permitting it; a corporate gateway may permit
only private destinations.

## Development and verification

The backend has no Python dependencies beyond Python 3.11+:

```sh
python3 -m unittest discover -s tests -v
```

To preview the panel without Docker or connecting anywhere:

```sh
FORTIPROXY_BIND=127.0.0.1 FORTIPROXY_PORT=48731 FORTIPROXY_RUNTIME=/tmp/fortiproxy-preview python3 -m app.server
```

Preview mode is for reviewing the UI. Actual VPN connections require the
container, root's network permissions, PPP and the firewall setup.

Run `python3 tests/integration_smoke.py --image fortiproxy:local` after building
the image. The harness creates isolated Docker networks and synthetic tunnel
interfaces to test HTTP, CONNECT, SOCKS, DNS and fail-closed behavior. It never
uses your real VPN configuration. It is not a FortiGate protocol emulator and does not validate authentication against a real server.

Stop the service with `docker compose down`. Inspect health with
`docker compose ps`. The control plane classifies VPN client output into fixed, sanitized errors
for certificate, login, network, TLS, option and PPP failures. Raw output is
drained in memory and never logged, returned to the browser or saved on disk. Check gateway, credentials,
MFA and certificate trust if a connection fails.

Client documentation: [openfortivpn](https://github.com/adrienverge/openfortivpn),
[microsocks](https://github.com/rofl0r/microsocks),
[tinyproxy](https://tinyproxy.github.io/).

## UI verification

The browser smoke test uses mocked API responses, so it never logs in to a VPN.
With Compose running, capture screenshots and verify the UI flows using:

```sh
mkdir -p /tmp/fortiproxy-screenshots
docker run --rm --network container:$(docker compose ps -q fortiproxy) \
  --entrypoint node \
  -v "$PWD/tests/ui_smoke.cjs:/test.cjs:ro" \
  -v /tmp/fortiproxy-screenshots:/artifacts \
  mcr.microsoft.com/playwright/mcp:v0.0.83 /test.cjs
```

Desktop and mobile previews: [desktop](docs/desktop.png), [mobile](docs/mobile.png).

## Local VPN protocol lab

For a repeatable local TLS/login/PPP/proxy test, see
[the protocol lab](docs/protocol-lab.md). It runs real openfortivpn and pppd
against a minimal compatible peer in isolated Docker containers, including
certificate rejection, bad passwords, DNS, HTTPS, disconnect and tunnel loss.
The peer is a test fixture, not Fortinet FortiGate; vendor compatibility remains
subject to testing against an SSL-VPN-capable FortiGate VM or appliance.
