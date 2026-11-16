# Fortiproxy

A local web panel for a Fortinet SSL VPN connection, exposed to individual apps
through SOCKS5 and HTTP proxies. The VPN, DNS and routing live inside one Linux
Docker container. macOS network settings are not modified.

## Start

Install Docker Desktop (or use a Linux Docker engine), then run:

```sh
docker compose up --build -d
```

Open **http://localhost:8787**. Enter your gateway address, custom port, username
and password, then select **Connect**. **Disconnect** stops the tunnel and blocks
proxy egress. Restarting the container does not reconnect automatically.

The supported connection type is **SSL VPN**, with password authentication,
optional realm, optional one-time code, no client certificate, and an optional
SHA-256 certificate fingerprint. A custom port such as `10443` is supported.
Browser SSO/SAML, IPsec and client certificates are not supported by this panel.
A configuration screenshot cannot prove that a specific server accepts the
open-source client; server-side policies, MFA or endpoint checks may matter.

Use these proxy addresses in your apps:

| Proxy | Address |
| --- | --- |
| SOCKS5 | `127.0.0.1:1080` |
| HTTP / HTTPS CONNECT | `127.0.0.1:8080` |

For example, after connecting:

```sh
curl --proxy socks5h://127.0.0.1:1080 https://example.com
curl --proxy http://127.0.0.1:8080 https://example.com
```

Use `socks5h` to resolve names inside the container. Apps that resolve names on
the Mac before contacting SOCKS may use the Mac's existing DNS. HTTP CONNECT is
allowed to ports 443 and 563; ordinary HTTP requests are supported. Proxies carry
TCP traffic; they do not provide a general UDP tunnel.

## Credentials and certificates

The UI does not save profiles, passwords or one-time codes. The backend writes
a private mode-0600 openfortivpn configuration under `/run`, which is a tmpfs in
Compose. The file is removed once connected, on failure or on disconnect.
Credentials remain in process memory while needed; they are not logged or sent
back through the status API. Re-enter credentials for the next connection.

TLS certificate validation stays enabled. If your gateway uses a private CA,
enter its SHA-256 certificate fingerprint only after verifying it through a
trusted administrator or another independent channel. The panel does not offer
an insecure certificate bypass. Leading or trailing spaces and control
characters are rejected because openfortivpn's configuration parser would
otherwise alter them.

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
proxy connections through Docker. Marked policy routing directs new proxy
connections through the VPN without changing routes used by the web panel or
VPN gateway transport. An unreachable fallback and UID firewall remain in place
when the tunnel disappears. IPv6 proxy egress is blocked. Internet availability
still depends on the VPN gateway permitting it; a corporate gateway may permit
only private destinations.

## Development and verification

The backend has no Python dependencies beyond Python 3.11+:

```sh
python3 -m unittest discover -s tests -v
```

To preview the panel without Docker or connecting anywhere:

```sh
FORTIPROXY_BIND=127.0.0.1 FORTIPROXY_RUNTIME=/tmp/fortiproxy-preview python3 -m app.server
```

Preview mode is for reviewing the UI. Actual VPN connections require the
container, root's network permissions, PPP and the firewall setup.

The integration smoke harness, when present, creates isolated Docker networks
and synthetic tunnel interfaces to test HTTP/SOCKS forwarding and fail-closed
behavior. It never uses your real VPN configuration. It is not a FortiGate
protocol emulator and does not validate authentication against a real server.

Stop the service with `docker compose down`. Inspect health with
`docker compose ps`. The control plane intentionally reports sanitized errors
instead of exposing potentially sensitive VPN output. Check gateway, credentials,
MFA and certificate trust if a connection fails.

Client documentation: [openfortivpn](https://github.com/adrienverge/openfortivpn),
[microsocks](https://github.com/rofl0r/microsocks),
[tinyproxy](https://tinyproxy.github.io/).
