# Local SSL VPN protocol lab

The lab runs a separate Fortiproxy instance and a minimal compatible test peer on
an **internal Docker network**, without public ports or host networking. It uses
temporary test credentials, a generated certificate, real openfortivpn and pppd,
and an actual kernel PPP interface. The server terminates Fortinet-framed PPP
inside TLS and delivers IPv4 traffic through a Linux TUN device.

This peer is **not Fortinet FortiGate** and is not a production VPN server. It
implements only the password/cookie, configuration, LCP/IPCP and IPv4 paths used
by these tests. It does not validate vendor firmware, SAML/MFA, endpoint checks,
real gateway policies, or Internet access through a corporate gateway.

Fortinet's Container FortiOS 7.2.2 documentation states that SSL VPN is not
supported. A genuine vendor test needs a suitable SSL-VPN-capable FortiGate VM
image and license; neither is supplied by this project. FortiOS 7.6.3 and later
removed SSL VPN tunnel mode, so a current arbitrary FortiGate image is not a
suitable replacement for this protocol.

- [FortiOS 7.6.3 release note](https://docs.fortinet.com/document/fortigate/7.6.3/fortios-release-notes/173430/ssl-vpn-tunnel-mode-no-longer-supported)

- [Fortinet Container FortiOS VPN documentation](https://docs.fortinet.com/document/container-fortios/7.2.2/administration-guide/429759/vpn)
- [Client protocol reference](https://github.com/adrienverge/openfortivpn/tree/v1.19.0/src)

## Run

Build the app, then run from the project folder:

```sh
docker compose build
python3 tests/fortisslvpn_smoke.py --image fortiproxy:local
```

Include an actual browser session and a screenshot with:

```sh
python3 tests/fortisslvpn_smoke.py --image fortiproxy:local --ui \
  --screenshots /tmp/fortiproxy-lab-screenshots
```

The optional UI test uses `mcr.microsoft.com/playwright/mcp:v0.0.83`. It uses real
API requests and a real local tunnel, with no API mocks. Test containers and the
internal network are removed in `finally`, on success and on failure. A timeout
or external termination can require removing resources whose names start with
`fortiproxy-ppp-`. Production containers, saved profiles and credentials are
never mounted or modified by this harness.

## Assertions

- Gateway TCP reachability and a closed port.
- Untrusted certificate rejection before login.
- Wrong password rejection and safe diagnostic messages.
- Explicit certificate-validation opt-out and appended password+OTP login,
  including a real browser session with both secret inputs cleared.
- Verified certificate pin and successful password/cookie login.
- Actual pppd LCP/IPCP negotiation and `ppp0` link type `ppp`.
- Client completion evidence as well as an assigned PPP interface before Connected.
- HTTP and SOCKS5 forwarding, VPN DNS, and HTTPS CONNECT with certificate and
  hostname validation. The peer verifies the VPN source address.
- Explicit disconnect and reconnect.
- Server-side TLS tunnel termination while the peer's HTTP service remains
  reachable through the ordinary root route; all proxies must remain blocked.
- Optional real UI gateway check, opt-in base-password persistence and removal,
  reconnect with a fresh OTP, and clearing secret inputs. Closing the page is
  verified to leave the VPN connected; a new page can still disconnect it.
- System dark theme screenshots from the real connected UI.

The existing `tests/integration_smoke.py` complements this lab with direct
firewall, loopback/Docker-DNS, and inbound VPN-side listener isolation checks.
