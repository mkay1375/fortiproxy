# Repository Guidelines

## Project Structure & Module Organization

- `app/server.py`: standard-library Python API, profile storage, and VPN lifecycle.
- `web/`: directly served HTML, CSS, and vanilla JavaScript; no build step.
- `scripts/`: startup, firewall rules, and Tinyproxy configuration.
- `tests/`: unit tests, Docker harnesses, Playwright scripts, and SSL VPN test peer.
- `docs/`: screenshots and [protocol lab instructions](docs/protocol-lab.md).
- `Dockerfile` and `compose.yaml`: container packaging and localhost port bindings.

## Build, Test, and Development Commands

- `docker compose up --build -d`: start the panel on `8787`, SOCKS5 on `48732`, and HTTP proxy on `48733`.
- `python3 -m unittest discover -s tests -v`: run backend tests; requires Python 3.11+.
- `FORTIPROXY_BIND=127.0.0.1 FORTIPROXY_PORT=48731 FORTIPROXY_RUNTIME=/tmp/fortiproxy-preview python3 -m app.server`: preview locally without VPN capabilities.
- `docker compose build`: build `fortiproxy:local` before either Docker harness:
  - `python3 tests/integration_smoke.py --image fortiproxy:local`: synthetic tunnels, firewall, DNS, and isolation.
  - `python3 tests/fortisslvpn_smoke.py --image fortiproxy:local --ui --screenshots /tmp/fortiproxy-lab`: real openfortivpn/PPP and browser verification against an isolated test peer, not FortiGate.
- `docker compose down`: stop services; `-v` also deletes saved profiles.

## Coding Style & Naming Conventions

Use four-space Python/CSS indentation and two-space HTML/JavaScript indentation. Follow `snake_case` Python functions, `PascalCase` classes, and `camelCase` JavaScript identifiers. Match nearby code; no formatter or linter is configured. Keep backend dependencies limited to the standard library.

## Testing Guidelines

Use `unittest`, `test_*.py` files, and descriptive `test_*` methods. Cover validation, secrets, API boundaries, and cleanup; no numeric coverage threshold exists. Run relevant Docker harnesses for networking or lifecycle changes. Run mocked `tests/ui_smoke.cjs` using the README command for UI changes; `tests/fortisslvpn_ui.cjs` supplies the protocol lab's real API flow. Use synthetic credentials.

## Commit & Pull Request Guidelines

Use short imperative subjects, e.g. `Add isolated SSL VPN protocol lab`. Describe behavior, linked issues, verification, and limitations. Include UI screenshots, or explain their absence.

After review and committed, verified, pushed fixes, confirm the remote head matches. Comment with first line `Reviewed at <full 40-character SHA>` and a second line naming the review. For GitHub, use `gh pr comment <n> --body-file <file>`. Later commits invalidate the marker.

## Security & Agent Workflow

Preserve localhost bindings, fail-closed routing, secret exclusion, and default certificate validation; keep opt-out explicit. Never commit credentials/runtime data.

Read adjacent `RTK.md` if present. Keep updates brief and meaningful. For large tasks, delegate parts to subagents, commit each before dependent work, then review the whole change.
