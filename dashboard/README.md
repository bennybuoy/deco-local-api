# Deco Console

Live: **https://atrium-agents.zonkey-interval.ts.net:10443/** (tailnet only)

Flask + Gunicorn on atrium-agents, bound to `127.0.0.1:8790`. Tailscale Serve terminates HTTPS. Existing Serve routes are untouched. The enabled user service is `deco-dashboard.service`.

## Operations

```sh
systemctl --user status deco-dashboard.service
systemctl --user restart deco-dashboard.service
journalctl --user -u deco-dashboard.service -n 50 --no-pager
curl http://127.0.0.1:8790/health
tailscale serve status
```

Service definition: `/home/ben/.config/systemd/user/deco-dashboard.service`.
The app must use one worker: its device lock, caches and staged-upload state are in-process. Threads let the UI remain accessible during a slow device request. A restart expires staged-upload tokens; upload again if needed.

## Features and verification

- Mesh: live device list, role, online state, backhaul, 5 GHz RSSI, firmware, hardware, IP and client counts. Three X50 units observed: Lounge Room, Charlotte’s Room, Garage. 46 clients at verification (dynamic).
- Clients: live searchable device/MAC/IP table, Ethernet or wireless band, associated mesh unit.
- Wi-Fi: main and guest configuration forms; encrypted write adapters with read-merge-write, blank-password preservation, optimistic revision checks and fresh-session read-back. IoT SSID/enabled/band data is visible **read-only**: a reliable IoT web write contract has not been established. This is intentionally not an inferred opcode implementation.
- Firmware: installed versions, online check, local .bin staging with SHA-256, explicitly confirmed authenticated multipart upload and encrypted `local_upgrade`. Online check was executed read-only and returned `need_to_upgrade: false` for all three units. Upload/install has **not** been tested on hardware. Matching hardware units may all update. This is not a per-unit firmware installer. Staging validates extension/size, not vendor signature or compatibility; the router remains responsible for validating the image.
- CWMP: ACS URL, CWMP enable and periodic inform enable; preserves all other fields/credentials and checks read-back.
- Reboot: select one or all known unit MACs, explicit confirmation. Acceptance is not shown as completed reboot.
- System: live time, performance, IGMP, flow control, Wi-Fi network parameters; editable timezone and IGMP; on-demand log snapshot preparation/read and the installed 73-entry deco-local read catalog.

**No Deco configuration changes, reboots, firmware uploads or installs were executed during implementation.** Hardware mutation paths remain unverified. Browser checks only opened and cancelled a confirmation. Adapter checks mocked ALL device I/O.

### Known device constraints

1. TMP port 20001 currently refuses connections. Mesh/client reads fall back to `deco_local.web.snapshot`; the 73-read explorer cannot succeed until TMP is available. The installed library has `device_list` / `client_list`, not a literal `mesh_overview` operation.
2. Device log reads return error 1 before a log snapshot is prepared. The explicit Prepare snapshot action is implemented from stock firmware, but was not run during setup. Logs are not falsely presented as empty.
3. IoT writes remain disabled rather than risking an unsupported write. Main/guest/channel adapters also require an authorized live write/read-back test before being considered proven.
4. Node associations are cached by deco-local and can lag client roaming. Dashboard reads are cached for 90 seconds. Refresh respects that TTL, and stale fallback is labeled.
5. This is a local-management dashboard, not complete Deco cloud/HomeShield/app parity.

## Security and storage

- Tailnet membership/ACLs are the access boundary; there is no additional dashboard login. Any tailnet user permitted to reach this Serve port can manage the router. Restrict it with Tailscale ACLs as appropriate.
- Loopback backend; explicit Host allowlist, same-origin checks, secure HttpOnly SameSite cookies, per-session CSRF tokens, CSP and no-store responses.
- Writes require literal `APPLY`; arbitrary API path/opcode mutation is not exposed. Server serializes network operations and never automatically retries a write.
- Credentials are server-only in `credentials.json` (0600); existing Wi-Fi/CWMP secrets are redacted from browser JSON. Do not publish this file, probe results, session key, uploads or screenshots of private network data.
- The inherited encrypted client does not validate the Deco's self-signed HTTPS certificate. Tailnet TLS is validated normally by browsers.
- `uploads/` is private, bounded to 128 MiB, with old files removed during staging. Staged tokens expire after 30 minutes. Upload payload limit is 64 MiB.
- Action audit records contain time, action, outcome and tailnet identity, not payloads/secrets. They appear in `audit.jsonl` after actions.

## Dependencies and source

`app.py` imports the existing `../deco_client.py` and the installed library from `/home/ben/.local/share/uv/tools/deco-local/lib/python3.11/site-packages`. This is intentionally a host-local deployment, not a portable package. `.venv` contains Flask, Gunicorn, cryptography and paramiko. Versions are in `requirements.txt`.

All visual primitives and tokens come from the locally vendored Pico CSS v2 Slate theme; no CDN requests are needed at runtime. See `DESIGN.md`. There was no existing dashboard kit in this directory to reuse.

## Focused verification

- `browser_smoke.py`: real-browser checks of all seven views, client search, cancel-only confirmation, select-all reboot controls; desktop/mobile screenshots. Uses installed Playwright Chromium. Does not submit device changes.
- `adapter_smoke.py`: eight focused adapter/security checks with device I/O mocked. Uses private real-read fixtures from `probe-results.json`; do not publish that fixture.
- `evidence/browser-report.json`: seven views loaded, zero JS errors, no horizontal page overflow at desktop or 390 px mobile.
- `evidence/{overview,clients,wifi,mobile}.png`: rendered screenshots.

No build, explicit lint/typecheck, full test suite, commit or push was run. Awaiting user visual feedback before cleanup/packaging.
