# Deco Local API

Encrypted local management client for TP-Link Deco mesh routers — manage your Decos without the app or cloud.

## What this is

A Python client that reverse-engineers the TP-Link Deco's encrypted local admin API (AES-128-CBC + RSA envelope) from the firmware source. It logs in with your own TP-Link ID credentials and can read and write device settings through the same encrypted API the Deco app uses — no app, no cloud, no vendor account beyond your own login.

## Why

TP-Link's Deco mesh is designed to be managed exclusively through the Deco phone app, which connects to TP-Link's cloud. The local web UI shows a CWMP Settings page but silently refuses to write it — the write endpoint is app-only. Two ISP users tried pointing their Decos at commercial ACS servers and both failed.

This tool cracks the encrypted envelope and provides the first working path to manage Deco CWMP settings locally, without the app.

## Tools

### `deco_client.py`
Protocol library — handles login, key exchange, AES+RSA encryption/decryption, and encrypted API calls.

### `deco_run.py`
CLI wrapper:
```
python3 deco_run.py get-cwmp                    # read CWMP settings
python3 deco_run.py set-cwmp http://your-acs:7547/  # set ACS URL
python3 deco_run.py raw /admin/cwmp cwmp_info '{"operation":"read"}'  # arbitrary encrypted API call
```

Environment:
```
DECO_HOST=192.168.68.1         # Deco IP (default: main unit)
DECO_EMAIL=you@example.com     # TP-Link ID email
DECO_PASSWORD='your-password'    # TP-Link ID password
```

## What's verified

- Login flow (two RSA keys: 512-bit sign from `/login?form=auth`, 1024-bit password from `/login?form=keys`)
- CWMP settings read/write via `cwmp_info` form (NOT the documented `/admin/cwmp?form=cwmp` which is app-only)
- CWMP enable, Inform enable, Inform interval, ACS URL — all writable with real JSON booleans
- Mesh sync propagates CWMP settings from main to satellites automatically

## What's not verified

- 44 of 45 deco-local writes (only `led_set` verified on X55, not X50)
- Wi-Fi SSID/password changes via encrypted API
- Satellite CWMP daemon startup (gated on slave role — needs FAP or Router mode)
- Reboot persistence of CWMP settings
- Cloud revert behaviour after blocking TP-Link cloud endpoints

## Dashboard

A Flask web UI for managing the mesh without the app:
- Mesh overview (nodes, clients, signal, firmware)
- Client list (searchable)
- Wi-Fi settings (SSID, password, channel, guest, IoT)
- Firmware (version, local upload, online check)
- CWMP settings (ACS URL, enable/disable)
- Reboot (per-unit or all)
- System (logs, time, parameters)

Runs on Flask/Gunicorn, accessible via Tailscale Serve.

## Security notes

This tool uses the owner's own TP-Link ID credentials — it does not exploit, bypass authentication, or use vendor keys. It accesses the same encrypted local API the Deco app uses, just from a different client. The app-only write restriction on CWMP settings is a vendor lock-in, not a security boundary.

## License

MIT — same as the upstream `deco-local` project this complements.