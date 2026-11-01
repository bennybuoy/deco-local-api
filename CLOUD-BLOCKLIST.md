# Deco X50 v1.30 — cloud endpoint blocklist

## Scope and confidence

Static analysis of `/home/ben/.hermes/profiles/vish/work/firmware/deco-x50-v1.30/analysis/rootfs`, performed on smith over SSH using a copied tree at `/home/smith/deco-cwmp/rootfs-analysis/rootfs`. Scanned 2,498 regular files without read errors, including binary and Lua-bytecode strings; additionally inspected the contents of both `lib/firmware/IPQ5018/fw_*.tar.gz` archives (no hostname matches). Symlinks were not followed outside the tree. Separated executable/configuration endpoints from comments, documentation, DPI signatures, and local administration names.

**This is the complete identified static TP-Link endpoint inventory from this scan, not proof of every runtime destination.** The firmware obtains `serverUrl` and `serviceUrls` from the cloud, caches them, and downloads firmware/content URLs. Static analysis cannot enumerate future, regional, or dynamically assigned hosts. No firewall rules or Deco settings were changed for this report.

## Recommended DNS suffix blocklist

Block each apex **and all descendants**, scoped to the Deco devices where possible:

```text
tplinkcloud.com
tplinknbu.com
tplinkra.com
tplinkra-ipc.com
kasasmart.com
```

The first two cover the proven cloud bootstrap, API, telemetry, and HomeShield families. The last three are defense-in-depth TP-Link remote-access/IoT families present in `lib/modules/4.4.60/xt_pctl.ko`; their presence is not evidence that this Deco initiates connections to every family.

For **no vendor/partner phone-home**, also block:

```text
safethings.avira.com
auc.avira.com
safethings.com
api.mixpanel.com
net.nortonlifelock.com
```

HomeShield security, reputation, device recognition, reporting, remote administration, integrations, and automatic firmware checks may stop working. Preserve local management, the mesh backhaul, and the local ACS.

## Exact TP-Link host inventory

| Host | Evidence relative to rootfs | Classification / purpose |
|---|---|---|
| `n-deventry-gw.tplinkcloud.com` | `etc/cloud_config.cfg`: `sefDomain`, `sefPort:443` | Configured cloud entry/bootstrap server |
| `n-devs-gw.tplinkcloud.com` | `etc/cloud_config.cfg`: `defaultSvr`, `defaultPort:443` | Configured default persistent cloud server |
| `n-device-api.tplinkcloud.com` | `etc/cloud_https.cfg`: `verify.host`, `verify.path` | HTTPS device validation at `/v1/validate` |
| `n-da.tplinkcloud.com` | `usr/bin/telemetry` | Default HTTPS telemetry endpoint |
| `api-homecare-cloud.i.tplinknbu.com` | `usr/lib/libauc.so.1.0.0` | Executable default TP-Link URL reputation/category server |
| `api-homecare-cloud-beta3.tplinknbu.com` | `usr/sbin/fing_device_recognize` | **Commented example**, not active fixed destination; live URL is read from `/tmp/cloud/cloud_report_fing` |
| `api-ifttt-router.tplinknbu.com` | `usr/sbin/ifttt_fapSwitch`, `ifttt_syncTrigger`, `ifttt_uploadEvent` | **Commented examples**; actual server comes from token/cache file |
| `n-wap-gw.tplinkcloud.com` | Supplied in task; **no literal match anywhere in this rootfs** | Include defensively; do not claim firmware discovery |
| `dcmp-api.i.tplinkcloud.com` | Supplied in task; **no literal match anywhere in this rootfs** | Include defensively; DCMP service discovery is present, exact hostname is not |

Exact-host list for a hostname/IP alias (see limitations below):

```text
n-deventry-gw.tplinkcloud.com
n-devs-gw.tplinkcloud.com
n-device-api.tplinkcloud.com
n-da.tplinkcloud.com
api-homecare-cloud.i.tplinknbu.com
api-homecare-cloud-beta3.tplinknbu.com
api-ifttt-router.tplinknbu.com
n-wap-gw.tplinkcloud.com
dcmp-api.i.tplinkcloud.com
```

## Third-party runtime endpoints

| Host | Evidence | Purpose |
|---|---|---|
| `ast-dual.safethings.avira.com` | Avira sentinel full/lite, service selector, watchdog binaries under `usr/bin/avira/` | HTTPS configuration/certificates and embedded API; full sentinel also uses WSS |
| `dfp-dual.safethings.avira.com` | Avira sentinel full/lite binaries | `/deviceId/api/v2` fingerprint/device identification |
| `v2.web-rep.auc.avira.com` | `usr/lib/libauc.so.1.0.0`, Avira `auc_example` | HTTPS reputation API |
| `api.mixpanel.com` | Avira service selector binary | Analytics `/track?data=` |
| `ntp1.net.nortonlifelock.com` | `usr/sbin/aviraservice`, `etc_ro/init.d/aviraservicemaster` | Security-stack time service |
| `ntp2.net.nortonlifelock.com` | Same | Security-stack time service |
| `ntp3.net.nortonlifelock.com` | Same | Security-stack time service |

```text
ast-dual.safethings.avira.com
dfp-dual.safethings.avira.com
v2.web-rep.auc.avira.com
api.mixpanel.com
ntp1.net.nortonlifelock.com
ntp2.net.nortonlifelock.com
ntp3.net.nortonlifelock.com
```

## API paths and dynamic discovery

`usr/lib/lua/cloud_req/cloud_https_v2.lua` reads `etc/cloud_https.cfg`, calls validation, consumes `deviceToken`, `expiresIn`, `serverUrl`, and `serviceUrls`, and uses `/tmp/cloud/cloud_server_token` and `/tmp/cloud/cloud_token_cvm_server`. It obtains older service tokens via `/common/v1/getOldDeviceToken`. These are **dynamically assigned origins**, not additional static FQDNs.

Service identifiers found in `usr/sbin/cloud_getDevToken`:

```text
nbu.config-service
nbu.event.dcmp
nbu.event.gw
nbu.homecare-cloud
nbu.ifttt-router.api
nbu.iot-security.appdevice
nbu.router-cloud
```

`nbu.cvm-server` also appears in the HTTPS dispatcher, TSS scripts, and certificate modules. These identifiers are not DNS names and must not be pasted into a hostname alias.

Identified API routes (origins depend on service discovery unless explicitly stated):

```text
/common/v1/copyUserList
/common/v1/fwSubscription
/common/v1/getOldDeviceToken
/common/v1/getSecureIntlFwList
/common/v2/batchTransferOwnership
/common/v2/validateDeviceForTLV
/common/v2/validateDeviceForTSS
/v1/certificate/device/apply
/v1/certificate/get-ca
/v1/certificate/group/get-ca-certificate
/v1/certificate/noc/device/apply
/v1/cloud-config/get-device-configuration
/v1/devices/components
/v1/firmware/getSecureFwList
/v1/hardware
/v1/license
/v1/messages/internet-time
/v1/messages/trigger-alert-notification
/v1/messages/white-list
/v1/services/get-device-status
/v1/services/insights-time
/v1/services/insights-upload
/v1/services/monthly-report-upload
/v1/traffic/upload-traffic-usage
/v1/url-library/get-category
/v1/url-library/get-whitelist
/v1/url-library/retrieve-all-malicious-url
/v1/url-library/retrieve-malicious-size
/v1/url-library/retrieve-malicious-url
/v1/url-library/retrieve-url-category
/v1/validate
```

Additional explicit endpoints:

- Telemetry at `https://n-da.tplinkcloud.com`: `/api/data/device/uploadBasicData`, `/api/data/device/strategy/getDataCollectStrategy`.
- Commented device-recognition example: `https://api-homecare-cloud-beta3.tplinknbu.com/v1/device-recognition/retrieve-client-type`.
- Avira AST: `/config-get`, `/ca-get`, `/embedded/api/v2`, and WSS `/embedded/api/v2/websocket` on 443.
- Avira reputation library: `/api/auth`, `/api/query`, `/api/categories`, `/api/update`; TP-Link alternative uses the `/v1/url-library/` routes above.

OPNsense layer-3/4 rules cannot match HTTPS URL paths without TLS interception. Block by domain/IP or restrict egress instead.

## Exclusions and false positives

Do **not** treat all strings containing `cloud` or `tp-link` as phone-home destinations:

- `tplinkdeco.net`, `tplinkwifi.net`, `tplinklogin.net`: local administration names; preserve local access.
- `r0kh.tp-link.com`: Wi-Fi fast-transition key-holder identifier in `lib/wifi/wificommon.sh`, not a demonstrated outbound cloud host.
- `yapi.rd.tp-link.net/project/182/interface/api/97402`: developer documentation comment in `usr/sbin/report_get_device_status`, not a runtime API request.
- `tp-link.com`, `tp-link.com.cn`, `tp-link.com.hk`, `tp-link.net`: many copyright/email strings. Do not infer active cloud use from those alone.
- `www.tp-link.com`: UPnP manufacturer metadata, UI support/download links, and DNS-proxy configuration; not a core cloud API. Optional website/probe block, not required to cover the cloud suffixes above.
- `usr/lib/dpi/libipoque_pace2.so.6.0.16` contains a large application-identification domain catalogue. `etc/safesearch/rules` similarly contains filtering targets. Neither proves the router contacts those domains.
- XML schema URLs, certificate/documentation URLs, examples, Lua module names, and OpenWrt copyright references are not service destinations.

Other non-TP-Link external services are present: `www.speedtest.net`, configurable DDNS providers, Google DoH, Cloudflare/other DoT examples, internet connectivity probes, and `0`–`3.openwrt.pool.ntp.org` / `0`–`3.pool.ntp.org`. A TP-Link cloud blocklist intentionally does not claim to block all internet traffic.

## OPNsense staging deployment guidance — not applied

1. Ensure the Deco-originated traffic actually traverses the staging firewall. DNS/egress rules on a bypassed firewall cannot protect the devices. Distinguish device-originated traffic from ordinary clients behind the Deco's NAT before applying broad denies.
2. Use a DNS policy supporting **suffix matching** for the apexes above. An ordinary hostname/IP alias is not a wildcard domain matcher. Configure local DNS enforcement for Deco sources and account for IPv6, external DNS, DoT, DoH, cached answers, and hard-coded IPs.
3. A hostname alias can resolve the exact-host list and block its current addresses, but it is only supplemental: TTL changes, DNS rotation, different regional answers, and cloud-discovered destinations make it incomplete. Shared CDN addresses can cause collateral blocking. Do not hard-code one lookup's IPs as a permanent complete list.
4. For a strict no-phone-home guarantee, isolate management traffic and deny Deco-originated WAN egress by default, with narrow local allowances for `192.168.68.53:7547/TCP`, approved local DNS/NTP, management, and mesh needs. Do not indiscriminately deny the gateway's NAT source if that also carries household clients.
5. After an approved rule deployment, handle pre-existing states, observe firewall/DNS logs and packet capture for all Decos, and check both A/AAAA paths. Verify local management, mesh connectivity, and ACS informs still work. This scan did not perform those network enforcement tests.

## Satellite enrollment result

Direct encrypted API reads through `deco_run.session(host)` confirmed:

| Unit | IP | MAC / expected serial | ACS URL | Enabled | Independent NBI enrollment |
|---|---|---|---|---|---|
| Garage | `192.168.71.250` | `24-2F-D0-EB-BE-0C` / `242FD0EBBE0C` | `http://192.168.68.53:7547/` | CWMP and periodic inform already true | **Absent** |
| Charlotte’s Room | `192.168.71.249` | `24-2F-D0-EB-BE-20` / `242FD0EBBE20` | `http://192.168.68.53:7547/` | CWMP and periodic inform already true | **Absent** |

At `2026-11-01T09:05:18Z`, smith's `curl -fsS http://127.0.0.1:7557/devices` returned only `242FD0-X50-242FD0EB937C` (main Deco), last inform `2026-11-01T09:05:10.105Z`. Satellite URLs already matched the requested value, so **no redundant writes were made** and no other settings were changed.

The firmware's `etc_ro/init.d/cwmp` only starts the daemon when:

```sh
if [ ! -s /tmp/group-info ] || [ "$role" == "AP" ]; then
    # generate configuration and launch cwmp
fi
```

Here `role` is read from `bind_device_list.<device_id>.role`. Both live satellite entries have API role `slave`. This is strong evidence of a mesh-role startup restriction, not a wrong ACS URL; it is not a live shell/process inspection of the satellites. Independent enrollment cannot be claimed or completed with an already-correct URL alone. Bypassing the startup guard or changing device roles exceeds the permitted URL-only change.

Also, the existing `deco_run.py set-cwmp` implementation is stale: it hardcodes the main host and uses `cwmp`/`set`, whereas this firmware exposes `cwmp_info`/`write`. It was deliberately not invoked blindly. The imported encrypted client was used for correct read-only operations. A write would need to preserve the complete parameter set and avoid blanking omitted values.

Raw analysis artifacts on smith: `~/deco-cwmp/cloud-evidence.json`, `cloud-wide-scan.json`, `cloud-api-paths.json`, and `enrollment-verification.json`. Local companion evidence files accompany this report.
