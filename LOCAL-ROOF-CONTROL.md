# Roll-Off Roof — LAN-Only Local Control

Complete local control of the observatory roll-off roof over Wi-Fi/LAN, with **zero
calls to the Tuya cloud**. Discovered and validated on **2026-11-15/16**: the roof
was physically closed and re-opened purely via local TCP, verified on CAM01
(`192.168.1.104`).

## Quick usage

From `D:\roof-control` (works with the internet completely off):

```bat
roof status                     :: full DP dump + ROOF: OPEN/CLOSED/MOVING
roof watch                      :: live monitor, prints on every change
roof close --yes                :: close the roof (motion, needs --yes)
roof open --yes                 :: open the roof
roof stop --yes                 :: stop roof motion
node tuya35.js status --json    :: machine-readable (for scripting/automation)
```

`roof.cmd` is a thin wrapper over `node tuya35.js …`. Motion commands always
require the explicit `--yes` flag as a safety interlock.

## The device

| | |
|---|---|
| Function | Tuya **TY-WFH V3.01** Wi-Fi sliding-gate/roof controller (drives the roll-off roof motor) |
| Tuya name | `RollOffRoof` (cloud name), product `WFH`, product_id `q4tn6xb10zncammj` |
| LAN address | `192.168.1.151`, TCP port **6668** only (MAC `4C:A9:19:AC:E2:AB`) |
| Protocol | **Tuya local protocol v3.5** — `0x00006699` framing, AES-128-**GCM**, session-key handshake |
| Device ID | `bfc0ab8e065904940eg1vv` |
| local_key | in `.env.local` (gitignored) — fetched once from the Tuya cloud |
| Config file | `D:\roof-control\.env.local` |

## Data points (TY-WFH V3.01, community-verified + locally confirmed)

| DP | code | meaning |
|----|------|---------|
| 101 | `wfh_open` | write `true` → open command |
| 102 | `wfh_close` | write `true` → close command |
| 103 | `wfh_stop` | write `true` → stop command |
| 104 | `wfh_lock` | lock |
| 105 | `return_state` | 2=opening, 3=open, 4=closing, 5=closed, 6=locked, **11=stopped (observed locally, not in community docs)**, 12=open, 13=closed |
| 106 | `l_close` | closed limit switch (`true` = at closed limit) |
| 107 | `l_open` | open limit switch (`true` = at open limit) |
| 108 | `inrf` | IR sensor |
| 109 | `fsw` | ground/magnetic sensor |
| 110 | `fast_op` | quick-open mode |
| 112 | `wfh_rssi` | Wi-Fi RSSI (≈ -55 dBm) |

Roof state is judged from the limit switches (106/107) first, `return_state` (105)
for motion. Full close→limit cycle takes ≈10-15 s.

## Protocol notes (v3.5 — the reason stock tools fail)

This device speaks **protocol 3.5**, the newest Tuya local protocol. It ignores all
unauthenticated traffic, RSTs 3.3-style queries, and does not answer legacy UDP
discovery on 6666/6667. `tuyapi` (npm) cannot talk to it (its 3.5 session-key
derivation is broken — it keeps 48 bytes instead of the 16-byte ciphertext).
The implementation in `tuya35.js` follows **tinytuya**
(github.com/jasonacox/tinytuya), the reference Python implementation.

### Frame format (both directions)

```
00 00 66 99 | unknown u16 | seq u32 | cmd u32 | len u32 | iv[12] | ciphertext | tag[16] | 00 00 99 66
```

- `len` = ciphertext length + 28 (iv 12 + tag 16; the 4-byte suffix is not counted)
- AES-128-**GCM**, AAD = frame bytes 4..18 (everything after the prefix)
- Before the session handshake the key is the `local_key`; afterwards it is the
  negotiated `sessionKey`
- Received plaintext = `retcode u32` + payload (optionally prefixed with
  `"3.5" + 12 zero bytes` version header)

### Session handshake (per connection)

```
1. → cmd 3  (SESS_KEY_NEG_START):  16 random bytes, GCM(localKey)
2. ← cmd 4  (SESS_KEY_NEG_RESP):   retcode(0) + remoteNonce[16] + HMAC-SHA256(localKey, our nonce)[32]
3. → cmd 5  (SESS_KEY_NEG_FINISH): HMAC-SHA256(localKey, remoteNonce)   (fire-and-forget)
4. sessionKey = AES-GCM(localKey, iv=ourNonce[0:12]).encrypt(ourNonce XOR remoteNonce).ciphertext[16]
```

The HMAC check in step 2 is what proves the `local_key` is correct.

### Commands (after handshake, GCM with sessionKey)

- **DP_QUERY_NEW (cmd 16)**: payload is literally `{}` — no version header
  (query commands are exempt). Response: `{"dps":{"105":3,"106":false,...}}`
- **CONTROL_NEW (cmd 13)**: payload = `"3.5" + 12×0x00` + `{"protocol":5,"t":<unix>,"data":{"dps":{"101":true}}}`
  — the version header **is** required here; without it the device replies
  `"data format error"` (found out the hard way)
- Each command may use a fresh connection (connect ≈ handshake ≈ 100 ms), which
  is what the CLI does — no heartbeat management needed. `watch` reuses one
  connection and reconnects automatically if it drops.

## Files

| File | Purpose |
|------|---------|
| `tuya35.js` | Protocol-3.5 client: module (`require`) + CLI (`status/watch/open/close/stop/set`) |
| `roof.cmd` | Windows wrapper: `roof status`, `roof open --yes`, … |
| `.env.local` | IP / device ID / local key (gitignored) |
| `get-local-key.js` | One-time key fetcher via Tuya OpenAPI (needs an active IoT Core subscription) |
| `LOCAL-ROOF-CONTROL.md` | This document |
| `tuyaService.js`, `server.js`, web UI | Original cloud-based setup — **left untouched on purpose** |

## The local_key

- Static per device provisioning; never changes on its own.
- **Changes if the device is removed and re-paired in the Tuya Smart app.**
- Was obtained 2026-11-16 via Tuya IoT Platform **API Explorer** → Device
  Management → *Query Device Details in Bulk* → `local_key` (the project's IoT Core
  trial had expired; prolongation was in review, so the manual console route was
  used — no coding needed).
- Alternative: `node get-local-key.js` with `.env` credentials, once the IoT Core
  subscription is active.
- The key is a secret: anyone on the LAN who has it can operate the roof.
  Keep `.env.local` private (already gitignored).

## Troubleshooting

- `FAILED: timeout waiting for frame` — device offline/rebooting (Wi-Fi down, power
  cycle). The TY-WFH usually returns in ~30 s after power-up.
- `HMAC mismatch — wrong local key` — device was re-paired; re-fetch the key (see above).
- Weird roof state — combine `l_open`/`l_close` (limit switches) with `return_state`.
- If the device firmware ever changes the protocol version (e.g. 3.4), re-test with
  tinytuya (`pip install tinytuya`) — the reference implementation.

## Provenance

2026-11-15: LAN scan found only TCP 6668 open on `192.168.1.151`; DVRIP-style probes
ruled out an XM camera. Tuya cloud project in `.env` gave the device ID and DP codes;
its IoT Core subscription had expired (code 28841002) blocking the programmatic
key fetch. Keyless TCP probes showed the device ignores all unauthenticated
traffic. Key obtained manually via API Explorer; the raw handshake probe
(`cmd 3`, GCM framing `0x00006699`) got `cmd 4` back → **protocol 3.5 confirmed,
key verified via HMAC**. Full client written in Node (`tuya35.js`); status query
worked immediately; the first control attempt returned `"data format error"` until
the `3.5` version header was prepended. Then, with the telescope parked:
`stop` accepted → roof **closed** (4→5, `l_close=true`) → **re-opened**
(2→3, `l_open=true`), observed live on CAM01 via the VMS app.
