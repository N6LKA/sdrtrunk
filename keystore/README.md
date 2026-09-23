# Radio Keystore

Local web UI + SQLite-backed store for manually-entered decryption keys
(P25 / DMR / NXDN), part of this fork's encryption modifications to SDRTrunk.

## Why

SDRTrunk already decodes the Algorithm ID, Key ID, and (for P25) Message
Indicator for every encrypted call, but has no way to hold an actual key
value you're authorized to use. This app is that missing piece: a place to
enter and manage keys, and a local JSON API the SDRTrunk process queries at
decrypt time.

## Running

    pip install -r requirements.txt
    python server.py

| Variable         | Default                                | Purpose                                             |
|------------------|------------------------------------------|-------------------------------------------------------|
| KEYSTORE_DB_PATH | /var/lib/sdrtrunk-keystore/keystore.db | Path to the SQLite database. Created on first run.   |
| KEYSTORE_HOST    | 0.0.0.0                                | Bind address for the web UI / API                     |
| KEYSTORE_PORT    | 5901                                    | Bind port                                             |

The database holds real decryption key material. The default path lives
under `/var/lib`, deliberately outside any location you'd plausibly clone
this repo into, so a fresh checkout or `git clean` can never touch it. The
app refuses to start if `KEYSTORE_DB_PATH` is pointed inside the repo
checkout at all, even if overridden — fail loud rather than risk it. Put the
web UI behind your normal LAN auth (e.g. Authelia) rather than exposing it
publicly.

## Running as a service

`sdrtrunk-keystore.service` assumes the checkout lives at `/opt/sdrtrunk-src`
and runs as user `n6lka` with a venv at `keystore/venv` — adjust paths/user
if yours differ.

    sudo cp sdrtrunk-keystore.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now sdrtrunk-keystore

    # logs
    journalctl -u sdrtrunk-keystore -f

## JSON API (used by SDRTrunk)

`GET /api/keys/lookup?protocol=P25&identifier=<system identifier>&algorithm_id=<int>&key_id=<int>`

Returns `{"found": true, "key_value_hex": "...", "key_length_bits": 256, "algorithm_name": "AES-256"}`,
or a 404 with `{"found": false}` if no active key matches.

## Status

- **Keystore app**: done, deployed, live-tested (systemd service, key
  entry/rotation, San Manuel DMR RC4 key verified end to end).
- **Java HTTP client**: `io.github.dsheirer.keystore.KeystoreClient` calls
  `/api/keys/lookup` and returns raw key bytes. Wired into `DMRAudioModule`
  (see below); not yet wired into `P25P1AudioModule`/`P25P2AudioModule`.
- **DMR RC4 decrypt engine (algorithm 0x21, DMRA Enhanced Privacy)**: written
  and wired into `DMRAudioModule`. Core codec logic
  (`AmbeFrameCodec`/`DmrRc4Decryptor`) is rigorously verified against the
  real, unmodified JMBE `AMBEFrame` class as an oracle - see
  `verification/dmr-rc4/README.md` for the full methodology and results
  (tens of thousands of trials, 0 failures). **Not yet verified against
  real over-the-air encrypted audio** - no captured RF sample was available
  to test against. The full project wouldn't compile in the sandbox this
  was written in (unrelated pre-existing JavaFX toolchain gap - confirmed
  by checking: the *original*, untouched `DMRAudioModule.java` hits the
  identical wall in that environment, so it's not something introduced
  here) - a real build on a proper dev machine is the next step before any
  live test.
- **P25 (DES-OFB / AES-256-OFB) decrypt engine**: not started. Same overall
  approach should apply (JMBE's IMBE codec has the same FEC-decode-then-
  encrypt-then-transmit structure), but P25's own FEC/interleaving scheme
  needs its own investigation - don't assume it's a copy-paste of the DMR
  AMBE work.

### Why decrypt isn't just XOR-the-frame

Traced through DSD-FME's reference implementation (github.com/lwvmobile/dsd-fme)
and JMBE's actual source (github.com/DSheirer/jmbe, `codec/` module): P25 and
DMR encryption is applied to the FEC-*decoded* voice codec parameters (49
corrected bits for DMR AMBE, IMBE is analogous), not to the raw transmitted
frame bytes SDRTrunk hands to the codec. FEC correction (Golay23/Golay24 for
DMR) happens *inside* `AMBEFrame`'s private `decode()` method in JMBE's codec
module, with no exposed hook to intercept the corrected-but-still-encrypted
bits, or to inject externally-decrypted bits back in.

Compounding this: JMBE's codec implementation (where `AMBEFrame`/`Golay23`/
etc. actually live) isn't even a compile-time dependency of SDRTrunk - it's
built separately by the end user and loaded as a runtime plugin (see the
`jmbe-api` vs `codec` module split, and the JMBE README's patent notice on
why). SDRTrunk only ever sees the `IAudioCodec` interface: raw frame bytes
in, PCM audio out. There is no supported extension point at the "decoded
but still encrypted" layer.

Realistic path forward: port the FEC-decode + descrambling step (Golay23/
Golay24 correction, vector extraction/descrambling - `AMBEFrame.decode()`
in JMBE's codec module is the reference, GPL and readable) into this fork,
decrypt the corrected bits, then re-encode them back into a synthetic frame
that the existing unmodified `IAudioCodec.getAudio(byte[])` call can consume
normally. This avoids reimplementing vocoder synthesis itself, but is real
DSP/FEC porting work, not a quick change - scope it as its own task before
starting.
