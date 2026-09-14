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

| Variable         | Default                   | Purpose                                                        |
|------------------|----------------------------|-----------------------------------------------------------------|
| KEYSTORE_DB_PATH | /opt/sdrtrunk/keystore.db | Path to the SQLite database. Created on first run.              |
| KEYSTORE_HOST    | 0.0.0.0                   | Bind address for the web UI / API                                |
| KEYSTORE_PORT    | 5901                       | Bind port                                                        |

The database holds real decryption key material. It is created outside the
repo checkout and is never committed — put the web UI behind your normal LAN
auth (e.g. Authelia) rather than exposing it publicly.

## JSON API (used by SDRTrunk)

`GET /api/keys/lookup?protocol=P25&identifier=<system identifier>&algorithm_id=<int>&key_id=<int>`

Returns `{"found": true, "key_value_hex": "...", "key_length_bits": 256, "algorithm_name": "AES-256"}`,
or a 404 with `{"found": false}` if no active key matches.

## Status

Scaffolding only. The SDRTrunk (Java) side does not call this API yet — that
integration, and the actual decrypt implementation in the `P25P1AudioModule`
/ `P25P2AudioModule` `processAudio` methods, is future work.
