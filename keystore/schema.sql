-- Radio Keystore schema.
-- Applied automatically on first run (see server.py:init_db). Safe to re-run.

CREATE TABLE IF NOT EXISTS systems (
    id          INTEGER PRIMARY KEY,
    protocol    TEXT NOT NULL CHECK(protocol IN ('P25', 'DMR', 'NXDN')),
    label       TEXT NOT NULL,
    identifier  TEXT,                -- P25: WACN/SYSID hex; DMR: network name; NXDN: RAN
    notes       TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS keys (
    id               INTEGER PRIMARY KEY,
    system_id        INTEGER NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    algorithm_id     INTEGER NOT NULL,   -- matches the protocol's own ALGID/algorithm enum
    algorithm_name   TEXT NOT NULL,
    key_id           INTEGER NOT NULL,   -- over-the-air key ID from the sync frame
    key_value_hex    TEXT NOT NULL,      -- the actual secret, hex-encoded
    key_length_bits  INTEGER NOT NULL,
    label            TEXT,
    active           INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Only one active key per system+algorithm+key_id at a time. Rotating a key
-- retires the old row (active=0) and inserts a new one, so history isn't lost.
CREATE UNIQUE INDEX IF NOT EXISTS idx_active_key
    ON keys(system_id, algorithm_id, key_id)
    WHERE active = 1;
