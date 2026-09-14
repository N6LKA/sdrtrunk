"""
Radio Keystore: local web UI + JSON API for manually-entered P25/DMR/NXDN
decryption keys, backing the encryption modifications in this SDRTrunk fork.

The SQLite database holds real key material and must never be committed.
It is created on first run at KEYSTORE_DB_PATH, outside the repo checkout.
"""
import os
import sqlite3
from pathlib import Path

from flask import Flask, abort, g, jsonify, redirect, render_template, request, url_for

APP_DIR = Path(__file__).resolve().parent
SCHEMA_PATH = APP_DIR / "schema.sql"
DB_PATH = Path(os.environ.get("KEYSTORE_DB_PATH", "/opt/sdrtrunk/keystore.db"))

# Algorithm ID -> name, per protocol. Mirrors the enums SDRTrunk itself parses
# (io.github.dsheirer.module.decode.p25.reference.Encryption,
#  io.github.dsheirer.module.decode.dmr.message.type.EncryptionAlgorithm,
#  io.github.dsheirer.module.decode.nxdn.layer3.type.CipherType) so the
# dropdowns here match what a decoded call will actually report.
ALGORITHMS = {
    "P25": [
        (0x00, "ACCORDIAN 3"),
        (0x01, "BATON AUTO EVEN"),
        (0x02, "FIREFLY"),
        (0x03, "MAYFLY"),
        (0x04, "SAVILLE"),
        (0x05, "MOTOROLA PADSTONE"),
        (0x41, "BATON AUTO ODD"),
        (0x80, "UNENCRYPTED"),
        (0x81, "DES OFB"),
        (0x82, "2-KEY TRIPLE DES"),
        (0x83, "3-KEY TRIPLE DES"),
        (0x84, "AES-256"),
        (0x85, "AES-128"),
        (0x88, "AES-CBC"),
        (0x89, "AES-128-OFB"),
        (0x9F, "MOTOROLA DES-XL"),
        (0xA0, "MOTOROLA DVI-XL"),
        (0xA1, "MOTOROLA DVP-XL"),
        (0xA2, "MOTOROLA DVP-SPFL"),
        (0xA3, "MOTOROLA HAYSTACK"),
        (0xAA, "MOTOROLA ADP 40-BIT RC4"),
        (0xAB, "MOTOROLA CFX-256"),
        (0xAF, "MOTOROLA AES-256-GCM"),
        (0xB0, "MOTOROLA DVP B0"),
    ],
    "DMR": [
        (0x00, "NO ENCRYPTION"),
        (0x01, "HYTERA BP"),
        (0x02, "HYTERA RC4/EP"),
        (0x21, "DMRA RC4/EP"),
        (0x24, "DMRA AES128"),
        (0x25, "DMRA AES256"),
        (0x26, "HYTERA RC4/EP"),
    ],
    "NXDN": [
        (0, "UNENCRYPTED"),
        (1, "SCRAMBLE"),
        (2, "DES"),
        (3, "AES"),
    ],
}


def get_db():
    if "db" not in g:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 5000")
    return g.db


def init_db():
    """Idempotent — schema.sql is all CREATE ... IF NOT EXISTS."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA_PATH.read_text())
    db.commit()
    db.close()


def create_app():
    app = Flask(__name__)

    @app.teardown_appcontext
    def close_db(exception):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.route("/")
    def index():
        db = get_db()
        systems = db.execute("SELECT * FROM systems ORDER BY protocol, label").fetchall()
        return render_template("index.html", systems=systems)

    @app.route("/systems", methods=["POST"])
    def add_system():
        db = get_db()
        db.execute(
            "INSERT INTO systems (protocol, label, identifier, notes) VALUES (?, ?, ?, ?)",
            (
                request.form["protocol"],
                request.form["label"],
                request.form.get("identifier") or None,
                request.form.get("notes") or None,
            ),
        )
        db.commit()
        return redirect(url_for("index"))

    @app.route("/systems/<int:system_id>")
    def view_system(system_id):
        db = get_db()
        system = db.execute("SELECT * FROM systems WHERE id = ?", (system_id,)).fetchone()
        if system is None:
            abort(404)
        keys = db.execute(
            "SELECT * FROM keys WHERE system_id = ? ORDER BY active DESC, algorithm_name, key_id",
            (system_id,),
        ).fetchall()
        algorithms = ALGORITHMS.get(system["protocol"], [])
        return render_template("system.html", system=system, keys=keys, algorithms=algorithms)

    @app.route("/systems/<int:system_id>/keys", methods=["POST"])
    def add_key(system_id):
        db = get_db()
        system = db.execute("SELECT * FROM systems WHERE id = ?", (system_id,)).fetchone()
        if system is None:
            abort(404)

        algorithm_id = int(request.form["algorithm_id"])
        algorithm_name = dict(ALGORITHMS.get(system["protocol"], [])).get(algorithm_id, "UNKNOWN")
        key_value_hex = request.form["key_value_hex"].strip().lower()
        key_id = int(request.form["key_id"])
        label = request.form.get("label") or None

        if not key_value_hex or any(c not in "0123456789abcdef" for c in key_value_hex):
            abort(400, "Key value must be hex")

        # Rotation: retire any existing active key for this system+algorithm+key_id
        db.execute(
            "UPDATE keys SET active = 0, updated_at = datetime('now') "
            "WHERE system_id = ? AND algorithm_id = ? AND key_id = ? AND active = 1",
            (system_id, algorithm_id, key_id),
        )
        db.execute(
            "INSERT INTO keys (system_id, algorithm_id, algorithm_name, key_id, "
            "key_value_hex, key_length_bits, label) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (system_id, algorithm_id, algorithm_name, key_id, key_value_hex, len(key_value_hex) * 4, label),
        )
        db.commit()
        return redirect(url_for("view_system", system_id=system_id))

    @app.route("/keys/<int:key_id>/deactivate", methods=["POST"])
    def deactivate_key(key_id):
        db = get_db()
        row = db.execute("SELECT system_id FROM keys WHERE id = ?", (key_id,)).fetchone()
        if row is None:
            abort(404)
        db.execute("UPDATE keys SET active = 0, updated_at = datetime('now') WHERE id = ?", (key_id,))
        db.commit()
        return redirect(url_for("view_system", system_id=row["system_id"]))

    # --- JSON API, queried by SDRTrunk at decrypt time ---

    @app.route("/api/keys/lookup")
    def api_lookup_key():
        protocol = request.args.get("protocol")
        identifier = request.args.get("identifier")
        algorithm_id = request.args.get("algorithm_id", type=int)
        key_id = request.args.get("key_id", type=int)

        if not protocol or not identifier or algorithm_id is None or key_id is None:
            abort(400, "protocol, identifier, algorithm_id, key_id are all required")

        db = get_db()
        row = db.execute(
            "SELECT k.key_value_hex, k.key_length_bits, k.algorithm_name "
            "FROM keys k JOIN systems s ON s.id = k.system_id "
            "WHERE s.protocol = ? AND s.identifier = ? AND k.algorithm_id = ? "
            "AND k.key_id = ? AND k.active = 1",
            (protocol, identifier, algorithm_id, key_id),
        ).fetchone()

        if row is None:
            return jsonify({"found": False}), 404

        return jsonify(
            {
                "found": True,
                "key_value_hex": row["key_value_hex"],
                "key_length_bits": row["key_length_bits"],
                "algorithm_name": row["algorithm_name"],
            }
        )

    @app.route("/api/systems")
    def api_list_systems():
        db = get_db()
        systems = db.execute("SELECT id, protocol, label, identifier FROM systems").fetchall()
        return jsonify([dict(s) for s in systems])

    return app


if __name__ == "__main__":
    init_db()
    create_app().run(
        host=os.environ.get("KEYSTORE_HOST", "0.0.0.0"),
        port=int(os.environ.get("KEYSTORE_PORT", "5901")),
    )
