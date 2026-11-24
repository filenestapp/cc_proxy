#!/usr/bin/env python3
"""Stream an existing SQLite v2 database to the Go migration command."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys

# Load parent tables before their dependents. Monitoring and console tables can be missing
# from SQLite databases that were initialized but never served.
TABLES = {
    "settings": "key value",
    "hosts": "name public_host port_min port_max reality_private reality_public short_id server_name "
             "handshake_server handshake_port block_private block_cidrs agent_token_hash created_at",
    "egress_ips": "ip host banned cooldown_until note",
    "users": "name password_hash mode egress_ip host port max_devices created_at",
    "devices": "id user_name name platform uuid token_hash revoked_at last_seen created_at",
    "admins": "name password_hash created_at last_login",
    "admin_sessions": "token_hash admin csrf created_at expires_at address",
    "audit": "id at actor action target detail address",
    "agents": "name last_seen config_etag singbox_running apply_error apply_state",
    "probes": "id kind subject source target ok latency_ms detail at",
    "alerts": "id key rule subject severity summary state started_at fired_at resolved_at notify notified_at notify_error",
}
CORE = {"settings", "hosts", "egress_ips", "users", "devices"}


def copy_value(value):
    if value is None:
        return r"\N"
    return str(value).replace("\\", r"\\").replace("\t", r"\t").replace("\n", r"\n").replace("\r", r"\r")


def source_rows(db, table, columns):
    if table == "settings":
        return db.execute("SELECT key, value FROM settings WHERE key != 'schema'")
    if table == "users":
        return db.execute(
            "SELECT u.name, u.password_hash, u.mode, u.egress_ip, e.host, u.port, u.max_devices, u.created_at "
            "FROM users u LEFT JOIN egress_ips e ON e.ip = u.egress_ip"
        )
    if table == "agents":
        have = {col[1] for col in db.execute("PRAGMA table_info(agents)")}
        optional = {"apply_error", "apply_state"}
        columns = ", ".join(
            "NULL" if col in optional and col not in have else col for col in columns.split(", ")
        )
    return db.execute(f"SELECT {columns} FROM {table}")


def main(file):
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    uri = Path(file).resolve(strict=True).as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as db:
        db.execute("BEGIN")
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        marker = db.execute("SELECT value FROM settings WHERE key = 'schema'").fetchone() if "settings" in tables else None
        if not CORE <= tables or not marker or json.loads(marker[0]) != 2:
            raise RuntimeError("source must be a control plane SQLite v2 database")
        for table, columns in TABLES.items():
            if table not in tables:
                continue
            print(table + " " + columns)
            for row in source_rows(db, table, ", ".join(columns.split())):
                print("\t".join(map(copy_value, row)))
            print(r"\.")


if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except (OSError, sqlite3.Error, ValueError, RuntimeError) as exc:
        sys.exit(str(exc))
