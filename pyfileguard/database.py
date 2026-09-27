import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path.home() / ".pyfileguard" / "events.db"


def _create_v3_table(connection):
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event TEXT,
            severity TEXT,
            root TEXT,
            path TEXT,
            old_path TEXT
        )
        """
    )


def _columns(connection):
    return {
        row[1]
        for row in connection.execute("PRAGMA table_info(events)")
    }


def _migrate_v2_to_v3(connection):
    """
    Upgrade a PyFileGuard v0.2 events database to the v0.3 schema
    while preserving existing event history.
    """

    connection.execute("ALTER TABLE events RENAME TO events_v02")

    _create_v3_table(connection)

    rows = connection.execute(
        """
        SELECT
            id,
            timestamp,
            event_type,
            path,
            new_path,
            monitored_root
        FROM events_v02
        ORDER BY id
        """
    ).fetchall()

    for event_id, timestamp, event_type, path, new_path, root in rows:

        # v0.2 stored a rename as:
        # path = old filename
        # new_path = new filename
        #
        # v0.3 stores:
        # old_path = old filename
        # path = current/new filename
        if event_type == "RENAMED":
            current_path = new_path or path
            old_path = path
        else:
            current_path = path
            old_path = None

        # v0.2 had no severity information.
        # MEDIUM is used as a neutral migration default.
        severity = "MEDIUM"

        connection.execute(
            """
            INSERT INTO events(
                id,
                timestamp,
                event,
                severity,
                root,
                path,
                old_path
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                timestamp,
                event_type,
                severity,
                root,
                current_path,
                old_path,
            ),
        )

    connection.execute("DROP TABLE events_v02")
    connection.commit()


def _ensure_schema(connection):
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }

    if "events" not in tables:
        _create_v3_table(connection)
        connection.commit()
        return

    columns = _columns(connection)

    v3_columns = {
        "id",
        "timestamp",
        "event",
        "severity",
        "root",
        "path",
        "old_path",
    }

    v2_columns = {
        "id",
        "timestamp",
        "event_type",
        "path",
        "new_path",
        "monitored_root",
    }

    if v3_columns.issubset(columns):
        return

    if v2_columns.issubset(columns):
        _migrate_v2_to_v3(connection)
        return

    raise RuntimeError(
        "Unsupported PyFileGuard events database schema. "
        "Back up ~/.pyfileguard/events.db before making changes."
    )


def connect(path=None):
    p = Path(path or DB_PATH).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(p)

    try:
        _ensure_schema(connection)
    except Exception:
        connection.close()
        raise

    return connection


def add_event(event, root, db_path=None):
    with connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO events(
                timestamp,
                event,
                severity,
                root,
                path,
                old_path
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now()
                .astimezone()
                .isoformat(timespec="seconds"),
                event.kind,
                event.severity,
                root,
                event.path,
                event.old_path,
            ),
        )

        connection.commit()


def query_events(
    event=None,
    severity=None,
    path_text=None,
    limit=100,
    db_path=None,
):
    sql = """
        SELECT
            id,
            timestamp,
            event,
            severity,
            root,
            path,
            old_path
        FROM events
        WHERE 1=1
    """

    arguments = []

    if event:
        sql += " AND event=?"
        arguments.append(event.upper())

    if severity:
        sql += " AND severity=?"
        arguments.append(severity.upper())

    if path_text:
        sql += " AND (path LIKE ? OR old_path LIKE ?)"
        arguments.extend(
            [
                f"%{path_text}%",
                f"%{path_text}%",
            ]
        )

    sql += " ORDER BY id DESC LIMIT ?"
    arguments.append(int(limit))

    with connect(db_path) as connection:
        return connection.execute(sql, arguments).fetchall()