from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from agentguard.models import AgentTrace, TraceEvent


class TraceRecorder:
    def __init__(self, db_path: str | Path = "runs/agentguard.sqlite3"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS trace_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    step_id TEXT,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_trace_events_run_id ON trace_events(run_id)"
            )

    def record_event(self, event: TraceEvent) -> None:
        payload = event.model_dump(mode="json", by_alias=True)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO trace_events (run_id, step_id, event_type, payload_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    event.run_id,
                    event.step_id,
                    event.event_type,
                    json.dumps(payload, ensure_ascii=False),
                ),
            )

    def load_trace(self, run_id: str) -> AgentTrace:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT payload_json
                FROM trace_events
                WHERE run_id = ?
                ORDER BY id ASC
                """,
                (run_id,),
            ).fetchall()
        events = [TraceEvent.model_validate(json.loads(row[0])) for row in rows]
        return AgentTrace(run_id=run_id, steps=events)
