"""
Módulo de banco de dados SQLite para cache de análises de URL.
Armazena resultados para consulta rápida em verificações futuras.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, Optional

_DB_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")
_DB_PATH = os.path.join(_DB_DIR, "url_cache.db")
_lock = threading.Lock()


def _get_db_path() -> str:
    os.makedirs(_DB_DIR, exist_ok=True)
    return _DB_PATH


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_get_db_path(), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db() -> None:
    """Cria a tabela se não existir."""
    with _lock:
        conn = _connect()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS url_analysis (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    url         TEXT NOT NULL UNIQUE,
                    risk_class  TEXT NOT NULL,
                    score       REAL NOT NULL,
                    confidence  REAL NOT NULL DEFAULT 0.0,
                    details     TEXT NOT NULL DEFAULT '{}',
                    source      TEXT NOT NULL DEFAULT 'model',
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_url ON url_analysis (url)
            """)
            conn.commit()
        finally:
            conn.close()


@dataclass
class CachedResult:
    url: str
    risk_class: str
    score: float
    confidence: float
    details: Dict[str, Any]
    source: str
    created_at: str
    updated_at: str


def lookup_url(url: str) -> Optional[CachedResult]:
    """Busca resultado da URL no cache. Retorna None se não encontrado."""
    init_db()
    normalized = url.strip().lower().rstrip("/")
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM url_analysis WHERE url = ? LIMIT 1",
                (normalized,),
            ).fetchone()
            if row is None:
                return None
            return CachedResult(
                url=row["url"],
                risk_class=row["risk_class"],
                score=row["score"],
                confidence=row["confidence"],
                details=json.loads(row["details"]),
                source=row["source"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )
        finally:
            conn.close()


def save_result(
    url: str,
    risk_class: str,
    score: float,
    confidence: float,
    details: Dict[str, Any],
    source: str = "model",
) -> None:
    """Salva ou atualiza resultado no cache."""
    init_db()
    normalized = url.strip().lower().rstrip("/")
    now = datetime.utcnow().isoformat()
    details_json = json.dumps(details, ensure_ascii=False, default=str)
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO url_analysis (url, risk_class, score, confidence, details, source, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    risk_class = excluded.risk_class,
                    score      = excluded.score,
                    confidence = excluded.confidence,
                    details    = excluded.details,
                    source     = excluded.source,
                    updated_at = excluded.updated_at
                """,
                (normalized, risk_class, score, confidence, details_json, source, now, now),
            )
            conn.commit()
        finally:
            conn.close()
