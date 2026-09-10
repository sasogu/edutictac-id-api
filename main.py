"""EduTicTac ID API: pseudonymous student credentials.

The service stores no student names, emails or institutional identifiers. A
teacher creates groups and public codes; pupils authenticate with public code +
PIN. PINs are hashed and are only returned immediately after generation or
rotation.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator
from edutictac_community.db import connect as db_connect
from edutictac_community.ratelimit import RateLimiter
from edutictac_community.session import SignedSession

DB_PATH = os.environ.get("EDUTICTAC_ID_DB", "/var/lib/edutictac-id-api/id.db")
SESSION_SECRET = os.environ.get("EDUTICTAC_ID_SECRET", "")
TEACHER_TOKEN = os.environ.get("EDUTICTAC_ID_TEACHER_TOKEN", "")
COOKIE_DOMAIN = os.environ.get("EDUTICTAC_ID_COOKIE_DOMAIN", "")
COOKIE_SECURE = os.environ.get("EDUTICTAC_ID_COOKIE_SECURE", "1") != "0"
SESSION_COOKIE = "edutictac_id"
TEACHER_COOKIE = "edutictac_teacher"
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_RE = re.compile(r"^[A-Z2-9]{3}$")
PIN_RE = re.compile(r"^[0-9]{4,6}$")
GROUP_CODE_RE = re.compile(r"^G[A-Z2-9]{5}$")
SESSION_TTL_DAYS = 180
RATE_WINDOW = 60
RATE_MAX = 12
PIN_HASH_ITERATIONS = int(os.environ.get("EDUTICTAC_ID_PIN_HASH_ITERATIONS", "210000"))

app = FastAPI(title="EduTicTac ID API")

_rate_limiter = RateLimiter(max_calls=RATE_MAX, window_seconds=RATE_WINDOW)


def get_conn() -> sqlite3.Connection:
    conn = db_connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return now_utc().isoformat()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY,
                name TEXT DEFAULT '',
                tenant_id TEXT NOT NULL DEFAULT 'default',
                created_by_teacher_id TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS student_identities (
                id TEXT PRIMARY KEY,
                group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
                public_code TEXT NOT NULL,
                pin_hash TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                pin_rotated_at TEXT,
                UNIQUE(group_id, public_code)
            );

            CREATE TABLE IF NOT EXISTS student_sessions (
                id TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL REFERENCES student_identities(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT
            );

            CREATE TABLE IF NOT EXISTS scores (
                id TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL REFERENCES student_identities(id) ON DELETE CASCADE,
                app_id TEXT NOT NULL,
                activity_id TEXT NOT NULL,
                score INTEGER NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scores_rank
                ON scores(app_id, activity_id, score DESC, created_at ASC);
            CREATE INDEX IF NOT EXISTS idx_sessions_identity
                ON student_sessions(identity_id);
            CREATE INDEX IF NOT EXISTS idx_identities_public_code
                ON student_identities(public_code);
            """
        )


init_db()


def require_secret() -> None:
    if not SESSION_SECRET:
        raise HTTPException(status_code=503, detail="service secret not configured")


def make_cookie(payload: dict[str, Any]) -> str:
    require_secret()
    return SignedSession(SESSION_SECRET, "").encode(payload)


def parse_cookie(raw: str | None) -> dict[str, Any] | None:
    return SignedSession(SESSION_SECRET, "").decode(raw)


def cookie_kwargs(max_age: int | None = None) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "httponly": True,
        "secure": COOKIE_SECURE,
        "samesite": "lax",
        "path": "/",
    }
    if COOKIE_DOMAIN:
        kwargs["domain"] = COOKIE_DOMAIN
    if max_age is not None:
        kwargs["max_age"] = max_age
    return kwargs


def delete_cookie_kwargs() -> dict[str, Any]:
    kwargs: dict[str, Any] = {"path": "/"}
    if COOKIE_DOMAIN:
        kwargs["domain"] = COOKIE_DOMAIN
    return kwargs


def hash_pin(pin: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), PIN_HASH_ITERATIONS)
    return f"pbkdf2_sha256${PIN_HASH_ITERATIONS}${salt}${digest.hex()}"


def verify_pin(pin: str, encoded: str) -> bool:
    try:
        algo, iterations_raw, salt, expected = encoded.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), int(iterations_raw))
        return hmac.compare_digest(digest.hex(), expected)
    except Exception:
        return False


def normalize_code(raw: str) -> str:
    code = (raw or "").strip().upper()
    if not CODE_RE.fullmatch(code):
        raise HTTPException(status_code=400, detail="invalid public code")
    if any(ch not in CODE_ALPHABET for ch in code):
        raise HTTPException(status_code=400, detail="confusing characters are not allowed")
    return code


def validate_pin(raw: str) -> str:
    pin = (raw or "").strip()
    if not PIN_RE.fullmatch(pin):
        raise HTTPException(status_code=400, detail="invalid PIN")
    return pin


def make_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(3))


def make_pin(length: int = 4) -> str:
    if length not in (4, 6):
        raise HTTPException(status_code=400, detail="pin_length must be 4 or 6")
    return "".join(secrets.choice("0123456789") for _ in range(length))


def make_group_code() -> str:
    return "G" + "".join(secrets.choice(CODE_ALPHABET) for _ in range(5))


def public_identity(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "group_id": row["group_id"],
        "public_code": row["public_code"],
        "active": bool(row["active"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def rate_limited(key: str) -> bool:
    return _rate_limiter(key)


def require_teacher(request: Request) -> str:
    cookie = parse_cookie(request.cookies.get(TEACHER_COOKIE))
    if cookie and cookie.get("teacher"):
        return str(cookie.get("teacher_id") or "teacher")
    if not TEACHER_TOKEN:
        raise HTTPException(status_code=503, detail="teacher token not configured")
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer ") and hmac.compare_digest(auth[7:].encode(), TEACHER_TOKEN.encode()):
        return "teacher-token"
    raise HTTPException(status_code=401, detail="teacher authentication required")


def is_teacher(request: Request) -> bool:
    try:
        require_teacher(request)
        return True
    except HTTPException:
        return False


def current_identity(request: Request) -> dict[str, Any] | None:
    cookie = parse_cookie(request.cookies.get(SESSION_COOKIE))
    if not cookie or not cookie.get("sid"):
        return None
    token_hash = hashlib.sha256(str(cookie["sid"]).encode()).hexdigest()
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT i.* FROM student_sessions s
            JOIN student_identities i ON i.id = s.identity_id
            WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND i.active = 1
            """,
            (token_hash, iso_now()),
        ).fetchone()
    return public_identity(row) if row else None


def require_ranking_viewer(request: Request) -> dict[str, Any] | None:
    identity = current_identity(request)
    if identity:
        return identity
    if is_teacher(request):
        return None
    raise HTTPException(status_code=401, detail="student or teacher authentication required")


def set_student_session(response: Response, identity_id: str) -> str:
    session_token = secrets.token_urlsafe(32)
    session_id = secrets.token_urlsafe(18)
    token_hash = hashlib.sha256(session_token.encode()).hexdigest()
    created_at = now_utc()
    expires_at = created_at + timedelta(days=SESSION_TTL_DAYS)
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO student_sessions (id, identity_id, token_hash, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, identity_id, token_hash, created_at.isoformat(), expires_at.isoformat()),
        )
    response.set_cookie(
        SESSION_COOKIE,
        make_cookie({"sid": session_token}),
        **cookie_kwargs(max_age=SESSION_TTL_DAYS * 24 * 60 * 60),
    )
    return session_id


class TeacherLoginIn(BaseModel):
    token: str


class GroupIn(BaseModel):
    tenant_id: str = "default"

    @field_validator("tenant_id")
    @classmethod
    def _tenant(cls, value: str) -> str:
        tenant = re.sub(r"[^a-z0-9_-]+", "-", (value or "default").lower()).strip("-")
        return tenant[:48] or "default"


class BatchIn(GroupIn):
    count: int = Field(ge=1, le=120)
    pin_length: int = 4


class StudentAuthIn(BaseModel):
    group_id: str = ""
    public_code: str
    pin: str


class ScoreIn(BaseModel):
    app_id: str
    activity_id: str
    score: int
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("score")
    @classmethod
    def _score(cls, value: int) -> int:
        if value < 0 or value > 1_000_000:
            raise ValueError("score out of range")
        return value


class AppRosterIn(BaseModel):
    group_id: str


def normalize_app_id(raw: str) -> str:
    app_id = re.sub(r"[^a-z0-9_-]+", "-", (raw or "").lower()).strip("-")[:64]
    if not app_id:
        raise HTTPException(status_code=400, detail="invalid app_id")
    return app_id


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/teacher/login")
def teacher_login(payload: TeacherLoginIn, response: Response) -> dict[str, bool]:
    if not TEACHER_TOKEN:
        raise HTTPException(status_code=503, detail="teacher token not configured")
    if not hmac.compare_digest(payload.token.encode(), TEACHER_TOKEN.encode()):
        raise HTTPException(status_code=401, detail="invalid teacher token")
    response.set_cookie(
        TEACHER_COOKIE,
        make_cookie({"teacher": True, "teacher_id": "teacher-token"}),
        **cookie_kwargs(max_age=8 * 60 * 60),
    )
    return {"ok": True}


@app.post("/api/groups", status_code=201)
def create_group(payload: GroupIn, request: Request) -> dict[str, Any]:
    teacher_id = require_teacher(request)
    group_id = secrets.token_urlsafe(10)
    group_code = make_group_code()
    ts = iso_now()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO groups (id, name, tenant_id, created_by_teacher_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (group_id, group_code, payload.tenant_id, teacher_id, ts, ts),
        )
    return {"id": group_id, "group_code": group_code, "tenant_id": payload.tenant_id}


@app.post("/api/identities/batch", status_code=201)
def create_batch(payload: BatchIn, request: Request) -> dict[str, Any]:
    teacher_id = require_teacher(request)
    pin_length = payload.pin_length
    if pin_length not in (4, 6):
        raise HTTPException(status_code=400, detail="pin_length must be 4 or 6")
    group_id = secrets.token_urlsafe(10)
    group_code = make_group_code()
    ts = iso_now()
    generated: list[dict[str, str]] = []
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO groups (id, name, tenant_id, created_by_teacher_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (group_id, group_code, payload.tenant_id, teacher_id, ts, ts),
        )
        for _ in range(payload.count):
            for _attempt in range(200):
                code = make_code()
                exists = conn.execute(
                    "SELECT 1 FROM student_identities WHERE public_code = ?",
                    (code,),
                ).fetchone()
                if not exists:
                    break
            else:
                raise HTTPException(status_code=409, detail="unable to generate unique code")
            pin = make_pin(pin_length)
            identity_id = secrets.token_urlsafe(16)
            conn.execute(
                """
                INSERT INTO student_identities
                    (id, group_id, public_code, pin_hash, active, created_at, updated_at, pin_rotated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (identity_id, group_id, code, hash_pin(pin), ts, ts, ts),
            )
            generated.append({"id": identity_id, "public_code": code, "pin": pin})
    return {
        "group": {"id": group_id, "group_code": group_code, "tenant_id": payload.tenant_id},
        "identities": generated,
    }


@app.post("/api/auth/student")
def student_login(payload: StudentAuthIn, request: Request, response: Response) -> dict[str, Any]:
    code = normalize_code(payload.public_code)
    pin = validate_pin(payload.pin)
    group_id = (payload.group_id or "").strip()
    key = f"{_client_ip(request)}:{group_id}:{code}"
    if rate_limited(key):
        raise HTTPException(status_code=429, detail="too many attempts")
    with get_conn() as conn:
        if group_id:
            rows = conn.execute(
                """
                SELECT * FROM student_identities
                WHERE group_id = ? AND public_code = ? AND active = 1
                """,
                (group_id, code),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM student_identities
                WHERE public_code = ? AND active = 1
                """,
                (code,),
            ).fetchall()
    matches = [row for row in rows if verify_pin(pin, row["pin_hash"])]
    if len(matches) != 1:
        raise HTTPException(status_code=401, detail="invalid code or PIN")
    row = matches[0]
    set_student_session(response, row["id"])
    return {"identity": public_identity(row)}


@app.get("/api/auth/me")
def me(request: Request) -> dict[str, Any]:
    identity = current_identity(request)
    if not identity:
        raise HTTPException(status_code=401, detail="not authenticated")
    return {"identity": identity}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response) -> dict[str, bool]:
    cookie = parse_cookie(request.cookies.get(SESSION_COOKIE))
    if cookie and cookie.get("sid"):
        token_hash = hashlib.sha256(str(cookie["sid"]).encode()).hexdigest()
        with get_conn() as conn:
            conn.execute(
                "UPDATE student_sessions SET revoked_at = ? WHERE token_hash = ?",
                (iso_now(), token_hash),
            )
    response.delete_cookie(SESSION_COOKIE, **delete_cookie_kwargs())
    return {"ok": True}


@app.post("/api/identities/{identity_id}/regenerate-pin")
def regenerate_pin(identity_id: str, request: Request, pin_length: int = Query(4)) -> dict[str, str]:
    require_teacher(request)
    pin = make_pin(pin_length)
    ts = iso_now()
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE student_identities
            SET pin_hash = ?, updated_at = ?, pin_rotated_at = ?
            WHERE id = ? AND active = 1
            """,
            (hash_pin(pin), ts, ts, identity_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="identity not found")
        conn.execute(
            "UPDATE student_sessions SET revoked_at = ? WHERE identity_id = ? AND revoked_at IS NULL",
            (ts, identity_id),
        )
    return {"id": identity_id, "pin": pin}


@app.post("/api/identities/{identity_id}/revoke")
def revoke_identity(identity_id: str, request: Request) -> dict[str, bool]:
    require_teacher(request)
    ts = iso_now()
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE student_identities SET active = 0, updated_at = ? WHERE id = ?",
            (ts, identity_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="identity not found")
        conn.execute(
            "UPDATE student_sessions SET revoked_at = ? WHERE identity_id = ? AND revoked_at IS NULL",
            (ts, identity_id),
        )
    return {"ok": True}


@app.post("/api/scores", status_code=201)
def add_score(payload: ScoreIn, request: Request) -> dict[str, Any]:
    identity = current_identity(request)
    if not identity:
        raise HTTPException(status_code=401, detail="not authenticated")
    score_id = secrets.token_urlsafe(12)
    ts = iso_now()
    app_id = normalize_app_id(payload.app_id)
    activity_id = re.sub(r"[^a-z0-9_.:-]+", "-", payload.activity_id.lower()).strip("-")[:128]
    if not activity_id:
        raise HTTPException(status_code=400, detail="invalid activity_id")
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO scores (id, identity_id, app_id, activity_id, score, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (score_id, identity["id"], app_id, activity_id, payload.score, json.dumps(payload.metadata), ts),
        )
    return {"ok": True, "id": score_id, "public_code": identity["public_code"], "score": payload.score}


@app.get("/api/rankings")
def rankings(
    request: Request,
    app_id: str = Query(...),
    activity_id: str = Query(...),
    limit: int = Query(10, ge=1, le=100),
) -> list[dict[str, Any]]:
    require_ranking_viewer(request)
    app_key = normalize_app_id(app_id)
    activity_key = re.sub(r"[^a-z0-9_.:-]+", "-", activity_id.lower()).strip("-")[:128]
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT i.public_code, s.score, s.created_at
            FROM scores s
            JOIN student_identities i ON i.id = s.identity_id
            WHERE s.app_id = ? AND s.activity_id = ? AND i.active = 1
            ORDER BY s.score DESC, s.created_at ASC
            LIMIT ?
            """,
            (app_key, activity_key, limit),
        ).fetchall()
    return [{"public_code": r["public_code"], "score": r["score"], "ts": r["created_at"]} for r in rows]


@app.get("/api/teacher/stats.csv", response_class=PlainTextResponse)
def teacher_stats_csv(request: Request, group_id: str | None = None) -> str:
    require_teacher(request)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["group_code", "public_code", "app_id", "activity_id", "attempts", "best_score", "last_score_at"])
    params: list[Any] = []
    where = "WHERE i.active = 1"
    if group_id:
        where += " AND i.group_id = ?"
        params.append(group_id)
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT g.name AS group_code, i.public_code, s.app_id, s.activity_id,
                   COUNT(s.id) AS attempts, MAX(s.score) AS best_score, MAX(s.created_at) AS last_score_at
            FROM student_identities i
            JOIN groups g ON g.id = i.group_id
            LEFT JOIN scores s ON s.identity_id = i.id
            {where}
            GROUP BY g.name, i.public_code, s.app_id, s.activity_id
            ORDER BY g.name, i.public_code, s.app_id, s.activity_id
            """,
            params,
        ).fetchall()
    for row in rows:
        writer.writerow(
            [
                row["group_code"],
                row["public_code"],
                row["app_id"] or "",
                row["activity_id"] or "",
                row["attempts"],
                row["best_score"] if row["best_score"] is not None else "",
                row["last_score_at"] or "",
            ]
        )
    return out.getvalue()


@app.get("/api/groups/{group_id}/cards", response_class=HTMLResponse)
def printable_cards(group_id: str, request: Request) -> str:
    require_teacher(request)
    with get_conn() as conn:
        group = conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
        rows = conn.execute(
            """
            SELECT id, public_code FROM student_identities
            WHERE group_id = ? AND active = 1
            ORDER BY public_code
            """,
            (group_id,),
        ).fetchall()
    if not group:
        raise HTTPException(status_code=404, detail="group not found")
    cards = "\n".join(
        f"<article><h2>EduTicTac</h2><p>Codi</p><strong>{row['public_code']}</strong>"
        "<p>PIN</p><em>Consulta la targeta original o regenera'l</em>"
        "<small>Utilitza aquest codi en les activitats EduTicTac.</small></article>"
        for row in rows
    )
    return f"""<!doctype html>
<html lang="ca">
<meta charset="utf-8">
<title>Targetes EduTicTac {group['name']}</title>
<style>
body{{font-family:Arial,sans-serif;margin:16px;color:#111}}
main{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}}
article{{border:1px dashed #555;padding:10px;min-height:130px;break-inside:avoid}}
h2{{font-size:18px;margin:0 0 8px}}p{{margin:6px 0 2px}}strong{{font-size:28px}}em{{display:block;font-style:normal;color:#555}}small{{display:block;margin-top:10px}}
@media print{{body{{margin:8mm}}}}
</style>
<main>{cards}</main>
</html>"""


@app.get("/api/groups/{group_id}/csv", response_class=PlainTextResponse)
def export_codes_csv(group_id: str, request: Request) -> str:
    """Export only public codes. PIN export is intentionally unavailable later."""
    require_teacher(request)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["codi", "grup"])
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT i.public_code, g.name FROM student_identities i
            JOIN groups g ON g.id = i.group_id
            WHERE i.group_id = ? AND i.active = 1
            ORDER BY i.public_code
            """,
            (group_id,),
        ).fetchall()
    for row in rows:
        writer.writerow([row["public_code"], row["name"]])
    return out.getvalue()


@app.post("/api/apps/{app_id}/roster")
def app_roster(app_id: str, payload: AppRosterIn, request: Request) -> dict[str, Any]:
    require_teacher(request)
    app_key = normalize_app_id(app_id)
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, public_code FROM student_identities
            WHERE group_id = ? AND active = 1
            ORDER BY public_code
            """,
            (payload.group_id,),
        ).fetchall()
    identities = [
        {
            "identity_id": row["id"],
            "public_code": row["public_code"],
            "app_user": f"{app_key}-{row['public_code'].lower()}",
        }
        for row in rows
    ]
    return {"app_id": app_key, "group_id": payload.group_id, "identities": identities}
