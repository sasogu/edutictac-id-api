import importlib
import sys
from http.cookies import SimpleCookie
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi import Response
from fastapi.datastructures import Headers

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def load_app(tmp_path, monkeypatch):
    monkeypatch.setenv("EDUTICTAC_ID_DB", str(tmp_path / "id.db"))
    monkeypatch.setenv("EDUTICTAC_ID_SECRET", "test-secret")
    monkeypatch.setenv("EDUTICTAC_ID_TEACHER_TOKEN", "teacher-token")
    monkeypatch.setenv("EDUTICTAC_ID_COOKIE_SECURE", "0")
    monkeypatch.setenv("EDUTICTAC_ID_PIN_HASH_ITERATIONS", "1000")
    import main

    importlib.reload(main)
    return main


def request(headers=None, cookies=None, host="127.0.0.1"):
    return SimpleNamespace(
        headers=Headers(headers or {}),
        cookies=cookies or {},
        client=SimpleNamespace(host=host),
    )


def teacher_request():
    return request(headers={"Authorization": "Bearer teacher-token"})


def cookie_from_response(response, name):
    jar = SimpleCookie()
    for key, value in response.raw_headers:
        if key.lower() == b"set-cookie":
            jar.load(value.decode())
    return jar[name].value


def raises_status(status_code, func, *args, **kwargs):
    with pytest.raises(HTTPException) as exc:
        func(*args, **kwargs)
    assert exc.value.status_code == status_code


def test_generates_unique_codes_and_hashes_pin(tmp_path, monkeypatch):
    main = load_app(tmp_path, monkeypatch)
    body = main.create_batch(main.BatchIn(count=30, pin_length=4), teacher_request())
    assert body["group"]["group_code"].startswith("G")
    codes = [item["public_code"] for item in body["identities"]]
    assert len(codes) == len(set(codes))
    assert all(len(code) == 3 for code in codes)
    assert all(not any(ch in code for ch in "0O1IL") for code in codes)
    assert all(len(item["pin"]) == 4 for item in body["identities"])

    with main.get_conn() as conn:
        rows = conn.execute("SELECT pin_hash FROM student_identities").fetchall()
    pins = [item["pin"] for item in body["identities"]]
    assert rows
    assert all("pbkdf2_sha256$" in row["pin_hash"] for row in rows)
    assert all(row["pin_hash"] not in pins for row in rows)


def test_student_login_score_ranking_and_logout(tmp_path, monkeypatch):
    main = load_app(tmp_path, monkeypatch)
    created = main.create_batch(main.BatchIn(count=1), teacher_request())
    group_id = created["group"]["id"]
    identity = created["identities"][0]

    raises_status(
        401,
        main.student_login,
        main.StudentAuthIn(public_code=identity["public_code"], pin="9999"),
        request(),
        Response(),
    )

    response = Response()
    ok = main.student_login(
        main.StudentAuthIn(public_code=identity["public_code"], pin=identity["pin"]),
        request(),
        response,
    )
    assert ok["identity"]["public_code"] == identity["public_code"]
    session_cookie = cookie_from_response(response, main.SESSION_COOKIE)
    student_request = request(cookies={main.SESSION_COOKIE: session_cookie})

    assert main.me(student_request)["identity"]["public_code"] == identity["public_code"]
    score = main.add_score(
        main.ScoreIn(app_id="edumusic", activity_id="sol-mi", score=980),
        student_request,
    )
    assert score["score"] == 980

    raises_status(401, main.rankings, request(), app_id="edumusic", activity_id="sol-mi", limit=10)
    ranking = main.rankings(student_request, app_id="edumusic", activity_id="sol-mi", limit=10)
    assert ranking[0]["public_code"] == identity["public_code"]
    assert set(ranking[0]) == {"public_code", "score", "ts"}

    stats = main.teacher_stats_csv(teacher_request(), group_id=group_id)
    assert "group_code,public_code,app_id,activity_id,attempts,best_score,last_score_at" in stats
    assert identity["public_code"] in stats
    assert "edumusic" in stats
    assert "980" in stats

    assert main.logout(student_request, Response()) == {"ok": True}
    raises_status(401, main.me, student_request)


def test_teacher_summary_counts_groups(tmp_path, monkeypatch):
    main = load_app(tmp_path, monkeypatch)
    first = main.create_batch(main.BatchIn(count=2), teacher_request())
    second = main.create_batch(main.BatchIn(count=1), teacher_request())

    summary = main.teacher_summary(teacher_request())

    assert summary["total"] == 3
    assert summary["active"] == 3
    assert summary["inactive"] == 0
    assert [group["total"] for group in summary["groups"]] == [1, 2]
    assert {group["id"] for group in summary["groups"]} == {first["group"]["id"], second["group"]["id"]}


def test_teacher_lists_identities_for_pin_regeneration(tmp_path, monkeypatch):
    main = load_app(tmp_path, monkeypatch)
    created = main.create_batch(main.BatchIn(count=2), teacher_request())

    listed = main.teacher_identities(teacher_request(), limit=200)

    assert {item["public_code"] for item in listed["identities"]} == {
        item["public_code"] for item in created["identities"]
    }
    assert {item["id"] for item in listed["identities"]} == {item["id"] for item in created["identities"]}
    assert all("pin" not in item for item in listed["identities"])


def test_teacher_finds_identity_by_public_code(tmp_path, monkeypatch):
    main = load_app(tmp_path, monkeypatch)
    created = main.create_batch(main.BatchIn(count=1), teacher_request())
    identity = created["identities"][0]

    found = main.teacher_identity_by_code(identity["public_code"].lower(), teacher_request())

    assert found["identity"]["id"] == identity["id"]
    assert found["identity"]["public_code"] == identity["public_code"]
    assert "pin" not in found["identity"]


def test_teacher_activity_assignments_scope_scores(tmp_path, monkeypatch):
    main = load_app(tmp_path, monkeypatch)
    created = main.create_batch(main.BatchIn(count=1), teacher_request())
    group_id = created["group"]["id"]
    identity = created["identities"][0]

    assignment = main.create_activity_assignment(
        main.ActivityAssignmentIn(
            group_id=group_id,
            app_id="EduHoot",
            activity_id="Taula-2",
            title="Taula del 2",
        ),
        teacher_request(),
    )["assignment"]

    assert assignment["app_id"] == "eduhoot"
    assert assignment["activity_id"] == "taula-2"
    assert assignment["group_id"] == group_id
    assert assignment["created_by_teacher_id"] == "teacher-token"

    listed = main.teacher_activity_assignments(teacher_request(), group_id=group_id, limit=100)
    assert [item["id"] for item in listed["assignments"]] == [assignment["id"]]

    response = Response()
    main.student_login(
        main.StudentAuthIn(public_code=identity["public_code"], pin=identity["pin"]),
        request(),
        response,
    )
    session_cookie = cookie_from_response(response, main.SESSION_COOKIE)
    student_request = request(cookies={main.SESSION_COOKIE: session_cookie})

    score = main.add_score(
        main.ScoreIn(
            app_id="eduhoot",
            activity_id="taula-2",
            assignment_id=assignment["id"],
            score=7,
        ),
        student_request,
    )
    assert score["assignment_id"] == assignment["id"]

    with main.get_conn() as conn:
        stored = conn.execute("SELECT assignment_id FROM scores WHERE id = ?", (score["id"],)).fetchone()
    assert stored["assignment_id"] == assignment["id"]


def test_score_rejects_assignment_for_other_group_or_activity(tmp_path, monkeypatch):
    main = load_app(tmp_path, monkeypatch)
    first = main.create_batch(main.BatchIn(count=1), teacher_request())
    second = main.create_batch(main.BatchIn(count=1), teacher_request())
    identity = first["identities"][0]

    assignment = main.create_activity_assignment(
        main.ActivityAssignmentIn(
            group_id=second["group"]["id"],
            app_id="eduhoot",
            activity_id="quiz-a",
        ),
        teacher_request(),
    )["assignment"]

    response = Response()
    main.student_login(
        main.StudentAuthIn(public_code=identity["public_code"], pin=identity["pin"]),
        request(),
        response,
    )
    session_cookie = cookie_from_response(response, main.SESSION_COOKIE)
    student_request = request(cookies={main.SESSION_COOKIE: session_cookie})

    raises_status(
        403,
        main.add_score,
        main.ScoreIn(
            app_id="eduhoot",
            activity_id="quiz-a",
            assignment_id=assignment["id"],
            score=4,
        ),
        student_request,
    )
    raises_status(
        400,
        main.add_score,
        main.ScoreIn(
            app_id="eduhoot",
            activity_id="quiz-b",
            assignment_id=assignment["id"],
            score=4,
        ),
        student_request,
    )


def test_regenerate_pin_revokes_old_sessions(tmp_path, monkeypatch):
    main = load_app(tmp_path, monkeypatch)
    created = main.create_batch(main.BatchIn(count=1), teacher_request())
    group_id = created["group"]["id"]
    identity = created["identities"][0]

    response = Response()
    main.student_login(
        main.StudentAuthIn(public_code=identity["public_code"], pin=identity["pin"]),
        request(),
        response,
    )
    session_cookie = cookie_from_response(response, main.SESSION_COOKIE)
    student_request = request(cookies={main.SESSION_COOKIE: session_cookie})
    assert main.me(student_request)["identity"]["public_code"] == identity["public_code"]

    rotated = main.regenerate_pin(identity["id"], teacher_request(), pin_length=4)
    new_pin = rotated["pin"]
    assert new_pin != identity["pin"]
    raises_status(401, main.me, student_request)

    raises_status(
        401,
        main.student_login,
        main.StudentAuthIn(public_code=identity["public_code"], pin=identity["pin"]),
        request(),
        Response(),
    )
    assert main.student_login(
        main.StudentAuthIn(public_code=identity["public_code"], pin=new_pin),
        request(),
        Response(),
    )["identity"]["public_code"] == identity["public_code"]


def test_revoke_and_app_roster(tmp_path, monkeypatch):
    main = load_app(tmp_path, monkeypatch)
    created = main.create_batch(main.BatchIn(count=2), teacher_request())
    group_id = created["group"]["id"]
    identity = created["identities"][0]

    roster = main.app_roster(
        "EduHoot",
        main.AppRosterIn(group_id=group_id),
        teacher_request(),
    )
    assert roster["app_id"] == "eduhoot"
    assert roster["group_id"] == group_id
    assert roster["identities"][0]["app_user"].startswith("eduhoot-")
    assert "public_code" in roster["identities"][0]
    assert "pin" not in str(roster).lower()

    assert main.revoke_identity(identity["id"], teacher_request()) == {"ok": True}
    raises_status(
        401,
        main.student_login,
        main.StudentAuthIn(public_code=identity["public_code"], pin=identity["pin"]),
        request(),
        Response(),
    )
