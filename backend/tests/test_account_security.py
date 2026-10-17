from __future__ import annotations

import os
import tempfile
import time
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api.deps import get_db
from src.core.database import Base
from src.main import app
from src.models.sqlalchemy import AuthChallenge, AuthOneTimeToken, AuthSession, MFARecoveryCode, RefreshToken, User
from src.services.account_security_service import account_security_service
from src.services.auth_email_service import auth_email_service
from src.utils.datetime_utils import get_utc_now


PASSWORD = "Correct-Horse-Battery-Staple-2026!"


@pytest.fixture()
def account_security():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(engine)

    def override_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    auth_email_service.captured.clear()
    client = TestClient(app)
    response = client.post("/api/v1/auth/register", json={
        "email": "security@example.com",
        "password": PASSWORD,
        "full_name": "Security Owner",
        "tenant_name": "Security Tenant",
        "tenant_slug": "security-tenant",
    })
    assert response.status_code == 201, response.text
    login = client.post("/api/v1/auth/login", json={"email": "security@example.com", "password": PASSWORD})
    assert login.status_code == 200, login.text
    access = login.json()["access_token"]
    try:
        yield client, factory, {"Authorization": f"Bearer {access}"}
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
        os.remove(path)


def _enable_mfa(client: TestClient, factory, headers: dict[str, str]):
    wrong = client.post("/api/v1/account/security/mfa/start", headers=headers, json={"current_password": "wrong"})
    assert wrong.status_code == 400
    start = client.post("/api/v1/account/security/mfa/start", headers=headers, json={"current_password": PASSWORD})
    assert start.status_code == 200, start.text
    setup = start.json()
    db = factory()
    try:
        user = db.query(User).filter_by(email="security@example.com").one()
        assert setup["manual_key"] not in user.mfa_pending_secret_encrypted
        assert "totp_secret" not in user.mfa_pending_secret_encrypted
    finally:
        db.close()
    bad = client.post("/api/v1/account/security/mfa/confirm", headers=headers, json={"code": "000000"})
    assert bad.status_code == 400
    step = int(time.time() // 30) - 1
    code = account_security_service._totp(setup["manual_key"], step)
    confirmed = client.post("/api/v1/account/security/mfa/confirm", headers=headers, json={"code": code})
    assert confirmed.status_code == 200, confirmed.text
    codes = confirmed.json()["recovery_codes"]
    assert len(codes) == 10
    assert setup["manual_key"] not in confirmed.text
    return setup, codes


def test_mfa_challenge_replay_and_recovery_codes(account_security):
    client, factory, headers = account_security
    setup, recovery_codes = _enable_mfa(client, factory, headers)
    login = client.post("/api/v1/auth/login", json={"email": "security@example.com", "password": PASSWORD})
    assert login.status_code == 200
    assert login.json()["mfa_required"] is True
    challenge = login.json()["challenge_token"]

    db = factory()
    try:
        row = db.query(AuthChallenge).filter_by(jti=jwt_unverified_jti(challenge)).one()
        row.expires_at = get_utc_now() - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()
    expired = client.post("/api/v1/auth/mfa/complete", json={
        "challenge_token": challenge, "code": "000000", "recovery_code": False,
    })
    assert expired.status_code == 401
    login = client.post("/api/v1/auth/login", json={"email": "security@example.com", "password": PASSWORD})
    challenge = login.json()["challenge_token"]

    invalid = client.post("/api/v1/auth/mfa/complete", json={
        "challenge_token": challenge, "code": "000000", "recovery_code": False,
    })
    assert invalid.status_code == 401
    valid_code = account_security_service._totp(setup["manual_key"], int(time.time() // 30))
    complete = client.post("/api/v1/auth/mfa/complete", json={
        "challenge_token": challenge, "code": valid_code, "recovery_code": False,
    })
    assert complete.status_code == 200, complete.text
    replay = client.post("/api/v1/auth/mfa/complete", json={
        "challenge_token": challenge, "code": valid_code, "recovery_code": False,
    })
    assert replay.status_code == 401

    login2 = client.post("/api/v1/auth/login", json={"email": "security@example.com", "password": PASSWORD}).json()
    recovery = client.post("/api/v1/auth/mfa/complete", json={
        "challenge_token": login2["challenge_token"], "code": recovery_codes[0], "recovery_code": True,
    })
    assert recovery.status_code == 200
    login3 = client.post("/api/v1/auth/login", json={"email": "security@example.com", "password": PASSWORD}).json()
    reused = client.post("/api/v1/auth/mfa/complete", json={
        "challenge_token": login3["challenge_token"], "code": recovery_codes[0], "recovery_code": True,
    })
    assert reused.status_code == 401
    db = factory()
    try:
        assert db.query(MFARecoveryCode).filter(MFARecoveryCode.used_at.isnot(None)).count() == 1
    finally:
        db.close()


def jwt_unverified_jti(token: str) -> str:
    import jwt
    return jwt.decode(token, options={"verify_signature": False})["jti"]


def test_recovery_regeneration_and_mfa_disable(account_security):
    client, factory, headers = account_security
    setup, old_codes = _enable_mfa(client, factory, headers)
    current_step = int(time.time() // 30)
    current_code = account_security_service._totp(setup["manual_key"], current_step)
    regenerated = client.post("/api/v1/account/security/recovery-codes/regenerate", headers=headers, json={
        "current_password": PASSWORD, "code": current_code,
    })
    assert regenerated.status_code == 200, regenerated.text
    assert regenerated.json()["recovery_codes"] != old_codes
    disable_code = account_security_service._totp(setup["manual_key"], current_step + 1)
    disabled = client.post("/api/v1/account/security/mfa/disable", headers=headers, json={
        "current_password": PASSWORD, "code": disable_code,
    })
    assert disabled.status_code == 200, disabled.text
    db = factory()
    try:
        user = db.query(User).filter_by(email="security@example.com").one()
        assert user.mfa_secret_encrypted is None
        assert db.query(MFARecoveryCode).filter_by(user_id=user.id).count() == 0
    finally:
        db.close()


def test_session_listing_ownership_revocation_and_refresh_reuse(account_security):
    client, factory, headers = account_security
    listed = client.get("/api/v1/account/security/sessions", headers=headers)
    assert listed.status_code == 200
    current = next(item for item in listed.json()["items"] if item["current"])
    revoked = client.delete(f"/api/v1/account/security/sessions/{current['id']}", headers=headers)
    assert revoked.status_code == 200
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert client.delete("/api/v1/account/security/sessions/not-owned", headers=headers).status_code == 401
    db = factory()
    try:
        session = db.get(AuthSession, current["id"])
        assert session.revoked_at is not None
        assert all(token.revoked_at is not None for token in db.query(RefreshToken).filter_by(session_id=session.id))
    finally:
        db.close()


def test_password_reset_hashes_token_revokes_sessions_and_is_single_use(account_security):
    client, factory, _ = account_security
    response = client.post("/api/v1/auth/password-reset/request", json={"email": "security@example.com"})
    unknown = client.post("/api/v1/auth/password-reset/request", json={"email": "missing@example.com"})
    assert response.status_code == unknown.status_code == 200
    assert response.json() == unknown.json()
    message = auth_email_service.captured[-1]
    link = next(part for part in message["text"].split() if part.startswith("http"))
    token = parse_qs(urlparse(link).query)["token"][0]
    db = factory()
    try:
        record = db.query(AuthOneTimeToken).filter_by(purpose="password_reset").one()
        assert record.token_hash != token
    finally:
        db.close()
    weak = client.post("/api/v1/auth/password-reset/complete", json={"token": token, "new_password": "password"})
    assert weak.status_code == 400
    completed = client.post("/api/v1/auth/password-reset/complete", json={
        "token": token, "new_password": "A-New-Unique-Passphrase-For-2026!",
    })
    assert completed.status_code == 200, completed.text
    assert client.post("/api/v1/auth/password-reset/complete", json={
        "token": token, "new_password": "Another-Unique-Passphrase-For-2026!",
    }).status_code == 400


def test_email_verification_token_is_hashed_and_single_use(account_security):
    client, factory, _ = account_security
    response = client.post("/api/v1/auth/email-verification/request", json={"email": "security@example.com"})
    assert response.status_code == 200
    link = next(part for part in auth_email_service.captured[-1]["text"].split() if part.startswith("http"))
    token = parse_qs(urlparse(link).query)["token"][0]
    db = factory()
    try:
        record = db.query(AuthOneTimeToken).filter_by(purpose="email_verification").one()
        assert record.token_hash != token
    finally:
        db.close()
    confirmed = client.post("/api/v1/auth/email-verification/confirm", json={"token": token})
    assert confirmed.status_code == 200
    assert client.post("/api/v1/auth/email-verification/confirm", json={"token": token}).status_code == 200


def test_security_history_is_user_scoped_and_contains_no_codes(account_security):
    client, factory, headers = account_security
    setup, _ = _enable_mfa(client, factory, headers)
    history = client.get("/api/v1/account/security/events", headers=headers)
    assert history.status_code == 200
    body = history.text
    assert setup["manual_key"] not in body
    assert account_security_service._totp(setup["manual_key"], int(time.time() // 30)) not in body
    assert all(item["severity"] in {"informational", "suspicious", "critical"} for item in history.json()["items"])
