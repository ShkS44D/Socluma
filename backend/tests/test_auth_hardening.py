import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from pathlib import Path
from datetime import timedelta

from alembic import command
from alembic.config import Config as AlembicConfig
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from src.api.deps import get_db
from src.core.config import Settings, get_settings
from src.core.database import Base
from src.core.security import get_password_hash
from src.main import app
from src.models.sqlalchemy import AuditLog, Collector, RefreshToken, Tenant, User, UserRole
from src.utils.datetime_utils import get_utc_now


class AuthHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fd, cls.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        cls.engine = create_engine(
            f"sqlite:///{cls.db_path}",
            connect_args={"check_same_thread": False},
        )
        cls.SessionTesting = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)
        cls.client = TestClient(app)
        cls.settings = get_settings()
        cls.original_max_attempts = cls.settings.MAX_FAILED_LOGIN_ATTEMPTS
        cls.original_lockout_minutes = cls.settings.ACCOUNT_LOCKOUT_MINUTES

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.clear()
        cls.settings.MAX_FAILED_LOGIN_ATTEMPTS = cls.original_max_attempts
        cls.settings.ACCOUNT_LOCKOUT_MINUTES = cls.original_lockout_minutes
        cls.engine.dispose()
        if os.path.exists(cls.db_path):
            os.remove(cls.db_path)

    def setUp(self):
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        self.settings.MAX_FAILED_LOGIN_ATTEMPTS = 2
        self.settings.ACCOUNT_LOCKOUT_MINUTES = 5

        def override_get_db():
            db = self.SessionTesting()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db

    def _register_admin(self, email: str = "admin@example.com", password: str = "Socluma-Test-Passphrase-2026!") -> dict:
        response = self.client.post(
            "/api/v1/auth/register",
            json={
                "email": email,
                "password": password,
                "full_name": "Admin User",
                "tenant_name": "Test Tenant",
                "tenant_slug": "test-tenant",
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def _login(self, email: str = "admin@example.com", password: str = "Socluma-Test-Passphrase-2026!") -> dict:
        response = self.client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def _create_user(self, role: UserRole, email: str) -> str:
        db = self.SessionTesting()
        tenant = db.query(Tenant).filter(Tenant.slug == "test-tenant").first()
        if tenant is None:
            tenant = Tenant(name="Test Tenant", slug="test-tenant")
            db.add(tenant)
            db.flush()
        user = User(
            tenant_id=tenant.id,
            email=email,
            hashed_password=get_password_hash("Socluma-Test-Passphrase-2026!"),
            full_name=f"{role.value.title()} User",
            role=role,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        user_id = user.id
        db.close()
        return user_id

    def test_login_success_issues_refresh_token_and_records_timestamp(self):
        self._register_admin()
        tokens = self._login()

        self.assertIn("access_token", tokens)
        self.assertIn("refresh_token", tokens)
        self.assertEqual(tokens["token_type"], "bearer")

        db = self.SessionTesting()
        user = db.query(User).filter(User.email == "admin@example.com").one()
        refresh_tokens = db.query(RefreshToken).filter(RefreshToken.user_id == user.id).all()
        actions = {row.action for row in db.query(AuditLog).all()}
        db.close()

        self.assertEqual(user.failed_login_attempts, 0)
        self.assertIsNotNone(user.last_login_at)
        self.assertEqual(len(refresh_tokens), 1)
        self.assertNotEqual(refresh_tokens[0].token_hash, tokens["refresh_token"])
        self.assertIn("login", actions)

    def test_login_failure_lockout_and_lockout_expiration(self):
        self._register_admin()

        first_failure = self.client.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "WrongSocluma-Test-Passphrase-2026!"},
        )
        self.assertEqual(first_failure.status_code, 401)

        second_failure = self.client.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "WrongSocluma-Test-Passphrase-2026!"},
        )
        self.assertEqual(second_failure.status_code, 423)

        locked_login = self.client.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "Socluma-Test-Passphrase-2026!"},
        )
        self.assertEqual(locked_login.status_code, 423)

        db = self.SessionTesting()
        user = db.query(User).filter(User.email == "admin@example.com").one()
        user.locked_until = get_utc_now() - timedelta(minutes=1)
        db.commit()
        db.close()

        unlocked_login = self.client.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "Socluma-Test-Passphrase-2026!"},
        )
        self.assertEqual(unlocked_login.status_code, 200, unlocked_login.text)

    def test_refresh_token_rotates_and_reuse_revokes_family(self):
        self._register_admin()
        tokens = self._login()

        refresh_response = self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        )
        self.assertEqual(refresh_response.status_code, 200, refresh_response.text)
        rotated = refresh_response.json()
        self.assertNotEqual(rotated["refresh_token"], tokens["refresh_token"])

        reuse_response = self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        )
        self.assertEqual(reuse_response.status_code, 401)

        family_revoked_response = self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": rotated["refresh_token"]},
        )
        self.assertEqual(family_revoked_response.status_code, 401)

    def test_logout_revokes_current_refresh_token(self):
        self._register_admin()
        tokens = self._login()

        logout_response = self.client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": tokens["refresh_token"]},
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        self.assertEqual(logout_response.status_code, 200, logout_response.text)

        refresh_response = self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        )
        self.assertEqual(refresh_response.status_code, 401)

    def test_logout_all_revokes_all_user_sessions(self):
        self._register_admin()
        first = self._login()
        second = self._login()

        logout_response = self.client.post(
            "/api/v1/auth/logout-all",
            headers={"Authorization": f"Bearer {first['access_token']}"},
        )
        self.assertEqual(logout_response.status_code, 200, logout_response.text)

        for token_pair in (first, second):
            refresh_response = self.client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": token_pair["refresh_token"]},
            )
            self.assertEqual(refresh_response.status_code, 401)

    def test_password_change_invalidates_old_access_and_refresh_tokens(self):
        self._register_admin()
        tokens = self._login()

        change_response = self.client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "Socluma-Test-Passphrase-2026!",
                "new_password": "NewSocluma-Test-Passphrase-2026!",
            },
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        self.assertEqual(change_response.status_code, 200, change_response.text)

        old_access_response = self.client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        self.assertEqual(old_access_response.status_code, 401)

        old_refresh_response = self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        )
        self.assertEqual(old_refresh_response.status_code, 401)

        old_password_response = self.client.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "Socluma-Test-Passphrase-2026!"},
        )
        self.assertEqual(old_password_response.status_code, 401)

        new_password_response = self.client.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "NewSocluma-Test-Passphrase-2026!"},
        )
        self.assertEqual(new_password_response.status_code, 200, new_password_response.text)

    def test_rbac_admin_only_user_management(self):
        self._register_admin()
        self._create_user(UserRole.ANALYST, "analyst@example.com")
        analyst_tokens = self._login("analyst@example.com")

        response = self.client.get(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {analyst_tokens['access_token']}"},
        )
        self.assertEqual(response.status_code, 403)

    def test_event_ingest_requires_authentication(self):
        response = self.client.post(
            "/api/v1/events/ingest",
            json={
                "source": "windows-edr",
                "event_type": "process",
                "raw_event": {"process": "powershell.exe"},
            },
        )
        self.assertEqual(response.status_code, 401)

    def test_collector_lookup_hash_and_ingest_authentication(self):
        self._register_admin()
        tokens = self._login()

        register_response = self.client.post(
            "/api/v1/collectors/register",
            json={
                "name": "Windows Collector",
                "type": "windows",
                "hostname": "host-01",
            },
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        self.assertEqual(register_response.status_code, 201, register_response.text)
        collector_credentials = register_response.json()

        db = self.SessionTesting()
        collector = db.query(Collector).filter(Collector.id == collector_credentials["id"]).one()
        self.assertIsNotNone(collector.token_lookup_hash)
        self.assertNotEqual(collector.token, collector_credentials["token"])
        db.close()

        collector_headers = {"Authorization": f"Bearer {collector_credentials['token']}"}
        heartbeat_response = self.client.post(
            f"/api/v1/collectors/{collector_credentials['id']}/heartbeat",
            headers=collector_headers,
        )
        self.assertEqual(heartbeat_response.status_code, 200, heartbeat_response.text)

        ingest_response = self.client.post(
            "/api/v1/events/ingest",
            json={
                "source": "windows-edr",
                "event_type": "process",
                "raw_event": {"process": "cmd.exe"},
            },
            headers=collector_headers,
        )
        self.assertEqual(ingest_response.status_code, 201, ingest_response.text)

        with patch("src.api.v1.events.broadcast_notification", new_callable=AsyncMock) as broadcast:
            batch_response = self.client.post(
                "/api/v1/events/ingest/batch",
                json={
                    "batch_id": "live-dashboard-batch",
                    "events": [
                        {
                            "source": "windows-edr",
                            "event_type": "process",
                            "raw_event": {"process": "whoami.exe"},
                        }
                    ],
                },
                headers=collector_headers,
            )

        self.assertEqual(batch_response.status_code, 202, batch_response.text)
        self.assertEqual(batch_response.json()["accepted"], 1)
        broadcast.assert_awaited_once()
        notification_args = broadcast.await_args.args
        self.assertEqual(notification_args[1], "new_event")
        self.assertEqual(notification_args[2]["accepted"], 1)

    def test_events_pagination_sorting_and_filtering(self):
        self._register_admin()
        tokens = self._login()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        for severity in ("low", "high", "critical"):
            response = self.client.post(
                "/api/v1/events/ingest",
                json={
                    "source": "windows-edr",
                    "event_type": "process",
                    "raw_event": {"process": f"{severity}.exe"},
                    "severity": severity,
                },
                headers=headers,
            )
            self.assertEqual(response.status_code, 201, response.text)

        page = self.client.get(
            "/api/v1/events?limit=2&offset=1&sort_by=created_at&sort_order=desc",
            headers=headers,
        )
        self.assertEqual(page.status_code, 200, page.text)
        self.assertEqual(len(page.json()), 2)

        filtered = self.client.get("/api/v1/events?severity=high", headers=headers)
        self.assertEqual(filtered.status_code, 200, filtered.text)
        self.assertEqual(len(filtered.json()), 1)
        self.assertEqual(filtered.json()[0]["severity"], "high")

    def test_security_headers_are_present(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])

    def test_production_secret_validation_rejects_weak_secrets(self):
        production_settings = Settings(
            ENVIRONMENT="production",
            SECRET_KEY="short-secret",
            JWT_SECRET_KEY="short-jwt",
            REFRESH_TOKEN_SECRET="short-refresh",
            COLLECTOR_TOKEN_SECRET="short-collector",
            ALLOWED_HOSTS=["socluma.example.com"],
            BACKEND_CORS_ORIGINS=["https://socluma.example.com"],
        )
        with self.assertRaises(RuntimeError):
            production_settings.validate_for_runtime()


class AuthMigrationTests(unittest.TestCase):
    def _alembic_config(self) -> AlembicConfig:
        backend_dir = Path(__file__).resolve().parents[1]
        cfg = AlembicConfig(str(backend_dir / "alembic.ini"))
        cfg.set_main_option("script_location", str(backend_dir / "alembic"))
        return cfg

    def test_sqlite_migration_upgrade_head(self):
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        settings = get_settings()
        original_override = settings.DATABASE_URL_OVERRIDE
        original_use_sqlite = settings.USE_SQLITE
        try:
            settings.USE_SQLITE = True
            settings.DATABASE_URL_OVERRIDE = f"sqlite:///{db_path}"
            command.upgrade(self._alembic_config(), "head")
            migrated_engine = create_engine(f"sqlite:///{db_path}")
            inspector = inspect(migrated_engine)
            self.assertIn("scheduled_purge_at", {column["name"] for column in inspector.get_columns("tenants")})
            self.assertIn("permission_revision", {column["name"] for column in inspector.get_columns("tenants")})
            self.assertIn("organization_api_keys", inspector.get_table_names())
            self.assertIn("sensitive_action_approvals", inspector.get_table_names())
            usage_uniques = {
                tuple(item["column_names"])
                for item in inspector.get_unique_constraints("organization_usage")
            }
            self.assertIn(("tenant_id", "snapshot_date"), usage_uniques)
            migrated_engine.dispose()
        finally:
            settings.DATABASE_URL_OVERRIDE = original_override
            settings.USE_SQLITE = original_use_sqlite
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_sqlite_upgrade_recovers_from_orm_precreated_tables(self):
        """Older local installs may have newer tables from legacy create_all startup."""
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        settings = get_settings()
        original_override = settings.DATABASE_URL_OVERRIDE
        original_use_sqlite = settings.USE_SQLITE
        engine = None
        try:
            settings.USE_SQLITE = True
            settings.DATABASE_URL_OVERRIDE = f"sqlite:///{db_path}"
            command.upgrade(self._alembic_config(), "20260729_1500")
            engine = create_engine(f"sqlite:///{db_path}")
            Base.metadata.create_all(engine)
            engine.dispose()
            engine = None

            command.upgrade(self._alembic_config(), "head")
            engine = create_engine(f"sqlite:///{db_path}")
            inspector = inspect(engine)
            self.assertIn(
                "display_query",
                {column["name"] for column in inspector.get_columns("search_templates")},
            )
            with engine.connect() as connection:
                self.assertEqual(
                    connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one(),
                    "20260801_2000",
                )
        finally:
            if engine is not None:
                engine.dispose()
            settings.DATABASE_URL_OVERRIDE = original_override
            settings.USE_SQLITE = original_use_sqlite
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_postgresql_migration_upgrade_head_when_configured(self):
        postgres_url = os.getenv("TEST_POSTGRES_DATABASE_URL")
        if not postgres_url:
            self.skipTest("TEST_POSTGRES_DATABASE_URL is not configured")

        settings = get_settings()
        original_override = settings.DATABASE_URL_OVERRIDE
        original_use_sqlite = settings.USE_SQLITE
        try:
            settings.USE_SQLITE = False
            settings.DATABASE_URL_OVERRIDE = postgres_url
            command.upgrade(self._alembic_config(), "head")
        finally:
            settings.DATABASE_URL_OVERRIDE = original_override
            settings.USE_SQLITE = original_use_sqlite


if __name__ == "__main__":
    unittest.main()
