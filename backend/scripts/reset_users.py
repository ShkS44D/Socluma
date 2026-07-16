"""
Reset users script: Delete all users and recreate admin from .env
"""
import sys
import os

# Add backend directory to Python path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, backend_dir)

from src.core.config import get_settings
from src.core.security import get_password_hash
from src.core.database import SessionLocal, create_tables
from src.models.sqlalchemy import User, Tenant, UserRole
from src.core.logging import logger

settings = get_settings()


def reset_users():
    if not settings.ADMIN_EMAIL or not settings.ADMIN_PASSWORD:
        logger.error("ADMIN_EMAIL and ADMIN_PASSWORD must be set in .env to reset users!")
        sys.exit(1)

    db = SessionLocal()
    try:
        logger.info("Starting user reset...")

        # Ensure tables exist
        if settings.USE_SQLITE:
            create_tables()

        # Delete any existing user with the admin email (from any tenant)
        existing_admin = db.query(User).filter(User.email == settings.ADMIN_EMAIL).first()
        if existing_admin:
            db.delete(existing_admin)
            db.commit()
            logger.info(f"Deleted existing admin user: {existing_admin.id}")

        # Find or create default tenant
        tenant_slug = "default"
        tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
        if not tenant:
            tenant = Tenant(name="Default Tenant", slug=tenant_slug)
            db.add(tenant)
            db.commit()
            db.refresh(tenant)
            logger.info(f"Created default tenant: {tenant.id}")

        # Delete all users in this tenant
        deleted_count = db.query(User).filter(User.tenant_id == tenant.id).delete()
        logger.info(f"Deleted {deleted_count} existing users in tenant")

        # Create admin user
        hashed_password = get_password_hash(settings.ADMIN_PASSWORD)
        admin = User(
            email=settings.ADMIN_EMAIL,
            full_name="Admin User",
            hashed_password=hashed_password,
            tenant_id=tenant.id,
            role=UserRole.ADMIN
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)
        logger.info(f"Recreated admin user: {admin.id} ({admin.email})")
        logger.info("User reset complete!")

    except Exception as e:
        logger.error(f"Failed to reset users: {e}")
        db.rollback()
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    reset_users()
