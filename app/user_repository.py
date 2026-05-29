"""User authentication and management persistence helpers."""

import logging
import os

import bcrypt
from sqlalchemy import text
from app.security import is_production

log = logging.getLogger(__name__)


def seed_default_admin(engine):
    try:
        with engine.connect() as conn:
            count = conn.execute(text("SELECT COUNT(*) FROM users")).scalar()
            if count == 0:
                default_user = os.getenv("DASH_USER", "admin").strip()
                default_pass = os.getenv("DASH_PASS", "admin123")
                if is_production() and (
                    not os.getenv("DASH_USER")
                    or not os.getenv("DASH_PASS")
                    or default_pass.strip().lower() in {"admin", "admin123", "password", "changeme"}
                    or len(default_pass) < 12
                ):
                    raise RuntimeError("DASH_USER and a strong DASH_PASS are required for production admin seeding")
                hashed = bcrypt.hashpw(default_pass.encode(), bcrypt.gensalt()).decode()
                conn.execute(
                    text("INSERT INTO users (username, password, role) VALUES (:u, :p, 'admin')"),
                    {"u": default_user, "p": hashed},
                )
                conn.commit()
                log.info("Default admin user '%s' created", default_user)
    except Exception as exc:
        log.error("Seed admin error: %s", exc)


def authenticate_user(engine, username, password):
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT id, username, password, role FROM users WHERE username = :u"),
                {"u": username},
            ).fetchone()
            if row and bcrypt.checkpw(password.encode(), row[2].encode()):
                return {"id": row[0], "username": row[1], "role": row[3]}
    except Exception as exc:
        log.error("Auth error: %s", exc)
    return None


def create_user(engine, username, password, role="user"):
    try:
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        with engine.connect() as conn:
            conn.execute(
                text("INSERT INTO users (username, password, role) VALUES (:u, :p, :r)"),
                {"u": username, "p": hashed, "r": role},
            )
            conn.commit()
        log.info("User created: %s", username)
        return True
    except Exception as exc:
        log.error("Create user error: %s", exc)
        return False


def get_all_users(engine):
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT id, username, role, created_at FROM users ORDER BY id")).fetchall()
        return [{"id": row[0], "username": row[1], "role": row[2], "created_at": str(row[3])} for row in rows]


def delete_user(engine, user_id, actor_id=None):
    if actor_id is not None and int(actor_id) == int(user_id):
        return False, "Cannot delete your own account"
    try:
        with engine.connect() as conn:
            row = conn.execute(text("SELECT role FROM users WHERE id = :id"), {"id": user_id}).fetchone()
            if not row:
                return False, "User not found"
            if row[0] == "admin":
                admin_count = conn.execute(text("SELECT COUNT(*) FROM users WHERE role = 'admin'")).scalar()
                if admin_count <= 1:
                    return False, "Cannot delete the last administrator"
            conn.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
            conn.commit()
        return True, None
    except Exception as exc:
        log.error("Delete user error: %s", exc)
        return False, str(exc)


def update_user_role(engine, user_id, role):
    try:
        with engine.connect() as conn:
            row = conn.execute(text("SELECT role FROM users WHERE id = :id"), {"id": user_id}).fetchone()
            if not row:
                return False, "User not found"
            if row[0] == "admin" and role == "user":
                admin_count = conn.execute(text("SELECT COUNT(*) FROM users WHERE role = 'admin'")).scalar()
                if admin_count <= 1:
                    return False, "Cannot demote the last administrator"
            conn.execute(
                text("UPDATE users SET role = :r WHERE id = :id"),
                {"r": role, "id": user_id},
            )
            conn.commit()
        return True, None
    except Exception as exc:
        log.error("Update user role error: %s", exc)
        return False, str(exc)
