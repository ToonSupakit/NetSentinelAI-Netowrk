"""Security helpers shared by runtime modules."""

import os


DEFAULT_FLASK_SECRET = "netsentinel-secret-key-change-me"
WEAK_VALUES = frozenset({"", "admin", "admin123", "password", "changeme", "change-me", DEFAULT_FLASK_SECRET})


def is_production() -> bool:
    return os.getenv("APP_ENV", "").strip().lower() in {"prod", "production"}


def env_value(key: str, default: str | None = None, *, required_in_production: bool = False) -> str | None:
    value = os.getenv(key)
    if value is None or not str(value).strip():
        if is_production() and required_in_production:
            raise RuntimeError(f"{key} is required when APP_ENV=production")
        return default
    return value


def ensure_strong_secret(key: str, value: str | None) -> str:
    if not value or value.strip().lower() in WEAK_VALUES or len(value) < 32:
        raise RuntimeError(f"{key} must be set to a strong random value of at least 32 characters")
    return value


def runtime_secret(key: str, default: str | None = None) -> str | None:
    value = env_value(key, default, required_in_production=True)
    if is_production():
        return ensure_strong_secret(key, value)
    return value


def device_credential(device: dict, key: str, env_key: str, dev_default: str = "admin") -> str | None:
    value = device.get(key) or os.getenv(env_key)
    if is_production():
        if not value or str(value).strip().lower() in WEAK_VALUES:
            name = device.get("name", device.get("host", "device"))
            raise RuntimeError(f"{env_key} for {name} must be configured with a non-default value in production")
        return value
    return value or dev_default
