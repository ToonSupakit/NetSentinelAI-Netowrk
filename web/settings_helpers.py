"""Settings validation and environment-file helpers for the dashboard."""

import os
import re

ENV_KEYS = frozenset(
    {
        "DISCORD_TOKEN",
        "DISCORD_CHANNEL_ID",
        "DEVICE_USERNAME",
        "DEVICE_PASSWORD",
        "DEVICE_SECRET",
        "SNMP_COMMUNITY",
        "SNMP_V3_USER",
        "SNMP_V3_AUTH",
        "SNMP_V3_PRIV",
    }
)
ENV_SECRET_KEYS = frozenset(
    {
        "DISCORD_TOKEN",
        "DEVICE_PASSWORD",
        "DEVICE_SECRET",
        "SNMP_COMMUNITY",
        "SNMP_V3_AUTH",
        "SNMP_V3_PRIV",
    }
)


def env_nonempty(key):
    value = os.getenv(key)
    return bool(value and str(value).strip())


def _valid_int(value, min_value, max_value):
    return type(value) is int and min_value <= value <= max_value


def validate_config_payload(data):
    if not isinstance(data, dict):
        return False, "Configuration must be an object"
    for section in ("collector", "model", "anomaly", "data_retention"):
        if section not in data or not isinstance(data[section], dict):
            return False, f"Missing or invalid section: {section}"
    if not _valid_int(data["collector"].get("interval"), 5, 86400):
        return False, "collector.interval must be between 5 and 86400 seconds"
    model_cfg = data["model"]
    for key in ("threshold_load", "threshold_reliability"):
        if not _valid_int(model_cfg.get(key), 0, 255):
            return False, f"model.{key} must be between 0 and 255"
    if not _valid_int(model_cfg.get("threshold_errors"), 0, 1000000):
        return False, "model.threshold_errors must be between 0 and 1000000"
    if not isinstance(model_cfg.get("path"), str) or not model_cfg["path"].strip():
        return False, "model.path is required"
    if not _valid_int(data["data_retention"].get("days"), 1, 3650):
        return False, "data_retention.days must be between 1 and 3650"
    if not isinstance(data["data_retention"].get("enabled"), bool):
        return False, "data_retention.enabled must be true or false"
    skip_types = data["anomaly"].get("skip_types", [])
    if not isinstance(skip_types, list) or not all((s is None or isinstance(s, str)) for s in skip_types):
        return False, "anomaly.skip_types must be a list of strings"
    link_types = data.get("link_types", {})
    if link_types and not isinstance(link_types, dict):
        return False, "link_types must be an object"
    for rule in link_types.get("rules", []) if isinstance(link_types, dict) else []:
        if (
            not isinstance(rule, dict)
            or not isinstance(rule.get("prefix"), str)
            or not isinstance(rule.get("type"), str)
        ):
            return False, "link_types.rules entries require prefix and type"
    return True, None


def validate_devices_payload(data):
    if not isinstance(data, dict) or not isinstance(data.get("devices"), list):
        return False, "Missing devices list"
    names = set()
    host_re = re.compile(r"^[A-Za-z0-9_.:-]+$")
    for idx, device in enumerate(data["devices"], start=1):
        if not isinstance(device, dict):
            return False, f"Device #{idx} must be an object"
        for key in ("name", "host", "device_type"):
            if not isinstance(device.get(key), str) or not device[key].strip():
                return False, f"Device #{idx} missing {key}"
        if device["name"] in names:
            return False, f'Duplicate device name: {device["name"]}'
        names.add(device["name"])
        if not host_re.match(device["host"]):
            return False, f'Invalid host for {device["name"]}'
        for key in ("username", "password", "secret", "snmp_community", "location", "zone"):
            if key in device and device[key] is not None and not isinstance(device[key], str):
                return False, f'{device["name"]}.{key} must be a string'
    return True, None


def validate_env_payload(data):
    if not isinstance(data, dict):
        return False, "Environment payload must be an object"
    for key, value in data.items():
        if key not in ENV_KEYS:
            return False, f"Unsupported environment key: {key}"
        if value is None:
            continue
        text = str(value)
        if "\n" in text or "\r" in text:
            return False, f"{key} cannot contain newlines"
        if len(text) > 4096:
            return False, f"{key} is too long"
        if key == "DISCORD_CHANNEL_ID" and text.strip() and not text.strip().isdigit():
            return False, "DISCORD_CHANNEL_ID must be numeric"
    return True, None


def update_env_file(path, updates):
    lines = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()

    remaining = dict(updates)
    output = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in line:
            key = line.split("=", 1)[0].strip()
            if key in remaining:
                output.append(f"{key}={remaining.pop(key)}\n")
                continue
        output.append(line)

    if remaining and output and not output[-1].endswith("\n"):
        output[-1] += "\n"
    for key, value in remaining.items():
        output.append(f"{key}={value}\n")

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(output)
