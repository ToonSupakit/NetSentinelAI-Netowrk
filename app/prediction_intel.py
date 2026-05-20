"""Cause, severity, and correlation helpers for predictions."""


def analyze_cause(data, config):
    causes = []
    suggestions = []

    if data.get("is_device_down"):
        causes.append("Device Unreachable")
        suggestions.append(
            "Verify device power status and network connectivity"
        )
        return causes, suggestions

    if data["is_admin_down"]:
        causes.append("Port administratively shutdown")
        suggestions.append(f"Run 'no shutdown' on {data['intf']}")
    elif data["status_num"] == 1 and data["protocol_num"] == 0:
        causes.append("Interface status is Up, but protocol status is Down (Link down)")
        suggestions.append("Check cable connection and remote device status")
    elif data["status_num"] == 0:
        causes.append("Interface physical status is Down")
        suggestions.append("Verify physical cabling and transceiver connectivity")

    model_cfg = config["model"]
    if data["network_load"] > model_cfg["threshold_load"]:
        pct = round(data["network_load"] / 255 * 100, 1)
        causes.append(f"High outgoing traffic ({pct}%)")
        suggestions.append("Inspect traffic patterns for possible network loops or broadcast storms")

    if data["rxload"] > model_cfg["threshold_load"]:
        pct = round(data["rxload"] / 255 * 100, 1)
        causes.append(f"High incoming traffic ({pct}%)")
        suggestions.append("Check for potential DDoS attacks or excessive downloads")

    if data["reliability"] < model_cfg["threshold_reliability"]:
        pct = round(data["reliability"] / 255 * 100, 1)
        causes.append(f"Low interface reliability ({pct}%)")
        suggestions.append("Inspect cable quality and check for electromagnetic interference")

    if data["input_errors"] > model_cfg["threshold_errors"]:
        causes.append(f"High input errors count: {data['input_errors']}")
        suggestions.append("Check for duplex mismatch or damaged cabling")

    if not causes:
        causes.append("AI detected anomalous behavior (Unusual Pattern Detection)")
        suggestions.append(
            "Review traffic charts for unusual deviation from historic baseline"
        )

    return causes, suggestions


def classify_severity(data, confidence, detection_source, config):
    role = str(data.get("device_role") or "").lower()
    intf_role = str(data.get("interface_role") or "").lower()
    link_type = str(data.get("link_type") or "").lower()
    load_pct = max(data.get("network_load", 0), data.get("rxload", 0)) / 255
    reliability = data.get("reliability", 255)
    error_rate = data.get("error_rate", data.get("input_errors", 0))
    down = data.get("is_device_down") or data.get("status_num") == 0 or data.get("protocol_num") == 0
    core_path = role == "core" or intf_role in ("uplink", "core") or link_type == "core"

    if data.get("is_device_down") or (down and core_path):
        return "critical"
    if (
        down
        or load_pct >= 0.85
        or reliability < 120
        or error_rate > config["model"]["threshold_errors"] * 5
        or (detection_source == "rules+ai" and confidence >= 0.95)
    ):
        return "high"
    if load_pct >= 0.5 or reliability < 180 or error_rate > config["model"]["threshold_errors"]:
        return "medium"
    if detection_source in ("rules+ai", "ai"):
        return "medium"
    return "low"


def is_down_event(anomaly):
    return bool(anomaly.get("is_device_down") or anomaly.get("status_num") == 0 or anomaly.get("protocol_num") == 0)


def is_root_event(anomaly):
    if not is_down_event(anomaly):
        return False
    role = str(anomaly.get("device_role") or "").lower()
    intf_role = str(anomaly.get("interface_role") or "").lower()
    link_type = str(anomaly.get("link_type") or "").lower()
    return (
        anomaly.get("is_device_down")
        or role == "core"
        or intf_role in ("uplink", "core")
        or link_type == "core"
        or anomaly.get("intf") == "ALL"
    )


def same_area(root, child):
    root_zone = root.get("zone")
    child_zone = child.get("zone")
    root_location = root.get("location")
    child_location = child.get("location")
    return (root_zone and child_zone and str(root_zone).lower() == str(child_zone).lower()) or (
        root_location and child_location and str(root_location).lower() == str(child_location).lower()
    )


def apply_correlation(anomalies):
    roots = [anomaly for anomaly in anomalies if is_root_event(anomaly)]
    if not roots:
        return anomalies

    for anomaly in anomalies:
        anomaly["notification_suppressed"] = False
        anomaly["correlated_with"] = None
        if anomaly in roots or not is_down_event(anomaly):
            continue
        upstream = {str(value) for value in anomaly.get("upstream_devices", [])}
        role = str(anomaly.get("device_role") or "").lower()
        for root in roots:
            if root.get("device") == anomaly.get("device"):
                continue
            explicit_parent = root.get("device") in upstream
            inferred_parent = (
                str(root.get("device_role") or "").lower() == "core"
                and role in ("access", "edge")
                and same_area(root, anomaly)
            )
            if explicit_parent or inferred_parent:
                anomaly["notification_suppressed"] = True
                anomaly["correlated_with"] = f"{root.get('device')}:{root.get('intf')}"
                break
    return anomalies
