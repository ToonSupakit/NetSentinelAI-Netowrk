---
title: NetSentinel AI Development Skill
description: ML-driven lab network anomaly detection and dashboard remediation system
tags: python, ml, network-automation, flask, snmp, netmiko, scikit-learn
---

# NetSentinel AI Development Skill

NetSentinel AI is a lab network monitoring and remediation project. It combines SNMP collection, rule-based checks, an experimental Isolation Forest model, a Flask dashboard, syslog review, config backup, and controlled Netmiko-based remediation.

## Project Context

- **Technology Stack:** Python 3.10+, Flask, SQLAlchemy, Scikit-learn, Netmiko, PySNMP
- **Network Environment:** GNS3/lab network devices
- **Database:** MySQL/SQLite-compatible development flows through SQLAlchemy
- **Key Features:**
  - Rules + ML anomaly detection
  - Scheduled model retraining
  - Flask dashboard with role-based access
  - Web-based port remediation through SSH/Telnet
  - Real-time Socket.IO dashboard updates
  - Syslog receiver and log analysis helpers
  - Pytest test suite

## Core Components

### Data Collection

- `app/collector.py`
- `app/snmp_helper.py`
- `app/collector_rules.py`

Collects SNMP interface metrics, supports simulator mode, labels records for rules/model use, and tracks upstream device context.

### Prediction

- `app/ai_features.py`
- `app/predictor.py`
- `app/prediction_intel.py`
- `train_model.py`

Builds model features, trains Isolation Forest, applies rule/model predictions, and derives severity/correlation hints.

### Web Dashboard

- `web/dashboard.py`
- `web/templates/`
- `web/static/`
- `web/settings_helpers.py`

Provides dashboard pages, settings, users, topology, traffic, logs, backups, retraining, and remediation APIs.

### Remediation

- `app/vendor_adapters.py`

Generates vendor-specific commands for fix, rate limit, and rate-limit removal. Keep actions controlled and test on lab devices first.

### Runtime

- `main.py`
- `app/runtime.py`
- `app/syslog_server.py`

Starts the collector, predictor, dashboard, retrain loop, and syslog server.

## Development Workflows

### Adding Network Rules

1. Edit `app/collector_rules.py`.
2. Wire behavior through `app/collector.py` if needed.
3. Add focused tests in `tests/`.

### Tuning The Model

1. Adjust thresholds/model settings in `config/config.yaml`.
2. Collect baseline lab traffic.
3. Run `python train_model.py`.
4. Validate behavior from the dashboard and tests.

### Adding Dashboard Pages

1. Add a route in `web/dashboard.py`.
2. Add or update templates in `web/templates/`.
3. Add CSS/JS in `web/static/` following existing patterns.
4. Add auth/admin guards and tests when routes mutate state.

### Extending Remediation Commands

1. Add or update an adapter in `app/vendor_adapters.py`.
2. Implement `fix`, `limit`, and `removelimit` only where the vendor supports them.
3. Test with mocks and a lab device.
4. Update `config/devices.yaml` with the right `device_type`.

## Testing And Quality

- Run tests: `python -m pytest`
- Compile key modules: `python -m py_compile app\db.py app\collector.py web\dashboard.py`
- Lint: `ruff check .`
- Format: `black .`

## Configuration Reference

- `config/config.yaml`: collector interval, model thresholds, link types, skip rules, simulator settings
- `config/devices.yaml`: device inventory, host, device type, zone, role, SNMP community
- `.env`: database URL, device credentials, SNMP credentials, dashboard secrets

Keep runtime files, real configs, logs, backups, scratch files, and model artifacts out of Git.

## Troubleshooting

**Model not retraining:**

- Check `models/` directory permissions.
- Verify `model.path` in `config/config.yaml`.
- Review `logs/netsentinel.log`.

**SNMP collection timeout:**

- Verify reachability with `ping <device_ip>`.
- Check SNMP community or SNMPv3 credentials.
- Confirm device ACL/firewall rules allow SNMP.

**Port fixes not working:**

- Verify `DEVICE_USERNAME`, `DEVICE_PASSWORD`, and `DEVICE_SECRET`.
- Confirm `device_type` matches Netmiko.
- Test CLI login manually before using dashboard remediation.

## File Structure Reference

```text
.
├── main.py
├── train_model.py
├── app/
│   ├── ai_features.py
│   ├── collector.py
│   ├── collector_rules.py
│   ├── db.py
│   ├── predictor.py
│   ├── security.py
│   ├── snmp_helper.py
│   ├── syslog_server.py
│   └── vendor_adapters.py
├── web/
│   ├── dashboard.py
│   ├── settings_helpers.py
│   ├── static/
│   └── templates/
├── config/
├── tests/
└── models/
```
