---
title: NetSentinel AI Development Skill
description: ML-driven network anomaly detection and auto-remediation system with Discord ChatOps
tags: python, ml, network-automation, flask, discord, snmp, netmiko, scikit-learn
---

# NetSentinel AI Development Skill

**NetSentinel AI** is a network monitoring and automated remediation system that combines traditional network rules with Machine Learning (Isolation Forest) to detect interface anomalies, send alerts to Discord, and trigger automatic or manual port fixes.

## Project Context

- **Technology Stack:** Python 3.10+, Flask, SQLAlchemy, Scikit-learn, Discord.py, Netmiko, PySNMP
- **Network Environment:** GNS3-simulated Cisco IOS routers (or live SNMP devices)
- **Database:** MySQL/SQLite with SQLAlchemy ORM
- **Key Features:**
  - Hybrid rules + ML anomaly detection
  - Automatic 24-hour model retraining
  - Flask web dashboard with role-based access (Admin/User)
  - Interactive Discord bot with action buttons
  - Port remediation via SSH/Telnet (Netmiko)
  - Real-time SocketIO dashboard updates
  - Comprehensive test suite (pytest)

## Core Components

### Data Collection & Validation (`app/collector.py`, `app/snmp_helper.py`)
- SNMP walks on network devices to collect interface metrics
- Simulator mode for demo/testing without physical devices
- Rule-based filtering and labeling of interfaces
- Baseline traffic collection for ML model training

### Machine Learning & Prediction (`app/ai_features.py`, `app/predictor.py`)
- Feature engineering: reliability, network_load, rxload, input_errors, tx/rx deltas, error rates
- Isolation Forest model for anomaly detection
- Severity scoring and correlation logic
- Automatic retraining on a configurable interval (default 24h)

### Web Dashboard (`web/dashboard.py`, `web/templates/`, `web/static/`)
- Flask + SocketIO for real-time UI updates
- Dark-mode responsive design
- Login with role-based authorization
- Admin-only settings and user management pages
- Port status grid, traffic trends, logs, model status

### Discord Bot (`app/bot.py`)
- Real-time anomaly alerts with formatted embeds
- Interactive buttons: Approve Fix, Check Status, Rate Limit, Remove Limit, Ignore
- Admin-only command execution
- ChatOps for network operations

### Database Layer (`app/db.py`, `app/user_repository.py`)
- SQLAlchemy schema with metrics, alerts, users, audit logs
- User authentication and role management (Admin vs User)
- CSRF protection for mutating endpoints
- Secure `.env` secret handling

### Remediation & Vendor Adapters (`app/vendor_adapters.py`)
- Command generation for port fixes, rate limits, and removals
- Built-in Cisco IOS support (bounce, shutdown, rate limiting)
- Extensible for additional vendors

### Configuration (`config/config.yaml`, `config/devices.yaml`, `.env`)
- Threshold tuning for anomaly rules
- Device inventory with SNMP/SSH credentials
- Model hyperparameters and feature selection
- Discord token and database URL

## Development Workflows

### Adding New Network Rules
1. Edit `app/collector_rules.py` to define skip, link, label, or topology rules
2. Update `app/collector.py` to apply new rules during collection
3. Add test cases in `tests/test_collector.py`

### Tuning ML Model
1. Adjust thresholds and contamination in `config/config.yaml`
2. Run `python train_model.py` to retrain on collected metrics
3. Test predictions on a sample dataset before deployment
4. Use dashboard Settings → AI Model → Retrain Model for production retraining

### Adding Dashboard Pages
1. Create route in `web/dashboard.py` with `@app.route()` and role guards
2. Add HTML template to `web/templates/`
3. Add CSS styling to `web/static/theme.css`
4. Update navigation sidebar in `web/templates/sidebar.html`

### Extending Remediation Commands
1. Register a new vendor adapter in `app/vendor_adapters.py`
2. Implement fix/limit/removelimit for the target OS
3. Test with Netmiko mock or real device in staging
4. Update `config/devices.yaml` to use the new `device_type`

### Adding Discord Bot Commands
1. Add handler function in `app/bot.py` with `@bot.command()` decorator
2. Implement admin checks and command logic
3. Add help text and button interactions as needed
4. Test in a test Discord channel before deploying

## Testing & Quality

- **Unit Tests:** `pytest tests/` validates DB security, SNMP parsing, prediction logic
- **Linting:** `ruff check .` for code quality
- **Formatting:** `black . && black --check .` for style consistency
- **CI:** GitHub Actions runs pytest on every push/PR

## Configuration Reference

### Isolation Forest Hyperparameters (`config/config.yaml`)
```yaml
model:
  contamination: 0.05          # Expected % of anomalies in dataset
  n_estimators: 200             # Number of isolation trees
  random_state: 42              # Reproducibility seed
  feature_window: 20            # Number of recent metrics per feature
  train_validation_fraction: 0.2 # Split for validation
  retrain_interval_hours: 24    # Auto-retrain schedule
```

### Feature Selection (`config/config.yaml`)
Default features: `reliability`, `network_load`, `rxload`, `input_errors`, `tx_delta`, `rx_delta`, `error_rate`, `uptime_pct`, `tx_baseline_delta`, `rx_baseline_delta`

Add/remove features to tune model sensitivity:
- **High sensitivity:** Add more delta/rate features
- **Low sensitivity:** Keep only stable metrics (load, reliability, error_rate)

### Device Inventory (`config/devices.yaml`)
```yaml
devices:
  - name: R1
    host: 10.10.100.1
    device_type: cisco_ios_telnet
    snmp_community: public
    location: Core
    zone: A
    role: core
    upstream_device: R1  # For topology tracking
    interfaces:
      GigabitEthernet0/0:
        role: uplink       # Custom role for filtering
```

Supported device_type: `cisco_ios`, `cisco_ios_telnet`, `cisco_nxos` (via Netmiko)

## Common Development Tasks

### Debug Anomaly Detection
1. Check collector output: `python main.py` (verbose logs to console/file)
2. Query database: `SELECT * FROM metrics WHERE device='R1' ORDER BY collected_at DESC LIMIT 10`
3. Run predictor standalone: `from app.predictor import predict; predict(device_id, latest_metrics)`
4. Verify model exists: Check `models/anomaly_model_v2.pkl` timestamp

### Investigate SNMP Issues
1. Test SNMP connectivity: `python -c "from app.snmp_helper import snmp_walk; snmp_walk('192.168.1.1', 'public')"`
2. Check OID mappings in `app/snmp_helper.py` (IF-MIB + Cisco private OIDs)
3. Verify device SNMP config matches auth method (SNMPv2c vs v3) in `.env`

### Reset Dashboard & Database
1. Stop the app: `Ctrl+C`
2. Clear database tables (or backup): `mysql -u root -p -D network_ai_v2 -e "TRUNCATE TABLE metrics; TRUNCATE TABLE alerts;"`
3. Clear trained model: `rm models/anomaly_model_v2.pkl*`
4. Restart: `python main.py`

### Test Remediation Locally
1. Set `DEVICE_USERNAME`, `DEVICE_PASSWORD`, `DEVICE_SECRET` in `.env`
2. Update `config/devices.yaml` with test device IP
3. Call remediation endpoint: `curl -X POST http://localhost:5000/api/fix/R1/GigabitEthernet0%2F0`
4. Check Netmiko logs for SSH/Telnet session output

## API Endpoints Summary

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/health` | - | DB connection check |
| POST | `/api/login` | - | JSON login |
| GET | `/api/status` | User | Latest interface status |
| GET | `/api/anomalies` | User | Anomaly feed |
| GET | `/api/analytics` | User | Summary metrics |
| GET | `/api/model/status` | User | Model metadata & retrain status |
| POST | `/api/model/retrain` | Admin | Queue model retraining |
| POST | `/api/fix/<device>/<intf>` | Admin | Port bounce fix |
| POST | `/api/ratelimit/<device>/<intf>` | Admin | Rate-limit port |
| GET\|POST | `/api/settings/config` | Admin | Read/write `config/config.yaml` |
| GET\|POST | `/api/users` | Admin | List/create users |

All mutating endpoints require CSRF token in header or form field.

## Troubleshooting

**Model not retraining:**
- Check `models/` directory permissions
- Verify `config/config.yaml` has writable `path` value
- Review logs for training errors: `tail netsentinel.log`

**Discord bot not sending alerts:**
- Verify `DISCORD_TOKEN` and `DISCORD_CHANNEL_ID` in `.env`
- Check bot permissions in Discord server (Message Send, Embed Links)
- Review console logs for bot errors

**SNMP collection timeout:**
- Increase timeout in `app/snmp_helper.py` if devices are slow
- Verify network connectivity: `ping <device_ip>`
- Check SNMP community string matches device config

**Port fixes not working:**
- Verify SSH/Telnet credentials in `.env`
- Test Netmiko connectivity: `python -c "from netmiko import ConnectHandler; ..."`
- Check device supports remediation commands (Cisco IOS required)

## Git Workflow

- Create feature branches: `git checkout -b feature/anomaly-tuning`
- Write tests before committing (TDD practice)
- Run linting & tests: `ruff check . && black . && pytest`
- Create pull request for review
- CI automatically runs pytest on PR

## File Structure Reference

```
.
├── main.py                    # App entry point (DB init, collector, web, bot)
├── train_model.py             # Model training script
├── requirements.txt           # Runtime deps
├── requirements-dev.txt       # Dev/test deps
├── config/
│   ├── config.yaml            # Model & collector config (git ignored)
│   ├── config.example.yaml    # Template for config.yaml
│   ├── devices.yaml           # Device inventory (git ignored)
│   ├── devices.example.yaml   # Template for devices.yaml
│   ├── .env.example           # Template for .env
│   └── .env (not committed)   # Env variables (git ignored)
├── scripts/                   # Utility & debugging scripts
│   ├── check_arp_r4.py
│   ├── check_network.py
│   ├── check_r2_from_r3.py
│   ├── check_r2_status.py
│   ├── check_r4.py
│   ├── grab_configs.py
│   ├── grab_r2_r4.py
│   └── test_r2_freeze.py
├── logs/                      # Runtime log files (git ignored)
│   ├── netsentinel.log
│   └── audit.log
├── app/
│   ├── ai_features.py         # Feature engineering
│   ├── bot.py                 # Discord bot
│   ├── collector.py           # SNMP/simulator data collection
│   ├── collector_rules.py     # Collection rule logic
│   ├── db.py                  # Database schema & queries
│   ├── model_registry.py      # Model metadata helpers
│   ├── predictor.py           # Rules + ML prediction
│   ├── prediction_intel.py    # Severity & correlation logic
│   ├── simulator.py           # Mock data generator
│   ├── snmp_helper.py         # SNMP walk utilities
│   ├── syslog_server.py       # Syslog listener
│   ├── user_repository.py     # User auth & management
│   ├── vendor_adapters.py     # Remediation commands
│   └── runtime.py             # App runtime lifecycle
├── web/
│   ├── dashboard.py           # Flask routes & SocketIO
│   ├── api_serializers.py     # JSON response helpers
│   ├── remediation_helpers.py # Port fix command logic
│   ├── settings_helpers.py    # Settings page helpers
│   ├── templates/
│   │   ├── base.html
│   │   ├── index.html         # Status/anomaly feed
│   │   ├── traffic.html       # Traffic trends
│   │   ├── login.html
│   │   ├── settings.html      # Admin settings
│   │   ├── terminal.html      # Syslog terminal
│   │   ├── backups.html       # Device backups
│   │   ├── logs.html          # Audit logs
│   │   ├── topology.html      # Network topology
│   │   └── sidebar.html       # Navigation menu
│   └── static/
│       ├── css/
│       │   ├── dashboard.css  # Dashboard styles
│       │   ├── ai-workspace.css
│       │   └── sidebar.css
│       ├── theme.css
│       └── theme.js
├── tests/                     # Unit & integration tests
│   ├── conftest.py            # Pytest fixtures
│   ├── test_*.py              # Individual test files
│   └── __pycache__/
├── models/                    # Trained model artifacts (git ignored)
│   └── anomaly_model_v2.pkl
├── backups/                   # Device config backups
├── scratch/                   # Experimental scripts
├── memory/                    # Session/documentation storage
├── .github/workflows/ci.yml   # GitHub Actions CI
├── pytest.ini                 # Test configuration
├── pyproject.toml             # Black & Ruff config
├── .gitignore                 # Git ignore rules
└── SKILL.md                   # This development guide
```

---

**Last Updated:** 2026-05-29  
**Project:** NetSentinel AI v2  
**Maintained by:** Project Network Team
