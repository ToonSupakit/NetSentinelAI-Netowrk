# NetSentinel AI

NetSentinel AI is a network anomaly monitoring app for lab and small network environments. It collects interface data through SNMP, classifies anomalies with rule checks plus an Isolation Forest model, sends Discord alerts, and provides a Flask dashboard for status, traffic, settings, users, retraining, and remediation actions.

## System Architecture

<img width="2048" height="1117" alt="diagram-AI" src="https://github.com/user-attachments/assets/9e515fe0-75c4-49a0-8e59-3d6ee3a0042e" />


## Current Capabilities

- Collect interface status, protocol, reliability, TX/RX load, input errors, link type, zone, location, and topology role.
- Support SNMPv2c and SNMPv3 through `app/snmp_helper.py`.
- Support demo/mock traffic through the simulator in `app/simulator.py`.
- Detect anomalies with rules, AI, or both: `rules`, `ai`, `rules+ai`, `device_unreachable`, and `healthy`.
- Enrich runtime prediction with recent deltas, error rate, uptime percentage, and baseline deltas.
- Correlate downstream failures with likely upstream/root events and suppress duplicate notifications.
- Send Discord alerts with admin-only buttons: approve fix, check status, rate limit, remove limit, ignore.
- Provide Flask pages for dashboard, traffic, login, and admin settings.
- Provide admin APIs for config, device config, environment variables, user management, model status, and retraining.
- Generate vendor-specific remediation commands for Cisco, Arista, MikroTik, Juniper, and local adapter plugins.
- Store data in MySQL through SQLAlchemy.
- Run automated pytest coverage through GitHub Actions.

## Project Layout

```text
.
├── main.py                         # Starts DB init, collector/predictor loop, dashboard, retrain loop, Discord bot
├── train_model.py                  # Trains Isolation Forest and writes model metadata
├── requirements.txt                # Runtime dependencies
├── requirements-dev.txt            # Test/lint/format dependencies
├── pyproject.toml                  # ruff/black config
├── pytest.ini
├── .github/workflows/ci.yml        # GitHub Actions pytest workflow
├── app/
│   ├── ai_features.py              # Shared training/runtime feature engineering
│   ├── bot.py                      # Discord bot and remediation buttons
│   ├── collector.py                # SNMP/simulator collection and rule labels
│   ├── collector_rules.py          # Pure collector skip/link/label/topology rules
│   ├── db.py                       # Database schema, queries, auth, user management
│   ├── model_registry.py           # Model metadata read/write helpers
│   ├── predictor.py                # Rules + AI prediction, severity, correlation
│   ├── prediction_intel.py         # Cause, severity, and correlation helpers
│   ├── simulator.py                # Mock topology data source
│   ├── snmp_helper.py              # SNMP walks and interface parsing
│   ├── user_repository.py          # User auth and user management persistence
│   └── vendor_adapters.py          # Remediation command adapters
├── web/
│   ├── dashboard.py                # Flask + SocketIO routes
│   ├── static/                     # CSS and theme JS
│   └── templates/                  # Dashboard, traffic, login, settings, sidebar
├── config/
│   ├── config.example.yaml         # Copy to config.yaml
│   └── devices.example.yaml        # Copy to devices.yaml
├── tests/                          # Unit and integration tests
└── models/                         # Trained model output, not committed
```

## Requirements

- Python 3.10+
- MySQL 8.0+
- Network devices with SNMP enabled, or simulator mode for local/demo testing
- Optional: Discord bot token and channel ID
- Optional for device remediation: SSH/Telnet access supported by Netmiko

## Setup

Create and activate a virtual environment:

```bash
python -m venv .venv

# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r requirements-dev.txt
```

Create runtime files:

```bash
cp .env.example .env
cp config/config.example.yaml config/config.yaml
cp config/devices.example.yaml config/devices.yaml
```

Create the database:

```sql
CREATE DATABASE network_ai_v2 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Edit `.env`:

```env
DB_URL=mysql+mysqlconnector://root:YOUR_PASSWORD@localhost/network_ai_v2

DISCORD_TOKEN=your_discord_bot_token
DISCORD_CHANNEL_ID=your_channel_id

DEVICE_USERNAME=admin
DEVICE_PASSWORD=admin123
DEVICE_SECRET=admin123

SNMP_COMMUNITY=public
FLASK_SECRET=change-this-long-random-value

# Optional dashboard seed credentials for first run
DASH_USER=admin
DASH_PASS=admin123
```

The first DB initialization seeds an admin account if the `users` table is empty. If `DASH_USER` and `DASH_PASS` are not set, it falls back to `admin` / `admin123`.

## Configuration

### `config/config.yaml`

Important sections:

```yaml
model:
  path: "models/anomaly_model_v2.pkl"
  threshold_load: 20
  threshold_reliability: 200
  threshold_errors: 10
  contamination: 0.05
  train_validation_fraction: 0.2
  random_state: 42
  retrain_interval_hours: 24
  n_estimators: 200
  feature_window: 20
  features:
    - reliability
    - network_load
    - rxload
    - input_errors
    - tx_delta
    - rx_delta
    - error_rate
    - uptime_pct
    - tx_baseline_delta
    - rx_baseline_delta

collector:
  interval: 60

data_retention:
  enabled: true
  days: 30

snmp:
  oids: {}

simulator:
  enabled: false
  interfaces_per_device: 4
  anomaly_rate: 0.15
  period_seconds: 60
```

`snmp.oids` can override default OIDs for a topology/vendor. Leave it empty to use IF-MIB plus Cisco private load/reliability OIDs.

### `config/devices.yaml`

Minimum keys are `name`, `host`, and `device_type`. Credentials and SNMP community can be omitted to use `.env` defaults.

```yaml
devices:
  - name: R1
    host: 10.10.100.1
    device_type: cisco_ios_telnet
    snmp_community: public
    location: Core
    zone: A
    role: core
    interfaces:
      GigabitEthernet0/0:
        role: uplink

  - name: R2
    host: 192.168.189.10
    device_type: cisco_ios_telnet
    location: Branch
    zone: B
    role: access
    upstream_device: R1
```

Supported Netmiko examples include:

- `cisco_ios`
- `cisco_ios_telnet`
- `cisco_nxos`
- `arista_eos`
- `juniper_junos`
- `mikrotik_routeros`

## Device SNMP Setup

SNMPv2c example:

```text
conf t
snmp-server community public ro
exit
wr
```

SNMPv3 example:

```text
conf t
no snmp-server community public ro
snmp-server group V3Group v3 priv read v3view
snmp-server view v3view iso included
snmp-server user netsentinel V3Group v3 auth sha admin12345 priv aes 128 admin12345
exit
wr
```

For remediation actions such as fix/rate limit, configure SSH or Telnet credentials compatible with Netmiko. Cisco IOS Telnet example:

```text
conf t
enable secret admin123
username admin privilege 15 secret admin123
line vty 0 4
 login local
 transport input telnet
exit
wr
```

## Run

```bash
python main.py
```

Dashboard: `http://localhost:5000`

`main.py` starts:

- database initialization and migrations
- collector + predictor loop
- Flask dashboard
- scheduled model retrain loop
- Discord bot if `DISCORD_TOKEN` is set

## Demo Mode Without Devices

Enable simulator mode in `config/config.yaml`:

```yaml
simulator:
  enabled: true
  interfaces_per_device: 4
  anomaly_rate: 0.15
```

Then run:

```bash
python main.py
```

The collector will use simulated interfaces instead of live SNMP devices.

## Train Or Retrain The Model

Collect baseline traffic first, then train:

```bash
python main.py
# let the collector run for a while, then in another terminal:
python train_model.py
```

Training writes the model to `model.path` and metadata next to it. The Dashboard can show model status and queue retraining from:

```text
Settings -> AI Model -> Retrain Model
```

The app also runs scheduled retraining every `model.retrain_interval_hours`.

## Dashboard

Pages:

- `/login` - login page
- `/` - interface status and anomaly feed
- `/traffic` - traffic view
- `/settings` - admin-only settings, model, devices, environment, and users

Security controls currently covered by tests:

- login-required API guards
- admin-only API guards
- CSRF checks for mutating routes
- admin action rate limiting
- masked secret reads for environment settings
- user management guard rails
- dashboard DOM rendering XSS regressions

## API Overview

Public/auth:

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/api/health` | DB health check |
| GET | `/login` | Login page |
| POST | `/api/login` | Login JSON endpoint |
| GET | `/logout` | Clear session |

User-authenticated:

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/api/status` | Latest interface status |
| GET | `/api/anomalies` | Latest anomaly history |
| GET | `/api/analytics` | Summary metrics |
| GET | `/api/traffic` | Recent traffic trend |
| GET | `/api/model/status` | Model metadata and retrain job status |

Admin-only:

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | `/api/model/retrain` | Queue model retrain |
| POST | `/api/fix/<device>/<intf>` | Queue port bounce/no shutdown style fix |
| POST | `/api/ratelimit/<device>/<intf>` | Queue rate limit |
| POST | `/api/removelimit/<device>/<intf>` | Queue rate-limit removal |
| GET/POST | `/api/settings/config` | Read/write `config/config.yaml` |
| GET/POST | `/api/settings/devices` | Read/write `config/devices.yaml` |
| GET/POST | `/api/settings/env` | Read/write safe `.env` keys; secrets are not returned |
| GET/POST | `/api/users` | List/create users |
| DELETE | `/api/users/<id>` | Delete user with guard rails |
| PUT | `/api/users/<id>/role` | Change role with guard rails |

Mutating endpoints require an `X-CSRF-Token` header or `csrf_token` form field.

## Discord Bot

Commands:

| Command | Description |
| --- | --- |
| `!status` | Show current interface status |
| `!history` | Show latest 10 anomalies |
| `!analytics` | Show anomaly, uptime, fix rate, and traffic summary |
| `!help` | Show commands |

Alert buttons:

- Approve Fix
- Check Status
- Rate Limit
- Remove Limit
- Ignore

Buttons are admin-only.

## Remediation Command Adapters

Command generation lives in `app/vendor_adapters.py`.

Built-in adapters:

- Cisco and Arista: `fix`, `limit`, `removelimit`
- MikroTik: `fix`, `limit`, `removelimit`
- Juniper: `fix`

Unknown vendors return no commands. You can register local adapters at runtime with `register_adapter(marker, adapter)`.

## Tests And Quality

Run the full test suite:

```bash
python -m pytest
```

Run lint and formatting:

```bash
ruff check .
black .
```

Check formatting only:

```bash
black --check .
```

Current test coverage includes:

- Flask auth/admin/user endpoint integration
- user management guard rails
- `.env` save/load secret safety
- dashboard XSS regression checks
- SNMP parsing and collector mock-device integration
- predictor rules + AI behavior
- remediation command generation

## CI

GitHub Actions is configured in `.github/workflows/ci.yml`.

It runs on every `push` and `pull_request`, installs dependencies, then runs:

```bash
python -m pytest
```

## Deployment Checklist

- Use Python 3.10+.
- Install `requirements.txt`.
- Set a strong `FLASK_SECRET`.
- Set `APP_ENV=production` and `SESSION_COOKIE_SECURE=true` when serving over HTTPS.
- Keep `.env`, `config/config.yaml`, `config/devices.yaml`, logs, and `models/*.pkl` out of git.
- Run behind a process manager such as systemd, Docker, or a supervisor.
- Put Flask behind a reverse proxy such as Nginx or Caddy for TLS.
- Back up MySQL and the trained model file before upgrades.
- Run `python -m pytest` before deploy.

## License

This project is for educational purposes.
