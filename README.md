# NetSentinel AI

NetSentinel AI is a lab-oriented network monitoring project for GNS3 or similar test environments. It collects interface data with SNMP, applies simple rule-based checks, uses a Scikit-learn Isolation Forest model for anomaly experiments, and provides a Flask dashboard for viewing device status, traffic, logs, settings, backups, and basic remediation actions.

This project is not intended to be presented as a production-ready NMS. It is a learning and lab automation project that demonstrates how SNMP collection, ML-assisted anomaly detection, web dashboards, syslog review, and controlled network remediation can be connected in one Python application.

## Current Scope

The project is useful for:

- Monitoring simulated or lab network devices.
- Testing SNMP-based interface collection.
- Experimenting with rule-based and ML-based anomaly detection.
- Triggering controlled remediation commands from the web dashboard in a lab.
- Reviewing interface status, traffic, syslog entries, and backups through a web dashboard.
- Practicing NetDevOps-style workflows with tests and GitHub Actions.

The project is not yet ready for:

- Direct production network use without review and hardening.
- Internet-facing deployment without a reverse proxy, TLS, monitoring, backups, and operational controls.
- Fully trusted automated remediation on critical devices.
- Vendor-complete support across real enterprise networks.

## System Architecture

<img width="1650" height="953" alt="architecture-ai-network2" src="https://github.com/user-attachments/assets/f9da1e5d-66ef-4943-9fae-1f21d15a7f5a" />

## Main Features

- **SNMP collection:** Polls interface status, reliability, load, errors, and IP mapping from configured devices.
- **Rule-based detection:** Flags simple anomalies such as down interfaces, high load, low reliability, and input errors.
- **Experimental ML detection:** Uses Isolation Forest on collected history to help identify unusual interface behavior.
- **Dashboard:** Flask web UI for status, traffic, topology, logs, backups, settings, users, and model status.
- **Lab remediation:** Can run vendor-specific CLI commands such as port bounce or rate-limit actions through Netmiko.
- **Syslog view:** Receives and displays device syslog messages with simple heuristic explanations.
- **Config backup:** Can collect running configuration from configured devices in supported lab setups.
- **Basic security controls:** Login, roles, CSRF checks, masked secrets, and related tests are included.

## Tech Stack

- Python 3.10+
- Flask and Flask-SocketIO
- SQLAlchemy with MySQL or SQLite-compatible development setups
- PySNMP
- Netmiko
- Scikit-learn
- Pytest
- Ruff and Black

## Project Layout

```text
.
├── main.py                         # Starts the main runtime loops
├── train_model.py                  # Trains the Isolation Forest model
├── requirements.txt                # Runtime dependencies
├── requirements-dev.txt            # Development/test dependencies
├── pyproject.toml                  # Ruff and Black config
├── pytest.ini
├── app/
│   ├── ai_features.py              # Training/runtime feature engineering
│   ├── collector.py                # SNMP/simulator collection
│   ├── collector_rules.py          # Rule helpers
│   ├── db.py                       # Database schema and queries
│   ├── model_registry.py           # Model metadata helpers
│   ├── predictor.py                # Rules + ML prediction
│   ├── prediction_intel.py         # Severity and correlation helpers
│   ├── security.py                 # Runtime security helpers
│   ├── simulator.py                # Mock topology data source
│   ├── snmp_helper.py              # SNMP walks and interface parsing
│   ├── syslog_server.py            # UDP syslog receiver
│   ├── user_repository.py          # User persistence helpers
│   └── vendor_adapters.py          # Remediation command adapters
├── web/
│   ├── dashboard.py                # Flask routes and Socket.IO events
│   ├── settings_helpers.py         # Settings/env validation helpers
│   ├── static/                     # CSS, theme, i18n JS
│   └── templates/                  # Dashboard pages
├── config/
│   ├── config.example.yaml         # Copy to config.yaml
│   └── devices.example.yaml        # Copy to devices.yaml
├── tests/                          # Automated tests
└── models/                         # Local trained model output, not committed
```

## Requirements

- Python 3.10+
- MySQL 8.0+ for the main database flow
- Network devices reachable from the machine running the app
- SNMP enabled on devices, or simulator mode for demo use
- Optional SSH/Telnet access for remediation and config backup

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

Create local runtime files:

```bash
cp .env.example .env
cp config/config.example.yaml config/config.yaml
cp config/devices.example.yaml config/devices.yaml
```

Create the MySQL database:

```sql
CREATE DATABASE network_ai_v2 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Edit `.env`:

```env
DB_URL=mysql+mysqlconnector://root:YOUR_PASSWORD@localhost/network_ai_v2

DEVICE_USERNAME=admin
DEVICE_PASSWORD=admin123
DEVICE_SECRET=admin123

SNMP_COMMUNITY=public
FLASK_SECRET=change-this-long-random-value-at-least-32-characters

# Optional dashboard seed credentials for first run
DASH_USER=admin
DASH_PASS=admin123
```

For lab use, defaults such as `admin123` and `public` may be acceptable. Do not use these values for any real or shared environment.

## Configuration

### `config/devices.yaml`

This file defines the devices in the lab topology. Minimum required keys are `name`, `host`, and `device_type`.

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

Common Netmiko device types:

- `cisco_ios`
- `cisco_ios_telnet`
- `cisco_nxos`
- `arista_eos`
- `juniper_junos`
- `mikrotik_routeros`

### `config/config.yaml`

Important sections:

```yaml
collector:
  interval: 60

model:
  path: "models/anomaly_model_v2.pkl"
  threshold_load: 20
  threshold_reliability: 200
  threshold_errors: 10
  contamination: 0.05
  retrain_interval_hours: 24

data_retention:
  enabled: true
  days: 30

snmp:
  oids: {}

simulator:
  enabled: false
  interfaces_per_device: 4
  anomaly_rate: 0.15

link_types:
  rules:
    - prefix: "192.168.189"
      type: Management
    - prefix: "10.10."
      type: Core
  default: Other

anomaly:
  skip_types:
    - Serial
    - Vlan
    - NVI
    - Loopback
    - Tunnel
    - Null
```

`snmp.oids` can be used to override OIDs for a specific topology or vendor. If left empty, the app uses the default IF-MIB flow plus Cisco-oriented load/reliability OIDs.

## Device Setup Examples

### SNMPv2c for lab

```text
conf t
snmp-server community public ro
end
wr
```

### SNMPv3 example

```text
conf t
no snmp-server community public ro
snmp-server group V3Group v3 priv read v3view
snmp-server view v3view iso included
snmp-server user netsentinel V3Group v3 auth sha admin12345 priv aes 128 admin12345
end
wr
```

### Cisco IOS Telnet for lab remediation

```text
conf t
enable secret admin123
username admin privilege 15 secret admin123
line vty 0 4
 login local
 transport input telnet
end
wr
```

Use SSH instead of Telnet if possible, especially outside an isolated lab.

### Syslog to NetSentinel

```text
conf t
logging host <NETSENTINEL_HOST_IP>
logging trap informational
service timestamps log datetime msec
end
wr
```

The built-in syslog receiver tries UDP 514 first and falls back to UDP 5140 if 514 cannot be bound.

## Run

```bash
python main.py
```

Dashboard:

```text
http://localhost:5000
```

`main.py` starts:

- database initialization
- collector + predictor loop
- Flask dashboard
- scheduled model retrain loop
- syslog receiver

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

The collector will use simulated interface data instead of live SNMP devices.

## Training The Model

Collect some baseline data first:

```bash
python main.py
```

Then train in another terminal:

```bash
python train_model.py
```

The model is saved to the configured `model.path`, usually `models/anomaly_model_v2.pkl`. Model output is local runtime data and should not be committed.

The dashboard can also queue retraining from:

```text
Settings -> AI Model -> Retrain Model
```

## Dashboard Pages

- `/login` - login page
- `/` - interface status and anomaly feed
- `/traffic` - recent traffic view
- `/topology` - lab topology map
- `/logs` - syslog and audit log views
- `/backups` - configuration backup tools
- `/settings` - admin settings, devices, environment, users, and model controls

## Topology Notes

Devices are configured in `config/devices.yaml`, but the current topology map still has some lab-specific links in `web/dashboard.py` under `backbone_links`.

When using a new topology, update:

1. `config/devices.yaml` for device names, hosts, roles, zones, and SNMP settings.
2. `config/config.yaml` for link type prefixes and anomaly skip rules.
3. `web/dashboard.py` if the displayed topology links differ from the current lab.

The names in `backbone_links` must match the device `name` values in `config/devices.yaml`.

## API Overview

Public/auth:

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/api/health` | Database health check |
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
| GET | `/api/topology` | Topology nodes and links |
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
| GET/POST | `/api/settings/env` | Read/write allowed `.env` keys; secrets are not returned |
| GET/POST | `/api/users` | List/create users |
| DELETE | `/api/users/<id>` | Delete user with guard rails |
| PUT | `/api/users/<id>/role` | Change role with guard rails |

Mutating endpoints require an `X-CSRF-Token` header or `csrf_token` form field.

## Tests And Quality

Run tests:

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

Current tests cover:

- Flask auth/admin/user endpoint behavior
- CSRF checks for mutating routes
- `.env` save/load secret masking
- user management guard rails
- dashboard XSS regression checks
- SNMP parsing and collector mock-device integration
- predictor rules and ML behavior
- syslog and terminal helper behavior
- remediation command generation

## CI

GitHub Actions is configured in `.github/workflows/ci.yml`.

It installs dependencies and runs:

```bash
python -m pytest
```

## Operational Notes

For lab use:

- Keep `.env`, `config/config.yaml`, `config/devices.yaml`, logs, backups, scratch files, and `models/*.pkl` out of Git.
- Restart the app after changing topology/config files.
- Test remediation commands on non-critical devices first.
- Prefer SSH over Telnet when available.
- Use SNMPv3 instead of SNMPv2c when moving beyond an isolated lab.

Before considering any real production use, the project would need additional review around deployment, TLS, secrets management, authorization policy, backup/restore, observability, failure handling, model validation, and safe remediation controls.

## License

This project is for educational and lab use.
