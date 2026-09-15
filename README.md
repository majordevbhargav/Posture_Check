# Endpoint Posture Check

A network endpoint posture-assessment project that combines Windows endpoint checks, Cisco ISE session tracking, posture ingestion, and an operator dashboard.

## Purpose

The project explores how endpoint compliance information can be collected, assessed, stored, reviewed, and connected to a network-access-control workflow.

## Architecture

```text
Windows Endpoint
      ↓
Posture Agent
      ↓
Posture Application
      ├── Assessment Storage
      ├── Dashboard
      └── Session State
              ↓
          Cisco ISE
              ↓
     Access / Remediation Workflow
```

## Main Components

- `posture_agent.ps1` collects endpoint posture information.
- `posture_app.py` handles posture ingestion and service logic.
- `posture_ui.py` provides the operator dashboard.
- `ise_session_watcher.py` tracks ISE session state.
- `Save-PostureCredential.ps1` supports credential setup.
- Queue and state files support pending-device workflows.

## Focus Areas

- Endpoint compliance
- Cisco ISE
- PowerShell automation
- Python services
- REST APIs
- Network access control
- Session tracking
- Security remediation workflows

## Development Direction

The project can evolve toward a database-backed architecture, stronger authentication and authorization, better audit logging, richer endpoint health signals, pxGrid integration, automated testing, and a decoupled frontend.

## Security

Never commit real ISE credentials, endpoint credentials, tokens, or private infrastructure details. Use environment variables, secure credential stores, or a dedicated secrets manager.

## Author

**Dev Bhargav**

- GitHub: https://github.com/majordevbhargav
- LinkedIn: https://www.linkedin.com/in/devbhargav100
