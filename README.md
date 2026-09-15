# Endpoint Posture Check

A network endpoint posture assessment project built around Windows endpoint checks, Cisco ISE integration, session tracking, and an operator dashboard.

## Purpose

The project explores how endpoint compliance information can be collected, stored, reviewed, and used as part of a network access control workflow.

## Main components

- `posture_agent.ps1` for endpoint posture collection
- `posture_app.py` for posture ingestion and service logic
- `posture_ui.py` for the dashboard and operator workflow
- `ise_session_watcher.py` for tracking ISE session state
- `Save-PostureCredential.ps1` for credential setup
- Queue and state files for pending and previously observed devices
- Demo material for testing the workflow

## Conceptual workflow

```text
Endpoint
   |
   | posture information
   v
Posture Agent
   |
   v
Posture Application
   |
   +----> Storage / assessment history
   |
   +----> Dashboard / operator workflow
   |
   v
Cisco ISE
   |
   v
Network access / remediation decisions
```

## Key learning areas

- Endpoint compliance
- Cisco ISE
- Windows PowerShell automation
- Python services
- REST APIs
- Network access control
- Session tracking
- Dashboard development
- Security remediation workflows

## Future direction

- Cleaner database-backed architecture
- Decoupled enforcement actions
- Better audit logging
- More endpoint health signals
- Hardware health information
- pxGrid integration
- Production-grade authentication and authorization
- React-based frontend
- Automated testing
- Containerized deployment

## Security

Never commit real ISE credentials, endpoint credentials, tokens, or private infrastructure details. Use environment variables, secure credential storage, or an appropriate secret manager.

## Author

**Dev Bhargav**

GitHub: https://github.com/majordevbhargav
