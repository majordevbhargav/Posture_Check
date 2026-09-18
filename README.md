# Endpoint Posture Check

A learning and lab project exploring **Windows endpoint posture assessment, Cisco ISE session visibility, data collection, and controlled remediation workflows**.

## Architecture

```text
Windows Endpoint
      |
      v
Posture Agent
      |
      v
Posture Application
   |      |      |
Storage Dashboard Session State
      |
      v
   Cisco ISE
      |
      v
Access / Remediation Workflow
```

## Components

- `posture_agent.ps1` - endpoint posture collection
- `posture_app.py` - posture ingestion and service logic
- `posture_ui.py` - operator dashboard
- `ise_session_watcher.py` - ISE session tracking
- `Save-PostureCredential.ps1` - credential setup

## Focus Areas

- Endpoint compliance
- Cisco ISE
- PowerShell automation
- Python services
- REST APIs
- Network access control
- Session tracking
- Security workflows

## Learning Direction

This project helped me understand how endpoint information can connect with network-access context.

It also led toward the more structured **Endpoint-Posture-Java** platform, where the architecture separates endpoint evidence, persistence, investigation, and enforcement.

## Development Direction

- Database-backed persistence
- Stronger authentication and authorization
- Audit logging
- Richer endpoint health signals
- pxGrid integration
- Automated testing
- Decoupled frontend

## Security

Never commit real ISE credentials, endpoint credentials, tokens, or private infrastructure information.

Use secure credential storage and run the project only in authorized environments.

## Author

**Dev Bhargav**

[GitHub](https://github.com/majordevbhargav) · [LinkedIn](https://www.linkedin.com/in/devbhargav100)
