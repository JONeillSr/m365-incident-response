# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-20

### Added
- `scripts/Invoke-M365IncidentResponse.ps1` v1.2.2: evidence collector (interactive and
  non-interactive sign-ins, directory audit, app consent, devices, Conditional Access, mailbox,
  unified audit, message trace) with a SHA-256 manifest; emergency-access audits; device-code
  Conditional Access policy creation, proof, enablement, and enforcement evidence.
- `scripts/Invoke-InvestigationCleanup.ps1` v1.0.1: removes the Graph consent grant and disabled
  rogue devices an investigation leaves behind.
- `scripts/Send-M365IncidentRecipientNotifications.ps1` v2.1.1: reviewed, rate-limited,
  one-per-recipient incident notices through Microsoft Graph or ACS SMTP.
- `templates/Notification-Template.md`: generic two-version notice template.
- `lab/`: sanitized dataset of a real incident, the attack-chain replay, the dataset builder with
  leak test, and the device-code proof demo.
- `docs/COLLECTOR.md` and `docs/NOTIFICATIONS.md`.
