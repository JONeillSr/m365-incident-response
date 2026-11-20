# Microsoft 365 Incident Response Toolkit

PowerShell tools for investigating, containing, and recovering from a Microsoft 365 account
compromise, built during a real one.

In 2026 my own Microsoft 365 account was taken over through device code phishing. The attacker
registered rogue devices, hid replies with inbox rules, and sent a phishing campaign from my
mailbox. These are the tools I built to reconstruct what happened, prove the fix, and tell the
people who got the email. The full story is in the
[Azure Innovators incident response series](https://www.azureinnovators.com/blog/).

**Test everything in a nonproduction tenant before you rely on it in an incident.**

## What's here

| Path | What it does | Changes anything? |
|---|---|---|
| `scripts/Invoke-M365IncidentResponse.ps1` | Collects sign-ins (interactive and non-interactive), directory audit, app consent, devices, Conditional Access, mailbox configuration, unified audit, and message trace into a timestamped folder with a SHA-256 manifest. Also audits emergency-access accounts and builds, proves, and enforces a device-code-flow block | `-Action Collect` is read-only. Conditional Access changes happen only through separately named actions with confirmation prompts |
| `scripts/Invoke-InvestigationCleanup.ps1` | Reviews and removes what the investigation leaves behind: the broad Microsoft Graph Command Line Tools consent grant and disabled rogue devices | `Report` is read-only. The other actions support `-WhatIf` and ask for confirmation |
| `scripts/Send-M365IncidentRecipientNotifications.ps1` | Prepares, previews, tests, and sends one reviewed notice per recipient through Microsoft Graph or Azure Communication Services SMTP, with rate limits and resume | Prepare and Preview send nothing. Send requires `-ConfirmSend` and a prompt |
| `templates/Notification-Template.md` | Two-version notice template for the mailer | |
| `lab/` | A sanitized copy of the real incident, an eight-act replay of the attack chain, a dataset builder with a leak test, and a device-code proof demo | See [lab/README.md](lab/README.md) |
| `docs/` | [COLLECTOR.md](docs/COLLECTOR.md) and [NOTIFICATIONS.md](docs/NOTIFICATIONS.md) | |

## Requirements

- PowerShell 7 on a privileged access workstation (PAW).
- `Microsoft.Graph.Authentication` and `ExchangeOnlineManagement`.
- Roles, Graph scopes, and licensing depend on the action. Each script's help lists them:

```powershell
Get-Help .\scripts\Invoke-M365IncidentResponse.ps1 -Full
```

## Quick start

Collect the complete evidence record for one user:

```powershell
.\scripts\Invoke-M365IncidentResponse.ps1 `
    -Action Collect `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -StartUtc "2026-01-05T00:00:00Z" `
    -SuspectIpAddress "203.0.113.66"
```

Evidence lands in a new timestamped folder under `scripts\Evidence-Runs\`. Start with
`00-Run\Collection-Summary.json` and `00-Run\Collection-Errors.csv`. See
[docs/COLLECTOR.md](docs/COLLECTOR.md) for every action.

Or try the lab first, with no tenant at all:

```powershell
.\lab\Show-IncidentTimeline.ps1
```

## The order that matters

1. **Revoke sessions with the password reset.** A reset alone doesn't evict sessions that never
   used the password, like those from device code phishing.
2. **Collect evidence before you clean up.** Disable rogue devices; don't delete them until you no
   longer need them.
3. **Before you block device code flow,** inventory who uses it, confirm two tested
   emergency-access accounts, deploy in report-only, then enable. Prove it with a real blocked
   sign-in from a dedicated test user.
4. **Don't send apologies from the compromised mailbox.** Set up a separate sending service ahead of
   time; [acs-email-toolkit](https://github.com/JONeillSr/acs-email-toolkit) sets up Azure
   Communication Services Email.
5. **Clean up last.** When the investigation is done, remove the broad delegated grants that
   evidence collection created.

## Handling evidence

Collected evidence contains personal data, message metadata, IP addresses, device identifiers, and
security configuration. Store it somewhere restricted to the incident team. The `.gitignore` keeps
`Evidence-Runs/` and `Notification-Runs/` out of the repository. Don't commit them anywhere else
either.

## References

- [Responding to a compromised email account](https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account)
- [Block authentication flows with Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows)
- [Manage emergency access accounts](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)
- [Refresh tokens and revocation](https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens)

## License

[MIT](LICENSE). Provided as is, without warranty. You're responsible for testing it in your own
environment.

John A. O'Neill Sr. · [Azure Innovators](https://www.azureinnovators.com)
