# Incident-recipient notification mailer

`scripts/Send-M365IncidentRecipientNotifications.ps1` prepares, previews, tests, and sends one
individually addressed incident notice per approved recipient. It supports two transports:

- `MicrosoftGraph` sends through the signed-in Microsoft 365 mailbox. It's the default.
- `AcsSmtp` sends through Azure Communication Services (ACS) SMTP. Use it when the compromised
  mailbox can't send, or shouldn't.

Neither transport's acceptance proves delivery. Verify Graph delivery with Exchange message trace,
and ACS delivery with ACS Email operational logs and delivery-status events.

## Before you start: don't notify from the compromised mailbox

After a mailbox sends a phishing campaign, Microsoft Defender may restrict it from sending. A burst
of hundreds of apology messages from the same mailbox looks exactly like a second campaign and can
trigger that restriction mid-run. If you have more than a handful of recipients, plan on a separate
sending service from the start.

Do not use another Microsoft 365 mailbox merely to get around an outbound-spam restriction.

## Setting up ACS for notifications

This repo doesn't create ACS resources. Use the companion
[acs-email-toolkit](https://github.com/JONeillSr/acs-email-toolkit):

1. `Deploy-ACSEmail.ps1` creates the Communication Service, Email Service, domain, and DNS records.
2. `Deploy-ACSEmail.ps1 -AddSmtpEndpoint` creates a dedicated SMTP username and Entra application
   for incident notices, separate from your other senders.
3. `Get-ACSEmailStatus.ps1 -EnableDiagnostics` turns on the Email operational logs you'll need to
   prove delivery.

Do this now, before an incident. Domain verification and DNS take time you won't have later.

## Safeguards

- One recipient per message; no shared To, Cc, or Bcc list.
- Explicit review: nothing sends unless its row has `SendApproved` set to `True`.
- Separate Graph and ACS submission logs.
- From, Reply-To, SMTP username, and a notification ID are recorded for every ACS submission.
- A successful Standard and Executive ACS test is required within 24 hours of Send.
- ACS defaults: 15 messages per batch, a 15-minute pause, and local ceilings of 20 accepted messages
  per rolling minute and 60 per rolling hour. Rolling counts are rebuilt from the logs on resume.
- Transient SMTP errors are retried with backoff. Two consecutive failures pause the run and create
  `SENDING-PAUSED.txt`.
- Recipients already accepted by ACS are always skipped when the same run directory is reused.
- Recipient-level reconciliation of an earlier Graph run excludes delivered rows and permits retry
  only for failed rows with an approved retry action.

The local rate guard only knows about submissions this script logged in this run directory. Other
ACS applications in the same subscription consume the same quota.

## Identity terminology

These three values are different:

| Value | Example | Purpose |
|---|---|---|
| SMTP username | `incident-notifications-smtp@somedomainsomewhere.com` | Authentication identity linked to an Entra application |
| From (MailFrom) | `DoNotReply@notify.somedomainsomewhere.com` | Sender address configured on the ACS domain, visible to recipients |
| Reply-To | `alex@somedomainsomewhere.com` | Monitored mailbox that receives replies |

The SMTP password is the **client-secret value** of the Entra application linked to the SMTP
username. It isn't the secret ID or an ACS access key. Never put it in a command, CSV, file,
transcript, or log. Read it as a `SecureString` at the start of each Test or Send run.

## Prerequisites

- PowerShell 7.
- For `MicrosoftGraph`: `Microsoft.Graph.Authentication` and delegated `Mail.Send` and `User.Read`.
- For `AcsSmtp`: a verified ACS domain, a MailFrom address on it, an SMTP username showing
  **Ready to use**, its client-secret value, and TCP 587 with TLS 1.2 to `smtp.azurecomm.net`.
- A reviewed recipient list and message template (see below).

## The message template

`templates/Notification-Template.md` holds two versions, each under its own heading with a
`**Subject:**` line:

- **Standard recipient version** for most recipients.
- **Personal follow-up for executives, security firms, and training partners** for people who
  deserve a personal note. `[Name]` is replaced with the recipient's display name; when the name is
  blank, `Hi [Name],` becomes `Hello,`.

Keep the headings exactly as they are; the script finds the sections by name. Rewrite everything
else in your own voice. Use `-TemplatePath` to point at a different file.

## 1. Prepare the review queue

```powershell
$runDirectory = Join-Path $PWD "Notification-Runs\Recipient-Notice"

.\Send-M365IncidentRecipientNotifications.ps1 `
    -Mode Prepare `
    -RecipientCsvPath ".\Recipients.csv" `
    -OutputDirectory $runDirectory
```

The source CSV needs a `RecipientAddress`, `EmailAddress`, or `Address` column. Prepare never
connects to anything. Review `Notification-Review-Queue.csv`:

| Column | Action |
|---|---|
| `RecipientAddress` | Confirm the address is within the notification scope |
| `DisplayName` | Optional. Blank executive names render as `Hello,` |
| `MessageVersion` | `Standard` or `Executive` |
| `SendApproved` | `True` only after review |
| `Notes` | Internal only; never included in the message |

Restrict the run directory. Its CSV files contain recipient data.

## 2. Preview without connecting or sending

```powershell
$queuePath = Join-Path $runDirectory "Notification-Review-Queue.csv"

.\Send-M365IncidentRecipientNotifications.ps1 `
    -Mode Preview `
    -Transport AcsSmtp `
    -RecipientCsvPath $queuePath `
    -OutputDirectory $runDirectory
```

Review `Planned-Messages.csv`, the three `Preview-*.txt` samples, and
`Preview-Blocking-Issues.csv` if it exists.

## 3. Send the controlled ACS tests

Use a mailbox you control at a provider other than your sending domain:

```powershell
$smtpSecret = Read-Host "ACS SMTP client-secret value" -AsSecureString

.\Send-M365IncidentRecipientNotifications.ps1 `
    -Mode Test `
    -Transport AcsSmtp `
    -FromAddress "DoNotReply@notify.somedomainsomewhere.com" `
    -FromDisplayName "Security Incident Notice" `
    -ReplyToAddress "alex@somedomainsomewhere.com" `
    -SmtpUsername "incident-notifications-smtp@somedomainsomewhere.com" `
    -SmtpPassword $smtpSecret `
    -TestRecipient "controlled-test@example.com" `
    -OutputDirectory $runDirectory
```

Before Send, confirm both messages arrived, the sender and Reply-To are right, no `[Name]` token
remains, there are no attachments or unexpected links, and SPF, DKIM, and DMARC pass in the headers.

## 4. Reconcile an earlier Graph run (if there was one)

If you started with Graph and it was cut off, build a reconciliation CSV from message trace that
marks each earlier recipient `Delivered` (no resend) or `Failed` (retry). Pass it with
`-ReconciliationCsvPath`. Delivered rows are excluded, failed rows are retried, and any unresolved
or contradictory row blocks sending and creates `Reconciliation-Blocking-Issues.csv`.

Don't combine `-ReconciliationCsvPath` with `-ResendRecipientsPreviouslyAcceptedByGraph`. The
reconciliation file is precise; the switch isn't.

## 5. Review the exact plan with -WhatIf

```powershell
.\Send-M365IncidentRecipientNotifications.ps1 `
    -Mode Send `
    -Transport AcsSmtp `
    -RecipientCsvPath $queuePath `
    -FromAddress "DoNotReply@notify.somedomainsomewhere.com" `
    -ReplyToAddress "alex@somedomainsomewhere.com" `
    -SmtpUsername "incident-notifications-smtp@somedomainsomewhere.com" `
    -OutputDirectory $runDirectory `
    -MaxMessages 300 `
    -ConfirmSend `
    -WhatIf
```

Review `Current-Send-Plan.csv` row by row. `-WhatIf` doesn't need the secret and sends nothing.

## 6. Send

Run the same command without `-WhatIf`, adding `-SmtpPassword $smtpSecret` (read it again first)
and `-SendVersion All`. The script asks for one batch-level confirmation; don't add `-Confirm`.

At the default 60 per hour, 250 recipients take a little over four hours. The console shows every
acceptance, failure, batch pause, and rate-guard wait.

## 7. Resume safely

If the run is interrupted, rerun the same Send command with the same queue and run directory. The
script skips recipients already accepted and rebuilds its rate history from
`ACS-Test-Submission-Log.csv` and `ACS-Submission-Log.csv`. Never edit accepted rows to restart.

If `SENDING-PAUSED.txt` exists, investigate its error before you remove it, and keep a copy with
the incident evidence.

## 8. Prove delivery

`AcceptedByAcsSmtp` means the SMTP server accepted the message, nothing more. After every batch:

1. Review `ACS-Submission-Log.csv` for failures.
2. Query ACS Email operational logs and delivery-status events.
3. Add hard bounces to your suppression process before any retry.
4. Answer replies, and follow up personally with the people who matter most.
5. Keep the batch logs and diagnostic exports with the evidence.

## Stop conditions

Stop immediately if a test message doesn't arrive or has the wrong identity, SPF/DKIM/DMARC fails,
the template has an unresolved token, ACS returns authentication, quota, or repeated SMTP errors,
`SENDING-PAUSED.txt` appears, logs show unexpected bounces or quarantine, or anything suggests
containment is incomplete.

These are security notifications, not a marketing campaign. Don't generate extra traffic to improve
a failure rate.

## References

- [ACS SMTP sending](https://learn.microsoft.com/en-us/azure/communication-services/quickstarts/email/send-email-smtp/send-email-smtp)
- [ACS service limits](https://learn.microsoft.com/en-us/azure/communication-services/concepts/service-limits)
- [ACS Email logs](https://learn.microsoft.com/en-us/azure/communication-services/concepts/analytics/logs/email-logs)
- [Microsoft Graph sendMail](https://learn.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0)
- [Restricted entities in Microsoft 365](https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-restore-restricted-users)
