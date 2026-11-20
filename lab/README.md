# Lab: replay the incident and prove the fix

These scripts let you walk through a real Microsoft 365 account compromise without touching a
production tenant, then prove a device-code block works in a test tenant. They come from the
Live! 360 Orlando 2026 keynote *I Teach Security, and Then My Account Was Compromised*.

| Script | What it does | Needs a tenant? |
|---|---|---|
| `Show-IncidentTimeline.ps1` | Replays the attack chain from `Sanitized-Evidence\`, one act at a time | No |
| `New-SanitizedIncidentDataset.ps1` | Builds a dataset like `Sanitized-Evidence\` from your own private evidence, with a leak test | No (reads local files) |
| `Invoke-DeviceCodeProofDemo.ps1` | Short, projector-safe view of the collector's device-code policy proof and enforcement evidence | Yes, a test tenant |

## The sample dataset

`Sanitized-Evidence\` is the real shape of the incident, with every identifier replaced:

- IP addresses are from the RFC 5737 documentation ranges (`192.0.2.x`, `198.51.100.x`,
  `203.0.113.x`).
- The mailbox owner is `alex@somedomainsomewhere.com`; devices are `DESKTOP-ROGUE01` through `05`.
- Sessions are `SESSION-A`, `SESSION-B`, and so on; recipients are `R001`, `R002`, and so on.
- The campaign subject is `Example RFP`.

`Manifest.json` records the row counts and the leak-test result from when the dataset was built.

## 1. Replay the attack chain

```powershell
.\Show-IncidentTimeline.ps1
```

Press Enter to move through eight acts:

| Act | What it shows |
|---|---|
| 1 Initial access | Device-code sign-ins, and the MFA detail "satisfied by claim in the token" |
| 2 Persistence | Rogue device registrations, seconds after the first sign-in |
| 3 The thread | One session identifier linking July activity to the August campaign |
| 4 Concealment | The inbox rules that hid replies |
| 5 Impact | The audited sends from Outlook on the web |
| 6 Anti-forensics | The campaign items moved and deleted afterward |
| 7 Blast radius | Targeted, delivered, and failed counts from recipient-level message trace |
| 8 Containment | Each containment action and how long after the campaign it came |

Options:

```powershell
.\Show-IncidentTimeline.ps1 -Act 1,3,7,8                  # short version
.\Show-IncidentTimeline.ps1 -NoPause                      # print everything at once
.\Show-IncidentTimeline.ps1 -TimeZoneId "Eastern Standard Time"
```

It reads local CSV files only: no sign-in, no network.

## 2. Build a dataset from your own evidence

After you've collected evidence with `..\scripts\Invoke-M365IncidentResponse.ps1`, you can build
a shareable dataset for a lessons-learned session:

```powershell
.\New-SanitizedIncidentDataset.ps1 `
    -EvidenceRoot "D:\IR\Incident-Evidence" `
    -AttackIp "<attack IP>" `
    -RegistrationIp "<device registration IP>" `
    -SelfAddress "user@somedomainsomewhere.com" `
    -CampaignSubject "<campaign subject>" `
    -OutputPath ".\My-Sanitized-Evidence"
```

The `-*File` parameters default to the file names from the original investigation. Point them at
your own files with `-SignInFile`, `-DeviceFile`, and the rest (`Get-Help -Full` lists them).

The leak test searches every output file for each original identifier it saw, plus any GUID or
non-somedomainsomewhere address. Any hit deletes the output and stops. The campaign subject is copied as is,
so check it before you share anything. Then look at every CSV yourself anyway. A leak test only
catches what it knows to look for.

## 3. Prove a device-code block in a test tenant

`Invoke-DeviceCodeProofDemo.ps1` wraps the collector's device-code actions in a short view. Use a
**test tenant** and a dedicated, nonadministrator test user.

First create the policy in report-only mode with the collector (see
[COLLECTOR.md](../docs/COLLECTOR.md#conditional-access-block-device-code-flow)), confirm two
working emergency-access accounts are excluded, and enable it. Then:

```powershell
# Policy and What If proof
.\Invoke-DeviceCodeProofDemo.ps1 -Step Proof `
    -AdminUpn admin@somedomainsomewhere.onmicrosoft.com -TestUserUpn ca-test@somedomainsomewhere.onmicrosoft.com

# Instructions for the device-code attempt (nothing runs)
.\Invoke-DeviceCodeProofDemo.ps1 -Step Attempt -TestUserUpn ca-test@somedomainsomewhere.onmicrosoft.com

# Collect the blocked sign-in as enforcement evidence
.\Invoke-DeviceCodeProofDemo.ps1 -Step Enforcement `
    -AdminUpn admin@somedomainsomewhere.onmicrosoft.com -TestUserUpn ca-test@somedomainsomewhere.onmicrosoft.com

# Show the newest saved results again, offline
.\Invoke-DeviceCodeProofDemo.ps1 -Step Saved
```

Sign-in logs can take several minutes to show the blocked attempt. Evidence runs go to
`Evidence-Runs\` beside the script; they contain tenant and policy IDs, so they're ignored by git.
Don't share them.

## Cleaning up afterward

`..\scripts\Invoke-InvestigationCleanup.ps1` reviews and removes what an investigation leaves
behind: the broad Microsoft Graph Command Line Tools consent grant and disabled rogue devices.
Run `-Action Report` first. Remove the grant last, when you're finished collecting.
