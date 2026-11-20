# Microsoft 365 Incident Response Collector

`Invoke-M365IncidentResponse.ps1` collects a defensible evidence record for a suspected Microsoft 365
account compromise: sign-ins (interactive and non-interactive), directory audit, app consent, devices,
Conditional Access, mailbox configuration, unified audit, and message trace, in one run.

The normal `Collect` action is read-only. Conditional Access changes use separate, explicitly named
actions and cannot occur during evidence collection.

The same script also supports the emergency-access recovery lifecycle: account-readiness auditing,
Conditional Access scenario testing, report-only device-code policy creation, policy proof,
deliberate enablement, and collection of an actual blocked sign-in as enforcement evidence.

## Quick start: collect the complete incident record

Open a fresh **PowerShell 7** window on a privileged access workstation (PAW).

```powershell
Set-Location "C:\Tools\m365-incident-response\scripts"

$endUtc = [datetimeoffset]::UtcNow

.\Invoke-M365IncidentResponse.ps1 `
    -Action Collect `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -StartUtc "2026-01-05T00:00:00Z" `
    -EndUtc $endUtc `
    -SuspectIpAddress "203.0.113.66" `
    -SuspectDeviceId @(
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222"
    ) `
    -CampaignSubject "Example RFP"
```

This is the primary collection command. It creates a new timestamped directory under
`Evidence-Runs` next to the script; it never overwrites an earlier run.

At the end, PowerShell prints the exact output directory. Review these files first:

1. `00-Run\Collection-Summary.json`
2. `00-Run\Collection-Errors.csv`
3. `00-Run\Collection-Steps.csv`
4. `99-Manifest\Evidence-Index.csv`
5. `99-Manifest\SHA256SUMS.csv`

If `Collection-Errors.csv` contains records, the run is partial. Successful components are still
preserved, but the failed component must be corrected and collected again.

## What the complete command collects

| Area | Evidence |
|---|---|
| Identity | Raw and flattened target-user sign-ins (interactive and non-interactive), authentication protocol, original transfer method, source IP, device, session, risk, Conditional Access, and authentication details |
| Source-IP correlation | Tenant sign-ins matching each supplied suspect IP |
| Directory audit | Raw tenant directory audit, target-user-relevant events, app-consent changes, and device/authentication changes |
| Applications | Current service principals, tenant delegated OAuth grants, target/tenantwide consent, and user app-role assignments |
| Devices | Tenant device inventory, target-owned/registered devices, `DESKTOP-*` devices, supplied suspect devices, owners, registered users, and tenant device-code sign-ins |
| Conditional Access | Raw and flattened snapshot of all current Conditional Access policies |
| Mailbox | Current aliases, forwarding, auditing configuration, visible/hidden inbox rules, FullAccess permissions, and SendAs permissions |
| Unified audit | Inbox-rule changes, forwarding changes, mailbox access, item actions, audited sends, and mailbox/recipient permission changes |
| Message trace | Outbound messages from every SMTP identity on the mailbox, subject/source-IP summary, and exact-subject campaign recipients and delivery status |
| Evidence integrity | Transcript, run metadata, evidence index, error report, step report, completion summary, and SHA-256 manifest |

The collector saves raw JSON wherever the source API supplies rich nested data and creates CSV
views for review. An empty CSV contains `# No records returned`; that means the query completed but
returned zero records.

## Prerequisites

### PowerShell modules

Check the installed modules:

```powershell
Get-Module Microsoft.Graph.Authentication,ExchangeOnlineManagement -ListAvailable |
    Sort-Object Name,Version -Descending |
    Select-Object Name,Version,Path
```

If required, install or update them from PowerShell Gallery:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

If Microsoft Graph reports an MSAL method or assembly mismatch, close every PowerShell window,
open a fresh PowerShell 7 session, update `Microsoft.Graph.Authentication`, and run the collector
again. Avoid mixing old Graph modules already loaded in the same process.

### Authorization and licensing

The script requests these Microsoft Graph delegated scopes when needed:

```text
AuditLog.Read.All
Directory.Read.All
Device.Read.All
Application.Read.All
DelegatedPermissionGrant.Read.All
Policy.Read.All
User.Read.All
```

Conditional Access creation or enablement additionally requests:

```text
Policy.ReadWrite.ConditionalAccess
```

The signed-in administrator must also hold directory and Exchange roles that allow the requested
data. Conditional Access changes require Conditional Access Administrator or Security Administrator.
Microsoft Entra sign-in export and Conditional Access require the applicable Entra licensing.

Microsoft documents `AuditLog.Read.All` for sign-in retrieval and notes that a Conditional Access
reader role plus a policy-read permission is required for applied-policy details:

<https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0>

Sign-ins are read from the Graph beta endpoint with a
`signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser')` filter. Without it,
Graph returns only interactive sign-ins, and the token refreshes that let a stolen session keep
working never appear. Non-interactive volume is much higher, so tenant-wide pulls take longer.
The flattened CSVs carry a `SignInEventTypes` column to tell the two apart.

## Collection choices

The complete command collects every component. For a Graph-only rerun:

```powershell
.\Invoke-M365IncidentResponse.ps1 `
    -Action Collect `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -StartUtc "2026-01-05T00:00:00Z" `
    -EndUtc ([datetimeoffset]::UtcNow) `
    -Components Identity,DirectoryAudit,Applications,Devices,ConditionalAccess `
    -SuspectIpAddress "203.0.113.66"
```

For an Exchange/Purview/message-trace-only rerun:

```powershell
.\Invoke-M365IncidentResponse.ps1 `
    -Action Collect `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -StartUtc "2026-01-05T00:00:00Z" `
    -EndUtc ([datetimeoffset]::UtcNow) `
    -Components Mailbox,UnifiedAudit,MessageTrace `
    -CampaignSubject "Example RFP"
```

To place evidence elsewhere, add:

```powershell
-OutputRoot "D:\Protected-Incident-Evidence"
```

Use a location restricted to the incident team. These exports contain personal data, message
metadata, device identifiers, IP addresses, application grants, and security configuration.

## Audit emergency-access accounts

Run this from a fresh PowerShell 7 session. The action requests the additional read-only scopes
`RoleManagement.Read.Directory` and `UserAuthenticationMethod.Read.All`:

```powershell
.\Invoke-M365IncidentResponse.ps1 `
    -Action AuditEmergencyAccessAccounts `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -EmergencyAccessUpn @(
        "emergency01@somedomainsomewhere.onmicrosoft.com",
        "emergency02@somedomainsomewhere.onmicrosoft.com"
    )
```

Review:

```text
01-Identity\Emergency-Access-Account-Audit.csv
01-Identity\Emergency-Access-Entra-Role-Comparison.csv
01-Identity\Emergency-Access-Conditional-Access-Group-Audit.csv
01-Identity\Emergency-Access-Audit-Raw.json
```

For each emergency account, the principal readiness fields should normally be:

```text
AccountEnabled              = True
CloudOnly                   = True
PermanentActiveDirectGA     = True
HasFido2OrCertificateMethod = True
```

The role comparison is informational. Microsoft recommends permanent active Global Administrator
for emergency access; it does not recommend copying every operational role from a normal administrator.
When the named device-code policy exists, the action also audits every excluded group and confirms
that the supplied emergency accounts are direct members, the group is static, and no unexpected
direct members are present.

`HasFido2OrCertificateMethod = True` confirms that Microsoft Entra reports a phishing-resistant
method on the account. It does **not** prove that the assigned physical key, its PIN, the chosen
workstation, Conditional Access path, or monitoring alert works. Perform and document a clean-session
sign-in drill for each account.

### Emergency-access operational drill

For each emergency account, using its separately assigned security key:

1. Notify the monitoring contact that a planned test is beginning.
2. Start a new private-browser session on the designated secure workstation.
3. Sign in using **Sign-in options > Security key** and the key's PIN.
4. Open the Entra admin center and perform a harmless read-only Global Administrator action.
5. Confirm that the emergency-account sign-in alert reaches its intended recipients.
6. Sign out, close the private session, and record the date, operator, result, key identifier, and
   evidence location.
7. Repeat with the second account and its distinct key. Do not use one key as the sole credential for
   both accounts.

One working key per account establishes primary-key coverage, not credential redundancy. Add and
independently test a backup key for each account, and store primary and backup keys in separate secure
locations. Do not store a key's PIN with the key.

After the drill, rerun both read-only audits and retain their separate timestamped output folders:

```powershell
.\Invoke-M365IncidentResponse.ps1 `
    -Action AuditEmergencyAccessAccounts `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -EmergencyAccessUpn @(
        "emergency01@somedomainsomewhere.onmicrosoft.com",
        "emergency02@somedomainsomewhere.onmicrosoft.com"
    )

.\Invoke-M365IncidentResponse.ps1 `
    -Action AuditEmergencyAccessConditionalAccess `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -EmergencyAccessUpn @(
        "emergency01@somedomainsomewhere.onmicrosoft.com",
        "emergency02@somedomainsomewhere.onmicrosoft.com"
    )
```

Microsoft recommends at least two cloud-only emergency accounts, phishing-resistant authentication,
permanent active Global Administrator assignment, exclusion from Conditional Access policies that
could block access, alerts for every use, and validation at least every 90 days:

<https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access>

Security-key registration and sign-in guidance:

- <https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-register-passkey-with-security-key>
- <https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-security-key-sign-in>

## Audit all Conditional Access policies for emergency access

This read-only action uses the Microsoft Graph Conditional Access What If evaluator. It tests each
emergency account against the current policy set across Azure Resource Manager, Microsoft Graph,
Exchange Online, and SharePoint Online. Its scenario matrix includes browsers, desktop clients,
Windows, macOS, Linux, iOS, Android, high-risk sign-ins, a noncompliant/unregistered device,
device code flow, and security-info registration.

Pass any known external or incident IP addresses with `-SuspectIpAddress` so location-dependent
policies are evaluated for those addresses too:

```powershell
.\Invoke-M365IncidentResponse.ps1 `
    -Action AuditEmergencyAccessConditionalAccess `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -EmergencyAccessUpn @(
        "emergency01@somedomainsomewhere.onmicrosoft.com",
        "emergency02@somedomainsomewhere.onmicrosoft.com"
    ) `
    -SuspectIpAddress @(
        "203.0.113.66",
        "198.51.100.25"
    )
```

Review:

```text
05-Conditional-Access\Emergency-Access-CA-Account-Summary.csv
05-Conditional-Access\Emergency-Access-CA-Applied-Policies.csv
05-Conditional-Access\Emergency-Access-CA-Unresolved-Policies.csv
05-Conditional-Access\Emergency-Access-CA-Scenario-Summary.csv
05-Conditional-Access\Emergency-Access-CA-WhatIf-Raw.json
05-Conditional-Access\Emergency-Access-CA-Coverage.json
```

The strongest result for each emergency account is:

```text
NoEnabledOrUnknownPolicyApplies = True
EvaluationComplete              = True
UnresolvedEnabledOrUnknownPolicies = 0
EmergencyAccessCaReadinessPass  = True
```

Report-only policies are reported separately because enabling one later could make an emergency
account unavailable. The action requests results for all policies so it can also identify enabled
policies that the evaluator could not resolve because scenario information was insufficient. Any
such unresolved policy or evaluation error makes the readiness result fail closed. Conditional
Access remains contextual, so this matrix does not replace independent sign-in tests, alerts, and
periodic operational exercises for both emergency accounts.

## Conditional Access: block device code flow

These actions are intentionally separate from `Collect`.

### End-to-end control sequence

Use this order; do not skip directly from policy creation to enablement:

1. `AuditEmergencyAccessAccounts`
2. Independently test each emergency account, physical key, and sign-in alert
3. `AuditEmergencyAccessConditionalAccess`
4. `CreateDeviceCodePolicyReportOnly`
5. Review report-only sign-ins and approved dependencies
6. `ExportDeviceCodePolicyProof`
7. `EnableDeviceCodePolicy` using a dedicated nonadministrator test user
8. Perform a controlled device-code attempt with that test user
9. `CollectDeviceCodePolicyEnforcementEvidence`
10. Preserve every timestamped evidence run and record the change in the incident chronology

Before creating or enabling the policy:

1. Verify at least two cloud-only emergency-access accounts.
2. Review sign-ins using both **Authentication protocol = Device code** and
   **Original transfer method = Device code flow**.
3. Identify Teams Rooms, Teams phones, Azure CLI, developer tooling, or device-registration
   dependencies.
4. Use narrowly scoped exception groups only for approved dependencies.
5. Do not use the compromised account or an emergency account as the test user.

Microsoft recommends blocking device code flow wherever possible, beginning in report-only mode:

<https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows>

### 1. Create the policy in report-only mode

Replace the example emergency and test users with verified accounts:

```powershell
.\Invoke-M365IncidentResponse.ps1 `
    -Action CreateDeviceCodePolicyReportOnly `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -TestUserUpn "ca-test@somedomainsomewhere.com" `
    -EmergencyAccessUpn @(
        "emergency01@somedomainsomewhere.onmicrosoft.com",
        "emergency02@somedomainsomewhere.onmicrosoft.com"
    ) `
    -Confirm
```

The confirmation prompt is expected. The policy is created as
`enabledForReportingButNotEnforced`; it does not block sign-ins yet.

If a documented device-registration dependency exists, add
`-ExcludeDeviceRegistrationService`. This excludes application ID
`01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9`. Do not add this exclusion without evidence that it is
required.

Microsoft's current guidance for Teams device exceptions is here:

<https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-teams-devices-device-code-flow>

### 2. Export policy and What If proof

```powershell
.\Invoke-M365IncidentResponse.ps1 `
    -Action ExportDeviceCodePolicyProof `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -TestUserUpn "ca-test@somedomainsomewhere.com"
```

Review `05-Conditional-Access\Device-Code-Policy-Proof-Summary.json`. Before enforcement, the
expected values are:

```text
PolicyState              = enabledForReportingButNotEnforced
ConfigurationValid       = true
WhatIfPolicyApplies      = true
WhatIfGrantControlBlocks = true
EnforcementConfigured    = false
```

Microsoft Graph What If evaluates which policies would apply to the supplied sign-in context:

<https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-evaluate?view=graph-rest-1.0>

### 3. Enable the policy

After reviewing report-only impact and independently testing both emergency-access accounts:

```powershell
.\Invoke-M365IncidentResponse.ps1 `
    -Action EnableDeviceCodePolicy `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -TestUserUpn "ca-test@somedomainsomewhere.com" `
    -ConfirmPolicyEnable `
    -Confirm
```

There are two safety controls:

- `-ConfirmPolicyEnable` records deliberate intent.
- `-Confirm` presents PowerShell's interactive change confirmation.

The action validates that the existing policy includes all users, includes all resources, targets
device code flow, and uses the block control before it changes policy state.

### 4. Prove actual enforcement

Policy JSON and What If prove configuration and expected evaluation. A controlled failed sign-in
attributed to the policy proves enforcement.

Using only the dedicated test account, initiate a device-code sign-in that you personally control.
For example, if Azure CLI is installed:

```powershell
az login --use-device-code --tenant "<tenant-id>"
```

Do not enter a device code received by email, chat, telephone, or another person.

After the expected failure has reached Entra sign-in logs, run:

```powershell
.\Invoke-M365IncidentResponse.ps1 `
    -Action CollectDeviceCodePolicyEnforcementEvidence `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -TestUserUpn "ca-test@somedomainsomewhere.com" `
    -SignInLookbackMinutes 120
```

Review `05-Conditional-Access\Device-Code-Enforcement-Proof-Summary.json`. Definitive proof is:

```text
EventsBlockedByThisPolicy > 0
EnforcementProven         = true
```

The matching event must have a nonzero sign-in error, Conditional Access status `failure`, and the
named policy recorded with result `failure`.

## Evidence layout

Each run uses this structure:

```text
Evidence-Runs\<UTC timestamp>-<action>-<user>\
  00-Run\
  01-Identity\
  02-Directory-Audit\
  03-Applications\
  04-Devices\
  05-Conditional-Access\
  06-Mailbox\
  07-Unified-Audit\
  08-Message-Trace\
  99-Manifest\
```

Copy the completed run to the protected incident repository before analysis. Analyze a working copy
when possible. Recalculate hashes if evidence must be transformed, and document who performed the
transformation and why.

## Important collection limits

- Microsoft Entra sign-ins are limited by the tenant's sign-in retention and licensing.
- `Get-MessageTraceV2` provides up to 90 days and only ten days per query. The script uses daily
  intervals and recursively narrows intervals that reach 5,000 results.
- `Search-UnifiedAuditLog` returns up to 50,000 records for a `ReturnLargeSet` session. The script
  searches daily, records a warning if that ceiling is reached, and preserves successful slices.
- Tenant-wide device-code correlation can take time because the script reads the interval in daily
  pages before retaining device-code and device-code-derived events.
- Current configuration files are snapshots taken at collection time, not proof that the same state
  existed throughout the incident interval.

Microsoft references:

- Unified audit paging: <https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/search-unifiedauditlog?view=exchange-ps>
- Message trace V2: <https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-messagetracev2?view=exchange-ps>
- Device registered owners: <https://learn.microsoft.com/en-us/graph/api/device-list-registeredowners?view=graph-rest-1.0>

## Full command help

```powershell
Get-Help .\Invoke-M365IncidentResponse.ps1 -Full
Get-Help .\Invoke-M365IncidentResponse.ps1 -Examples
```


## Emergency-access records

Keep operational secrets out of your emergency-access runbook. Record key serial numbers and
controlled storage locations, but never passwords, recovery codes, FIDO2 PINs, or complete
physical-storage combinations.
