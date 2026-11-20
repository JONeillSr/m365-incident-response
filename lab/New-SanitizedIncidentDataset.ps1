<#
.SYNOPSIS
    Builds a small, sanitized copy of Microsoft 365 incident evidence that is safe to show
    on a projector or share with an audience.

.DESCRIPTION
    New-SanitizedIncidentDataset.ps1 reads the private evidence exported during a Microsoft 365
    account-compromise investigation and writes a curated demo dataset for
    Show-IncidentTimeline.ps1. It works from an allowlist: only the rows and columns that tell
    the attack story are copied, and every identifier in them is replaced.

    1. Loads the attack-relevant records: sign-ins, rogue device inventory, inbox-rule changes,
       mailbox item actions, audited sends, campaign message trace, and containment events.
    2. Filters each source to the incident (supplied attack and registration IP addresses,
       device-code-derived sessions, and the campaign subject) and drops everything else.
    3. Replaces identifiers with stable placeholders (see SANITIZATION MAP).
    4. Writes eight CSV files to OutputPath.
    5. Runs a leak test that searches every output file for each original identifier it saw,
       plus any GUID or non-somedomainsomewhere email address. Any hit deletes the output and stops.

    SANITIZATION MAP:
    Attack IP                  203.0.113.66   (RFC 5737 documentation range)
    Registration IP            198.51.100.40
    Any other IP               192.0.2.1, 192.0.2.2, ... in order of first appearance
    Session IDs                SESSION-A, SESSION-B, ... in order of first appearance
    Rogue DESKTOP-* devices    DESKTOP-ROGUE01..05 in registration order
    Other device names         VICTIM-PC-01, ...
    Mailbox owner              alex@somedomainsomewhere.com
    Recipients                 R001, R002, ... (self-addresses flagged, never written)
    Rule names                 Owner-name rule 1, 2 (attacker named rules after the owner)
    Rule sender condition      <one external correspondent>
    Device, object, correlation, audit IDs, message IDs, message bodies: dropped

    OUTPUT FILES:
    SignIns.csv         Successful sign-ins from the attack chain, with the MFA detail text
    Devices.csv         Rogue device objects: registration time, build, managed, compliant
    DeviceEvents.csv    Device registration audit events
    InboxRules.csv      Rule creation and removal with sanitized conditions and actions
    MailboxActions.csv  Attacker mailbox operations (access, create, delete) by time
    Sends.csv           Audited Send operations from the attack IP
    Trace.csv           Campaign message-trace rows keyed by recipient placeholder
    Containment.csv     Password changes, token revocation, rule removal, device disablement
    Manifest.json       Build time, source file names, row counts, leak-test result

    SAFETY:
    The script never modifies the source evidence. Indicator values are passed as parameters
    so this script contains none. Review the output yourself before every public use; the leak
    test catches identifiers it knows about, not every possible sensitive string.

.PARAMETER EvidenceRoot
    Folder that holds the private incident evidence (the dated export subfolders). Required.

.PARAMETER OutputPath
    Folder for the sanitized dataset. Created if missing. Existing files in it are replaced.
    Default: Sanitized-Evidence beside this script.

.PARAMETER AttackIp
    IP address the attacker used for mailbox access and sends. Required.

.PARAMETER RegistrationIp
    IP address the attacker used to register devices. Required.

.PARAMETER SelfAddress
    Every SMTP address and UPN of the compromised mailbox. Used to flag self-addressed trace
    rows and to seed the leak test. Required.

.PARAMETER CampaignSubject
    Exact subject of the fraudulent campaign. Required. It is copied to Trace.csv as is, so
    review it before sharing the output. (The sample dataset in this repo uses "Example RFP".)

.PARAMETER IncidentEndUtc
    Sign-ins and mailbox actions after this time are excluded, which keeps the investigator's
    own later activity out of the dataset. Default: 2026-08-07T23:59:59Z.

.PARAMETER SignInFile
    Raw Microsoft Graph sign-in export (JSON array), relative to EvidenceRoot.
    Default: 2026-07-22\User-SignIns-Raw.json.

.PARAMETER DeviceFile
    Suspected device inventory CSV, relative to EvidenceRoot.
    Default: 2026-08-06\Suspected-Fraudulent-Devices.csv.

.PARAMETER DirectoryAuditFile
    Device and authentication change audit CSV, relative to EvidenceRoot.
    Default: 2026-07-22\Device-And-Authentication-Changes.csv.

.PARAMETER InboxRuleFile
    Inbox-rule change audit CSV, relative to EvidenceRoot.
    Default: 2026-07-22\Inbox-Rule-Changes.csv.

.PARAMETER MailboxActionFile
    Mailbox access and item action audit CSV, relative to EvidenceRoot.
    Default: 2026-07-22\Mailbox-Access-And-Item-Actions.csv.

.PARAMETER SendFile
    Audited send action CSV, relative to EvidenceRoot.
    Default: 2026-07-22\Audited-Send-Actions.csv.

.PARAMETER TraceFile
    Campaign message-trace CSV, relative to EvidenceRoot.
    Default: 2026-08-06\Azure-Innovators-RFP-Campaign-Raw.csv.

.PARAMETER UnifiedAuditFile
    Unified audit CSV searched for refresh-token revocation (StsRefreshTokenValidFrom),
    relative to EvidenceRoot. Default: 2026-07-22\Unified-Audit-All.csv.

.EXAMPLE
    .\New-SanitizedIncidentDataset.ps1 -EvidenceRoot "D:\IR\M365-Incident" -AttackIp "<attack IP>" -RegistrationIp "<registration IP>" -SelfAddress "user@somedomainsomewhere.com","user@somedomainsomewhere.net" -CampaignSubject "Example RFP"

    Builds Sanitized-Evidence beside the script from the private evidence folder and runs the
    leak test. Run once on the presenter laptop before the keynote, then review the CSVs.

.EXAMPLE
    .\New-SanitizedIncidentDataset.ps1 -EvidenceRoot "D:\IR\M365-Incident" -AttackIp "<attack IP>" -RegistrationIp "<registration IP>" -SelfAddress "user@somedomainsomewhere.com" -CampaignSubject "Example RFP" -OutputPath "D:\Demo\Sanitized-Evidence" -IncidentEndUtc "2026-08-08T00:00:00Z"

    Writes the dataset to a different folder and stops the sign-in and mailbox window at a
    specific time.

.NOTES
    Script Name  : New-SanitizedIncidentDataset.ps1
    Version      : 1.0.0
    Author       : John O'Neill Sr.
    Company      : Azure Innovators
    Website      : https://www.azureinnovators.com
    Blog         : https://azureinnovators.com/blog

    Prerequisites:
    - PowerShell 7 or later
    - Read access to the private evidence folder produced by Invoke-M365IncidentResponse.ps1
      or the earlier collection scripts
    - No modules and no network access are required

    Change Log:
    v1.0.0 - 2026-11-05 - Initial release for the Live! 360 Orlando 2026 keynote demo.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EvidenceRoot,
    [string]$OutputPath = (Join-Path $PSScriptRoot "Sanitized-Evidence"),
    [Parameter(Mandatory)][string]$AttackIp,
    [Parameter(Mandatory)][string]$RegistrationIp,
    [Parameter(Mandatory)][string[]]$SelfAddress,
    [Parameter(Mandatory)][string]$CampaignSubject,
    [datetime]$IncidentEndUtc = [datetime]::Parse("2026-08-07T23:59:59Z").ToUniversalTime(),
    [string]$SignInFile = "2026-07-22\User-SignIns-Raw.json",
    [string]$DeviceFile = "2026-08-06\Suspected-Fraudulent-Devices.csv",
    [string]$DirectoryAuditFile = "2026-07-22\Device-And-Authentication-Changes.csv",
    [string]$InboxRuleFile = "2026-07-22\Inbox-Rule-Changes.csv",
    [string]$MailboxActionFile = "2026-07-22\Mailbox-Access-And-Item-Actions.csv",
    [string]$SendFile = "2026-07-22\Audited-Send-Actions.csv",
    [string]$TraceFile = "2026-08-06\Azure-Innovators-RFP-Campaign-Raw.csv",
    [string]$UnifiedAuditFile = "2026-07-22\Unified-Audit-All.csv"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
# pwsh -File passes "a,b" as one string; accept commas or semicolons either way.
$SelfAddress = @($SelfAddress | ForEach-Object { $_ -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$us =[System.Globalization.CultureInfo]::GetCultureInfo("en-US")

# ---------- helpers ----------
function Get-SourcePath([string]$Relative) {
    $p = Join-Path $EvidenceRoot $Relative
    if (-not (Test-Path -LiteralPath $p)) { throw "Source file not found: $p" }
    return $p
}

function ConvertTo-Utc([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse($Value, $us, $styles)
}

function Format-Utc([datetime]$Value) { $Value.ToString("yyyy-MM-ddTHH:mm:ssZ") }

$script:Forbidden = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
# Audit Targets fields are "Type:Name:Id:UPN"; the type labels are not identifiers.
$script:LabelWords = @("Device", "Other", "User", "Group", "ServicePrincipal", "Policy", "Application", "Directory", "True", "False", "Windows", "AzureAd", "None", "Inbox")
function Add-Forbidden([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $v = $Value.Trim()
    if ($v.Length -lt 4 -or $v -in $script:LabelWords -or $v -eq '00000000-0000-0000-0000-000000000000') { return }
    [void]$script:Forbidden.Add($v)
}

function Get-BareIp([string]$Ip) {
    # Audit ClientIP values carry a port: "a.b.c.d:port" or "[v6]:port". Sign-in IPs do not.
    if ($Ip -match '^\[(.+)\]:\d+$') { return $Matches[1] }
    if (@($Ip.ToCharArray() | Where-Object { $_ -eq ':' }).Count -eq 1) { return ($Ip -replace ':\d+$', '') }
    return $Ip
}

$ipMap = @{}; $ipNext = 1
$ipMap[$AttackIp] = "203.0.113.66"; $ipMap[$RegistrationIp] = "198.51.100.40"
function Get-SafeIp([string]$Ip) {
    if ([string]::IsNullOrWhiteSpace($Ip)) { return "" }
    $bare = Get-BareIp $Ip
    Add-Forbidden $bare
    if (-not $ipMap.ContainsKey($bare)) { $ipMap[$bare] = "192.0.2.$script:ipNext"; $script:ipNext++ }
    return $ipMap[$bare]
}

$sessionMap = @{}; $sessionNext = 0
function Get-SafeSession([string]$Id) {
    if ([string]::IsNullOrWhiteSpace($Id)) { return "" }
    Add-Forbidden $Id
    if (-not $sessionMap.ContainsKey($Id)) { $sessionMap[$Id] = "SESSION-" + [char](65 + $script:sessionNext); $script:sessionNext++ }
    return $sessionMap[$Id]
}

$deviceMap = @{}; $victimNext = 1
function Get-SafeDevice([string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Name)) { return "" }
    Add-Forbidden $Name
    if (-not $deviceMap.ContainsKey($Name)) { $deviceMap[$Name] = "VICTIM-PC-{0:00}" -f $script:victimNext; $script:victimNext++ }
    return $deviceMap[$Name]
}

foreach ($a in $SelfAddress) {
    Add-Forbidden $a
    Add-Forbidden ($a.Split('@')[-1])          # tenant and mail domains
}
Add-Forbidden $AttackIp; Add-Forbidden $RegistrationIp

# ---------- 1. rogue devices (defines DESKTOP-ROGUE names first) ----------
Write-Host "Reading device inventory..." -ForegroundColor Cyan
$devRows = @(Import-Csv -LiteralPath (Get-SourcePath $DeviceFile)) | Sort-Object { ConvertTo-Utc $_.RegistrationUTC }
$i = 1
$devices = foreach ($d in $devRows) {
    Add-Forbidden $d.DeviceId; Add-Forbidden $d.ObjectId; Add-Forbidden $d.DisplayName
    foreach ($o in ($d.Owners, $d.RegisteredUsers)) { foreach ($part in ($o -split '[<>;]')) { Add-Forbidden $part } }
    $deviceMap[$d.DisplayName] = "DESKTOP-ROGUE{0:00}" -f $i; $i++
    [pscustomobject]@{
        Device        = $deviceMap[$d.DisplayName]
        RegisteredUtc = Format-Utc (ConvertTo-Utc $d.RegistrationUTC)
        OS            = $d.OperatingSystem
        OSBuild       = $d.OperatingSystemBuild
        TrustType     = $d.TrustType
        Managed       = if ($d.Managed) { $d.Managed } else { "False" }
        Compliant     = if ($d.Compliant) { $d.Compliant } else { "False" }
        EnabledNow    = $d.Enabled
    }
}

# ---------- 2. sign-ins ----------
Write-Host "Reading sign-ins..." -ForegroundColor Cyan
$raw = Get-Content -LiteralPath (Get-SourcePath $SignInFile) -Raw | ConvertFrom-Json
if ($raw.PSObject.Properties.Name -contains 'value') { $raw = $raw.value }
foreach ($s in $raw) {
    Add-Forbidden $s.id; Add-Forbidden $s.correlationId; Add-Forbidden $s.userId; Add-Forbidden $s.userDisplayName
    Add-Forbidden $s.uniqueTokenIdentifier; Add-Forbidden $s.originalRequestId
    if ($s.deviceDetail) { Add-Forbidden $s.deviceDetail.deviceId; Add-Forbidden $s.deviceDetail.displayName }
}
$signIns = foreach ($s in ($raw | Sort-Object createdDateTime)) {
    $t = ([datetime]$s.createdDateTime).ToUniversalTime()
    if ($t -gt $IncidentEndUtc) { continue }
    if ($s.status.errorCode -ne 0) { continue }
    $isAttackIp = $s.ipAddress -in @($AttackIp, $RegistrationIp)
    $isDeviceCode = ($s.authenticationProtocol -eq "deviceCode") -or ($s.originalTransferMethod -eq "deviceCodeFlow")
    if (-not ($isAttackIp -or $isDeviceCode)) { continue }
    $detail = (@($s.authenticationDetails) | ForEach-Object { $_.authenticationStepResultDetail } |
        Where-Object { $_ -like "MFA*" } | Select-Object -First 1)
    [pscustomobject]@{
        TimeUtc                = Format-Utc $t
        App                    = $s.appDisplayName
        IP                     = Get-SafeIp $s.ipAddress
        AuthenticationProtocol = $s.authenticationProtocol
        OriginalTransferMethod = $s.originalTransferMethod
        Interactive            = $s.isInteractive
        Session                = Get-SafeSession $s.sessionId
        Device                 = Get-SafeDevice $s.deviceDetail.displayName
        Managed                = $s.deviceDetail.isManaged
        Compliant              = $s.deviceDetail.isCompliant
        MfaDetail              = $detail
    }
}

# ---------- 3. device registration audit ----------
Write-Host "Reading directory audit..." -ForegroundColor Cyan
$dirRows = @(Import-Csv -LiteralPath (Get-SourcePath $DirectoryAuditFile))
foreach ($r in $dirRows) {
    Add-Forbidden $r.CorrelationId; Add-Forbidden $r.AuditId; Add-Forbidden $r.InitiatorUserId
    foreach ($part in ($r.Targets -split '[:;]')) { Add-Forbidden $part }
}
$deviceEvents = foreach ($r in $dirRows) {
    if ($r.Activity -ne "Register device") { continue }
    $name = ($r.Targets -split ':')[1]
    if (-not $deviceMap.ContainsKey($name) -or $deviceMap[$name] -notlike "DESKTOP-ROGUE*") { continue }
    [pscustomobject]@{
        TimeUtc  = Format-Utc (ConvertTo-Utc $r.ActivityDateTimeUtc)
        Activity = $r.Activity
        Device   = $deviceMap[$name]
        SourceIP = Get-SafeIp $r.InitiatorIP
    }
}
$deviceEvents = @($deviceEvents | Sort-Object TimeUtc)

# ---------- 4. inbox rules ----------
Write-Host "Reading inbox-rule changes..." -ForegroundColor Cyan
$ruleRows = @(Import-Csv -LiteralPath (Get-SourcePath $InboxRuleFile)) | Sort-Object { ConvertTo-Utc $_.CreationTimeUtc }
$ruleNo = 0
$rules = foreach ($r in $ruleRows) {
    Add-Forbidden $r.AuditRecordId; Add-Forbidden $r.ObjectId; Add-Forbidden $r.Actor; Add-Forbidden $r.MailboxOwner
    $p = @{}
    foreach ($kv in ($r.Parameters -split ';\s*')) { $k, $v = $kv -split '=', 2; if ($k) { $p[$k.Trim()] = "$v".Trim() } }
    if ($p.ContainsKey('FromAddressContainsWords')) { foreach ($w in ($p["FromAddressContainsWords"] -split ';')) { Add-Forbidden $w; Add-Forbidden ($w -replace '^@', '') } }
    if ($p.ContainsKey('Name')) { Add-Forbidden $p.Name }
    if ($p.ContainsKey('Identity')) { Add-Forbidden $p["Identity"]; foreach ($part in ($p["Identity"] -split '\\')) { Add-Forbidden $part } }
    if ($r.Operation -eq "New-InboxRule") {
        $ruleNo++
        $condition = if ($p.ContainsKey('FromAddressContainsWords')) { "From contains <one external correspondent>" } else { "All incoming messages" }
        $actions = @()
        if ($p['MoveToFolder']) { $actions += "Move to $($p['MoveToFolder'])" }
        if ($p['MarkAsRead'] -eq 'True') { $actions += "Mark as read" }
        if ($p['DeleteMessage'] -eq 'True') { $actions += "Delete" }
        if ($p['ForwardTo'] -or $p['RedirectTo']) { $actions += "Forward/redirect" }
        if ($p['StopProcessingRules'] -eq 'True') { $actions += "Stop processing more rules" }
        $rule = "Owner-name rule $ruleNo"
    }
    else {
        $condition = ""; $actions = @("Rule removed"); $rule = "(removal)"
    }
    [pscustomobject]@{
        TimeUtc   = Format-Utc (ConvertTo-Utc $r.CreationTimeUtc)
        Operation = $r.Operation
        Rule      = $rule
        Condition = $condition
        Actions   = $actions -join "; "
        SourceIP  = Get-SafeIp $r.ClientIP
        Session   = Get-SafeSession $r.SessionId
    }
}

# ---------- 5. mailbox actions and sends from the attack IP ----------
Write-Host "Reading mailbox audit (large file)..." -ForegroundColor Cyan
function Select-AttackAudit([string]$Path, [string[]]$Operations) {
    foreach ($r in (Import-Csv -LiteralPath $Path)) {
        if ((Get-BareIp $r.ClientIP) -ne $AttackIp) { continue }
        if ($Operations -and $r.Operation -notin $Operations) { continue }
        $t = ConvertTo-Utc $r.CreationTimeUtc
        if ($t -gt $IncidentEndUtc) { continue }
        Add-Forbidden $r.AuditRecordId; Add-Forbidden $r.ObjectId; Add-Forbidden $r.InternetMessageId; Add-Forbidden $r.SessionId
        [pscustomobject]@{
            TimeUtc   = Format-Utc $t
            Operation = $r.Operation
            Client    = if ($r.ClientInfo -match 'OWA|Outlook-?Web|Client=OWA') { "Outlook on the web" } elseif ($r.ClientInfo) { "Other client" } else { "" }
            Folder    = ($r.FolderPath -replace '^\\', '')
            SourceIP  = Get-SafeIp $r.ClientIP
            Session   = Get-SafeSession $r.SessionId
        }
    }
}
$mailbox = @(Select-AttackAudit (Get-SourcePath $MailboxActionFile) @("MailItemsAccessed", "Create", "Update", "MoveToDeletedItems", "SoftDelete", "HardDelete", "Move")) | Sort-Object TimeUtc
foreach ($m in $mailbox) { if ($m.Folder -notin @("Inbox", "Sent Items", "Deleted Items", "Recoverable Items\Deletions", "Drafts", "")) { $m.Folder = "<other folder>" } }
$sends = @(Select-AttackAudit (Get-SourcePath $SendFile) @("Send", "SendAs")) | Sort-Object TimeUtc
foreach ($s in $sends) { $s.Folder = "" }

# ---------- 6. message trace ----------
Write-Host "Reading campaign message trace..." -ForegroundColor Cyan
$recipientMap = @{}; $rNext = 1
$trace = foreach ($r in (Import-Csv -LiteralPath (Get-SourcePath $TraceFile))) {
    if ($r.Subject -ne $CampaignSubject) { continue }
    Add-Forbidden $r.RecipientAddress; Add-Forbidden $r.MessageTraceId; Add-Forbidden $r.MessageId; Add-Forbidden $r.SenderAddress
    $key = $r.RecipientAddress.ToLowerInvariant()
    if (-not $recipientMap.ContainsKey($key)) { $recipientMap[$key] = "R{0:000}" -f $rNext; $rNext++ }
    [pscustomobject]@{
        ReceivedUtc = Format-Utc (ConvertTo-Utc $r.Received)
        Recipient   = $recipientMap[$key]
        IsSelf      = [bool]($SelfAddress | Where-Object { $_ -ieq $r.RecipientAddress })
        Status      = $r.Status
        FromIP      = Get-SafeIp $r.FromIP
        Subject     = $CampaignSubject
    }
}

# ---------- 7. containment ----------
Write-Host "Reading containment events (unified audit is large)..." -ForegroundColor Cyan
$containment = [System.Collections.Generic.List[object]]::new()
foreach ($r in $dirRows) {
    $t = ConvertTo-Utc $r.ActivityDateTimeUtc
    if ($r.Activity -eq "Change user password") {
        $containment.Add([pscustomobject]@{ TimeUtc = Format-Utc $t; Action = "Password changed"; Target = "alex@somedomainsomewhere.com" })
    }
    elseif ($r.Activity -eq "Update device") {
        $name = ($r.Targets -split ':')[1]
        if ($deviceMap.ContainsKey($name) -and $deviceMap[$name] -like "DESKTOP-ROGUE*") {
            $containment.Add([pscustomobject]@{ TimeUtc = Format-Utc $t; Action = "Device disabled"; Target = $deviceMap[$name] })
        }
    }
}
foreach ($r in $rules | Where-Object Operation -eq "Remove-InboxRule") {
    $containment.Add([pscustomobject]@{ TimeUtc = $r.TimeUtc; Action = "Malicious inbox rule removed"; Target = "Inbox rule" })
}
$uaPath = Join-Path $EvidenceRoot $UnifiedAuditFile
if (Test-Path -LiteralPath $uaPath) {
    $seen = @{}
    foreach ($m in (Select-String -LiteralPath $uaPath -Pattern 'StsRefreshTokenValidFrom' -SimpleMatch)) {
        $ts = [regex]::Match($m.Line, '\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2} [AP]M').Value
        if ($ts -and -not $seen.ContainsKey($ts)) {
            $seen[$ts] = $true
            $containment.Add([pscustomobject]@{ TimeUtc = Format-Utc (ConvertTo-Utc $ts); Action = "Refresh tokens revoked (StsRefreshTokenValidFrom reset)"; Target = "alex@somedomainsomewhere.com" })
        }
    }
}
else { Write-Warning "Unified audit file not found; token revocation rows omitted." }
$containment = @($containment | Sort-Object TimeUtc, Action -Unique)

# ---------- 8. write ----------
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$outputs = [ordered]@{
    "SignIns.csv"        = $signIns
    "Devices.csv"        = $devices
    "DeviceEvents.csv"   = $deviceEvents
    "InboxRules.csv"     = $rules
    "MailboxActions.csv" = $mailbox
    "Sends.csv"          = $sends
    "Trace.csv"          = $trace
    "Containment.csv"    = $containment
}
foreach ($name in $outputs.Keys) {
    @($outputs[$name]) | Export-Csv -LiteralPath (Join-Path $OutputPath $name) -NoTypeInformation -Encoding utf8
}

# ---------- 9. leak test ----------
Write-Host "Running leak test..." -ForegroundColor Cyan
$hits = [System.Collections.Generic.List[string]]::new()
$allowed = @($CampaignSubject)
foreach ($name in $outputs.Keys) {
    $text = Get-Content -LiteralPath (Join-Path $OutputPath $name) -Raw
    if (-not $text) { continue }
    foreach ($f in $script:Forbidden) {
        if ($f -in @("True", "False", "Windows", "AzureAd", "None", "Inbox")) { continue }
        $check = $text
        foreach ($a in $allowed) { $check = $check.Replace($a, "") }
        if ($check.IndexOf($f, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hits.Add("$name contains an original identifier ($($f.Length) chars, starts '$($f.Substring(0,2))')") }
    }
    if ($text -match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') { $hits.Add("$name contains a GUID") }
    foreach ($e in [regex]::Matches($text, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')) {
        if ($e.Value -notlike "*@somedomainsomewhere.com") { $hits.Add("$name contains a non-somedomainsomewhere email address") }
    }
    foreach ($ip in [regex]::Matches($text, '\b\d{1,3}(\.\d{1,3}){3}\b')) {
        if ($ip.Value -notmatch '^(192\.0\.2|198\.51\.100|203\.0\.113)\.') { $hits.Add("$name contains a non-documentation IPv4 address") }
    }
}
$hits = @($hits | Select-Object -Unique)
if ($hits.Count -gt 0) {
    $hits | ForEach-Object { Write-Host "  LEAK: $_" -ForegroundColor Red }
    Remove-Item -LiteralPath $OutputPath -Recurse -Force
    throw "Leak test failed; the sanitized output was deleted. Fix the mapping and run again."
}

$manifest = [ordered]@{
    BuiltUtc        = (Get-Date).ToUniversalTime().ToString("o")
    Sources         = @($SignInFile, $DeviceFile, $DirectoryAuditFile, $InboxRuleFile, $MailboxActionFile, $SendFile, $TraceFile, $UnifiedAuditFile)
    RowCounts       = [ordered]@{}
    LeakTest        = "Passed"
    IdentifiersChecked = $script:Forbidden.Count
}
foreach ($name in $outputs.Keys) { $manifest.RowCounts[$name] = @($outputs[$name]).Count }
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutputPath "Manifest.json") -Encoding utf8

Write-Host ""
Write-Host "Sanitized dataset written to $OutputPath" -ForegroundColor Green
$manifest.RowCounts.GetEnumerator() | ForEach-Object { "  {0,-20} {1,6} rows" -f $_.Key, $_.Value }
Write-Host ("Leak test passed ({0} original identifiers checked). Review the files before public use." -f $script:Forbidden.Count) -ForegroundColor Green
