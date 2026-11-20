<#
.SYNOPSIS
    Replays a Microsoft 365 account compromise as a step-by-step attack chain from sanitized
    evidence, for live demonstration.

.DESCRIPTION
    Show-IncidentTimeline.ps1 reads the dataset produced by New-SanitizedIncidentDataset.ps1 and
    walks an audience through the correlated evidence one act at a time. It reads local CSV files
    only: no sign-in, no network, no tenant access.

    1. Initial access: successful device-code sign-ins and the MFA detail they carry.
    2. Persistence: rogue device registrations and how many seconds after the sign-in they began.
    3. The thread: the session identifier that links July activity to the August campaign.
    4. Concealment: the inbox rules the attacker created, with conditions and actions.
    5. Impact: the audited sends, how many, and how fast.
    6. Anti-forensics: the campaign items moved, soft-deleted, and hard-deleted.
    7. Blast radius: targeted, delivered, failed, and external-notification counts computed
       from recipient-level message trace.
    8. Containment: the recorded containment actions and how long after the campaign each came.

    PRESENTING:
    Press Enter to advance between acts. Use -NoPause to print the whole chain at once (the
    recovery path if a keypress misbehaves on stage). Use -Act to jump straight to one act.
    Times are shown in UTC and in the zone named by -TimeZoneId.

    DATA EXPECTED IN EvidencePath:
    SignIns.csv, Devices.csv, DeviceEvents.csv, InboxRules.csv, MailboxActions.csv, Sends.csv,
    Trace.csv, Containment.csv (as written by New-SanitizedIncidentDataset.ps1).

.PARAMETER EvidencePath
    Folder that holds the sanitized dataset. Default: Sanitized-Evidence beside this script.

.PARAMETER TimeZoneId
    Time zone for the second time column. Windows or IANA ID. Default: Pacific Standard Time
    (the time zone where the incident happened).

.PARAMETER Act
    Shows only the listed acts (1-8). Default: all acts in order.

.PARAMETER NoPause
    Prints every act without waiting for Enter.

.EXAMPLE
    .\Show-IncidentTimeline.ps1

    Runs the full eight-act walkthrough from .\Sanitized-Evidence, pausing between acts.

.EXAMPLE
    .\Show-IncidentTimeline.ps1 -Act 3,7

    Shows only the session thread and the blast-radius math, for a short version of the demo.

.EXAMPLE
    .\Show-IncidentTimeline.ps1 -NoPause | Tee-Object -FilePath .\Demo1-Output.txt

    Prints the whole chain at once and saves a copy.

.NOTES
    Script Name  : Show-IncidentTimeline.ps1
    Version      : 1.0.0
    Author       : John O'Neill Sr.
    Company      : Azure Innovators
    Website      : https://www.azureinnovators.com
    Blog         : https://azureinnovators.com/blog

    Prerequisites:
    - PowerShell 7 or later; a console at least 120 characters wide (font 18-20 pt on stage)
    - A dataset built by New-SanitizedIncidentDataset.ps1 and reviewed before public use

    Change Log:
    v1.0.0 - 2026-11-05 - Initial release for the Live! 360 Orlando 2026 keynote demo.
#>

[CmdletBinding()]
param(
    [string]$EvidencePath = (Join-Path $PSScriptRoot "Sanitized-Evidence"),
    [string]$TimeZoneId = "Pacific Standard Time",
    [ValidateRange(1, 8)][int[]]$Act = 1..8,
    [switch]$NoPause
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Import-Evidence([string]$Name) {
    $p = Join-Path $EvidencePath $Name
    if (-not (Test-Path -LiteralPath $p)) { throw "Missing $Name in $EvidencePath. Run New-SanitizedIncidentDataset.ps1 first." }
    @(Import-Csv -LiteralPath $p)
}

try { $tz = [TimeZoneInfo]::FindSystemTimeZoneById($TimeZoneId) }
catch { $tz = [TimeZoneInfo]::Utc; Write-Warning "Time zone '$TimeZoneId' not found; showing UTC twice." }
$tzLabel = if ($tz.Id -eq "UTC") { "UTC" } else { ($tz.StandardName -split ' ' | ForEach-Object { $_[0] }) -join '' }

function Get-Utc([string]$Value) { [datetime]::Parse($Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal) }
function Format-When([string]$Value) {
    $u = Get-Utc $Value
    $l = [TimeZoneInfo]::ConvertTimeFromUtc($u, $tz)
    $label = if ($tz.IsDaylightSavingTime($l) -and $tzLabel -match 'S') { $tzLabel -replace 'S', 'D' } else { $tzLabel }
    "{0:MMM dd HH:mm:ss} UTC  ({1:h:mm:ss tt} {2})" -f $u, $l, $label
}
function Format-Span([timespan]$Span) {
    if ($Span.TotalDays -ge 1) { return "{0:N1} days" -f $Span.TotalDays }
    if ($Span.TotalHours -ge 1) { return "{0:N1} hours" -f $Span.TotalHours }
    if ($Span.TotalMinutes -ge 1) { return "{0}m {1}s" -f [int][math]::Floor($Span.TotalMinutes), $Span.Seconds }
    return "{0}s" -f [int]$Span.TotalSeconds
}
function Write-Act([int]$Number, [string]$Title, [string]$Subtitle) {
    Write-Host ""
    Write-Host ("=" * 100) -ForegroundColor DarkMagenta
    Write-Host (" ACT {0}  {1}" -f $Number, $Title.ToUpperInvariant()) -ForegroundColor Magenta
    if ($Subtitle) { Write-Host ("        {0}" -f $Subtitle) -ForegroundColor DarkGray }
    Write-Host ("=" * 100) -ForegroundColor DarkMagenta
}
function Write-Line([string]$When, [string]$Text, [ConsoleColor]$Color = "Gray") {
    Write-Host ("  {0}  " -f $When) -NoNewline -ForegroundColor DarkCyan
    Write-Host $Text -ForegroundColor $Color
}
function Write-Point([string]$Text) { Write-Host ""; Write-Host ("  >> {0}" -f $Text) -ForegroundColor Yellow }
function Wait-Presenter { if (-not $NoPause) { Write-Host ""; [void](Read-Host "  [Enter] next") } }

$signIns = Import-Evidence "SignIns.csv"
$devices = Import-Evidence "Devices.csv"
$deviceEvents = Import-Evidence "DeviceEvents.csv"
$rules = Import-Evidence "InboxRules.csv"
$mailbox = Import-Evidence "MailboxActions.csv"
$sends = Import-Evidence "Sends.csv"
$trace = Import-Evidence "Trace.csv"
$containment = Import-Evidence "Containment.csv"

if (-not $NoPause) { try { Clear-Host } catch { } }   # redirected output has no console to clear
Write-Host ""
Write-Host "  MICROSOFT 365 ACCOUNT COMPROMISE: THE ATTACK CHAIN FROM THE EVIDENCE" -ForegroundColor White
Write-Host "  Sanitized replay. IPs are documentation ranges; devices, sessions, people are placeholders." -ForegroundColor DarkGray
Write-Host ("  Source: .\{0}" -f (Split-Path (Resolve-Path $EvidencePath) -Leaf)) -ForegroundColor DarkGray   # leaf only: full paths can reveal names on screen
Wait-Presenter

$firstDeviceCode = $signIns | Where-Object AuthenticationProtocol -eq "deviceCode" | Sort-Object TimeUtc | Select-Object -First 1
$campaignStart = ($sends | Sort-Object TimeUtc | Select-Object -First 1).TimeUtc

if (1 -in $Act) {
    Write-Act 1 "Initial access" "A legitimate sign-in flow, completed for somebody else's client"
    foreach ($s in ($signIns | Where-Object { $_.AuthenticationProtocol -eq "deviceCode" -and $_.TimeUtc -lt "2026-07-23" })) {
        Write-Line (Format-When $s.TimeUtc) ("{0,-34} protocol={1}  device={2}" -f $s.App, $s.AuthenticationProtocol, $s.Device)
    }
    $firstAttacker = $signIns | Where-Object IP -eq "203.0.113.66" | Sort-Object TimeUtc | Select-Object -First 1
    Write-Host ""
    Write-Line (Format-When $firstAttacker.TimeUtc) ("{0,-34} from {1} on {2}" -f $firstAttacker.App, $firstAttacker.IP, $firstAttacker.Device) Red
    Write-Line "                                    " ("OriginalTransferMethod = {0}" -f $firstAttacker.OriginalTransferMethod) Red
    Write-Line "                                    " ("Authentication detail  = ""{0}""" -f $firstAttacker.MfaDetail) Red
    Write-Point "MFA was not bypassed. It was satisfied once, and every later token inherited the claim."
    Wait-Presenter
}

if (2 -in $Act) {
    Write-Act 2 "Persistence" "Register a device, and the attacker's session looks like one of yours"
    $t0 = Get-Utc $firstDeviceCode.TimeUtc
    foreach ($e in $deviceEvents) {
        $delta = (Get-Utc $e.TimeUtc) - $t0
        $d = $devices | Where-Object Device -eq $e.Device
        Write-Line (Format-When $e.TimeUtc) ("{0} from {1}  build {2}  managed={3}  +{4}" -f $e.Device, $e.SourceIP, $d.OSBuild, $d.Managed, (Format-Span $delta))
    }
    Write-Host "  (+ = time since the first device-code sign-in)" -ForegroundColor DarkGray
    $builds = @($devices.OSBuild | Select-Object -Unique)
    Write-Point ("{0} rogue devices, {1} distinct Windows build(s), none managed or compliant." -f $devices.Count, $builds.Count)
    Wait-Presenter
}

if (3 -in $Act) {
    Write-Act 3 "The thread" "One session identifier ties two weeks together"
    $events = @()
    $events += $signIns | Where-Object { $_.IP -eq "203.0.113.66" -or $_.AuthenticationProtocol -eq "deviceCode" } | ForEach-Object { [pscustomobject]@{ TimeUtc = $_.TimeUtc; Session = $_.Session; What = "Sign-in: $($_.App)" } }
    $events += $rules | Where-Object Operation -eq "New-InboxRule" | ForEach-Object { [pscustomobject]@{ TimeUtc = $_.TimeUtc; Session = $_.Session; What = "Inbox rule created" } }
    $events += $mailbox | Where-Object Session | ForEach-Object { [pscustomobject]@{ TimeUtc = $_.TimeUtc; Session = $_.Session; What = "Mailbox: $($_.Operation)" } }
    $events += $sends | Where-Object Session | ForEach-Object { [pscustomobject]@{ TimeUtc = $_.TimeUtc; Session = $_.Session; What = "Send" } }
    $campaignSession = ($events | Where-Object { $_.TimeUtc -ge $campaignStart } | Group-Object Session | Sort-Object Count -Descending | Select-Object -First 1).Name
    $thread = @($events | Where-Object Session -eq $campaignSession | Sort-Object TimeUtc)
    $first = $thread[0]; $last = $thread[-1]
    Write-Line (Format-When $first.TimeUtc) ("{0} first seen   {1}" -f $campaignSession, $first.What) Green
    foreach ($g in ($thread | Group-Object { $_.TimeUtc.Substring(0, 10) })) {
        Write-Line ("{0,-36}" -f $g.Name) ("{0,4} events   {1}" -f $g.Count, ((($g.Group.What | ForEach-Object { ($_ -split ':')[0] }) | Select-Object -Unique) -join ", "))
    }
    Write-Line (Format-When $last.TimeUtc) ("{0} last seen    {1}" -f $campaignSession, $last.What) Green
    Write-Point ("{0} spans {1}. Correlate on the session, not on IP geolocation." -f $campaignSession, (Format-Span ((Get-Utc $last.TimeUtc) - (Get-Utc $first.TimeUtc))))
    Wait-Presenter
}

if (4 -in $Act) {
    Write-Act 4 "Concealment" "MITRE ATT&CK T1564.008: Email Hiding Rules"
    foreach ($r in ($rules | Where-Object Operation -eq "New-InboxRule")) {
        Write-Line (Format-When $r.TimeUtc) ("{0}" -f $r.Rule) Red
        Write-Line "                                    " ("  IF   {0}" -f $r.Condition)
        Write-Line "                                    " ("  THEN {0}" -f $r.Actions)
    }
    Write-Point "Rule 2 sends every new message to a folder nobody opens, already marked read: the silent inbox."
    Wait-Presenter
}

if (5 -in $Act) {
    Write-Act 5 "Impact" "Authenticated sends from the real mailbox, not a forged header"
    foreach ($s in $sends) { Write-Line (Format-When $s.TimeUtc) ("{0,-8} via {1} from {2}" -f $s.Operation, $s.Client, $s.SourceIP) }
    $span = (Get-Utc ($sends | Sort-Object TimeUtc | Select-Object -Last 1).TimeUtc) - (Get-Utc $campaignStart)
    Write-Point ("{0} sends in {1}." -f $sends.Count, (Format-Span $span))
    Wait-Presenter
}

if (6 -in $Act) {
    Write-Act 6 "Anti-forensics" "Covering tracks in Sent Items"
    $cleanup = @($mailbox | Where-Object { $_.Operation -in @("MoveToDeletedItems", "SoftDelete", "HardDelete") -and $_.TimeUtc -ge $campaignStart } | Sort-Object TimeUtc)
    foreach ($g in ($cleanup | Group-Object Operation | Sort-Object { ($_.Group | Sort-Object TimeUtc | Select-Object -First 1).TimeUtc })) {
        $f = $g.Group | Sort-Object TimeUtc | Select-Object -First 1
        Write-Line (Format-When $f.TimeUtc) ("{0,-20} x{1}" -f $g.Name, $g.Count)
    }
    if ($cleanup.Count) {
        $span = (Get-Utc $cleanup[-1].TimeUtc) - (Get-Utc $cleanup[0].TimeUtc)
        $after = (Get-Utc $cleanup[0].TimeUtc) - (Get-Utc ($sends | Sort-Object TimeUtc | Select-Object -Last 1).TimeUtc)
        Write-Point ("Cleanup began {0} after the last send and finished in {1}. Sent Items alone would have shown nothing." -f (Format-Span $after), (Format-Span $span))
    }
    $reads = @($mailbox | Where-Object Operation -eq "MailItemsAccessed").Count
    Write-Host ("  Also: {0} MailItemsAccessed audit records from the attacker. They aggregate, so this is not a message count." -f $reads) -ForegroundColor DarkGray
    Wait-Presenter
}

if (7 -in $Act) {
    Write-Act 7 "Blast radius" "Recipient-level message trace, not assumptions"
    $byRecipient = $trace | Group-Object Recipient
    $targeted = $byRecipient.Count
    $delivered = @($byRecipient | Where-Object { $_.Group.Status -contains "Delivered" })
    $failed = $targeted - $delivered.Count
    $notify = @($delivered | Where-Object { ($_.Group | Select-Object -First 1).IsSelf -ne "True" }).Count
    "{0,-40}{1,8}" -f "  Trace rows", $trace.Count | Write-Host -ForegroundColor DarkGray
    "{0,-40}{1,8}" -f "  Unique recipients targeted", $targeted | Write-Host -ForegroundColor White
    "{0,-40}{1,8}" -f "  Unique recipients delivered", $delivered.Count | Write-Host -ForegroundColor White
    "{0,-40}{1,8}" -f "  Unique recipients failed", $failed | Write-Host -ForegroundColor White
    "{0,-40}{1,8}" -f "  Delivered, excluding my own addresses", $notify | Write-Host -ForegroundColor Yellow
    Write-Point "A target list is not a delivery list, and a delivered message is not a compromised recipient."
    Wait-Presenter
}

if (8 -in $Act) {
    Write-Act 8 "Containment" "Every action timestamped, every claim provable"
    $c0 = Get-Utc $campaignStart
    Write-Host "  (+ = time since the campaign's first send)" -ForegroundColor DarkGray
    foreach ($c in $containment) {
        $action = $c.Action -replace ' \(StsRefreshTokenValidFrom reset\)', ''
        Write-Line (Format-When $c.TimeUtc) ("{0,-30} {1,-30} +{2}" -f $action, $c.Target, (Format-Span ((Get-Utc $c.TimeUtc) - $c0))) Green
    }
    $firstPw = $containment | Where-Object Action -eq "Password changed" | Select-Object -First 1
    $firstRevoke = $containment | Where-Object Action -like "Refresh tokens revoked*" | Select-Object -First 1
    if ($firstPw -and $firstRevoke) {
        Write-Point ("Password first changed {0} before the refresh tokens were revoked. Revoke sessions first." -f (Format-Span ((Get-Utc $firstRevoke.TimeUtc) - (Get-Utc $firstPw.TimeUtc))))
    }
}

Write-Host ""
Write-Host "  End of replay." -ForegroundColor DarkGray
