<#
.SYNOPSIS
Collects Microsoft 365 forensic evidence and validates emergency-access and device-code controls.

.DESCRIPTION
Invoke-M365IncidentResponse.ps1 provides a single, reusable entry point for Microsoft Graph,
Exchange Online, Microsoft Purview audit, message trace, device, application-consent, and
Conditional Access evidence collection. It also audits emergency-access account readiness,
evaluates those accounts against Conditional Access, and manages the staged rollout and proof of
a policy that blocks device code flow.

The default Collect action is read-only. It creates a timestamped evidence directory containing
raw JSON, analyst-friendly CSV files, a collection transcript, an evidence index, error records,
run metadata, and SHA-256 hashes.

Conditional Access remediation is deliberately separated into explicit actions. Creating a
report-only policy and enabling a policy never occurs during the Collect action.

.PARAMETER Action
The operation to perform:

Collect
    Performs read-only forensic collection.

CreateDeviceCodePolicyReportOnly
    Creates a report-only Conditional Access policy that blocks device code flow and exports
    configuration and What If evidence.

ExportDeviceCodePolicyProof
    Exports the named policy and runs a Conditional Access What If evaluation.

EnableDeviceCodePolicy
    Enables an existing policy after validation. Requires ConfirmPolicyEnable.

CollectDeviceCodePolicyEnforcementEvidence
    Searches recent sign-in logs for a device-code sign-in blocked by the named policy.

AuditEmergencyAccessAccounts
    Audits the target administrator and supplied emergency-access accounts for Microsoft Entra
    roles, permanent active Global Administrator status, cloud-only state, authentication methods,
    and direct membership in groups excluded by the named device-code policy. A reported FIDO2
    method proves registration only; independently test the assigned physical key.

AuditEmergencyAccessConditionalAccess
    Runs a read-only Conditional Access What If scenario matrix for every supplied emergency-access
    account and reports every enabled, report-only, or unknown-state policy that applies. This is a
    broad configuration test, not a substitute for an operational sign-in drill and alert test.

.PARAMETER UserPrincipalName
The user principal name or SMTP address of the account under investigation.

.PARAMETER StartUtc
Beginning of the forensic search interval. Specify an ISO 8601 value with a UTC offset.

.PARAMETER EndUtc
Exclusive end of the forensic search interval. Specify an ISO 8601 value with a UTC offset.

.PARAMETER OutputRoot
Parent directory for timestamped evidence runs. The default is Evidence-Runs beside this script.

.PARAMETER Components
Read-only components to collect. Valid values are Identity, DirectoryAudit, Applications,
Devices, ConditionalAccess, Mailbox, UnifiedAudit, and MessageTrace.

.PARAMETER SuspectIpAddress
One or more source IP addresses to correlate against Microsoft Entra sign-in records.

.PARAMETER SuspectDeviceId
One or more Microsoft Entra device IDs to flag in device reports.

.PARAMETER CampaignSubject
An exact outbound-message subject to report separately, including unique targets and delivery status.

.PARAMETER PolicyName
Conditional Access policy name used by the policy actions.

.PARAMETER TestUserUpn
Nonprivileged test user used for What If and enforcement evidence. Defaults to UserPrincipalName.

.PARAMETER EmergencyAccessUpn
Exact user principal names of the cloud-only emergency-access accounts to audit or exclude when
creating the report-only device-code policy. Supply at least two accounts for a production design.
Use dedicated .onmicrosoft.com identities, verify permanent active Global Administrator assignment,
register distinct phishing-resistant credentials, and test each account independently.

.PARAMETER ApprovedDeviceCodeGroupId
Optional group object IDs excluded from the device-code policy for documented dependencies.

.PARAMETER ExcludeDeviceRegistrationService
Excludes Microsoft Device Registration Service from the policy. Use only after confirming a
legitimate device-code registration dependency in sign-in logs.

.PARAMETER ConfirmPolicyEnable
Required safety acknowledgement before EnableDeviceCodePolicy can change policy state.

.PARAMETER SignInLookbackMinutes
Lookback used by CollectDeviceCodePolicyEnforcementEvidence.

.PARAMETER TestResourceAppId
Resource application used in the Conditional Access What If evaluation. Defaults to Exchange Online.

.PARAMETER DisconnectWhenFinished
Disconnects Exchange Online and Microsoft Graph after the run. By default, sessions remain connected.

.OUTPUTS
For every action, the script writes a summary object containing Action, TargetUser, and
OutputDirectory. Emergency-access and Conditional Access actions also write readiness or proof
objects to the success stream. The authoritative record is the timestamped evidence directory.

.EXAMPLE
./Invoke-M365IncidentResponse.ps1 -Action Collect `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -StartUtc "2026-07-22T00:00:00Z" `
    -EndUtc ([datetimeoffset]::UtcNow) `
    -SuspectIpAddress "203.0.113.20" `
    -SuspectDeviceId "11111111-2222-3333-4444-555555555555" `
    -CampaignSubject "Suspicious campaign subject"

Performs a comprehensive read-only collection and creates a new timestamped evidence directory.

.EXAMPLE
./Invoke-M365IncidentResponse.ps1 -Action Collect `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -StartUtc "2026-07-22T00:00:00Z" `
    -EndUtc ([datetimeoffset]::UtcNow) `
    -Components Identity,DirectoryAudit,Applications,Devices,ConditionalAccess

Collects only Microsoft Graph and Microsoft Entra evidence.

.EXAMPLE
./Invoke-M365IncidentResponse.ps1 -Action CreateDeviceCodePolicyReportOnly `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -TestUserUpn "ca-test@somedomainsomewhere.com" `
    -EmergencyAccessUpn "breakglass1@somedomainsomewhere.com","breakglass2@somedomainsomewhere.com"

Creates the device-code block policy in report-only mode and exports policy/What If evidence.

.EXAMPLE
./Invoke-M365IncidentResponse.ps1 -Action EnableDeviceCodePolicy `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -TestUserUpn "ca-test@somedomainsomewhere.com" `
    -ConfirmPolicyEnable -Confirm

Validates the device-code policy, prompts for confirmation, enables it, and exports fresh proof.

.EXAMPLE
./Invoke-M365IncidentResponse.ps1 -Action CollectDeviceCodePolicyEnforcementEvidence `
    -UserPrincipalName "alex@somedomainsomewhere.com" `
    -TestUserUpn "ca-test@somedomainsomewhere.com" `
    -SignInLookbackMinutes 120

Collects a recent controlled device-code test and determines whether the named policy blocked it.

.EXAMPLE
./Invoke-M365IncidentResponse.ps1 -Action AuditEmergencyAccessAccounts `
    -UserPrincipalName "founding-admin@somedomainsomewhere.com" `
    -EmergencyAccessUpn "emergency01@somedomainsomewhere.onmicrosoft.com","emergency02@somedomainsomewhere.onmicrosoft.com"

Creates a read-only emergency-access account and Entra role comparison report.

.EXAMPLE
./Invoke-M365IncidentResponse.ps1 -Action AuditEmergencyAccessAccounts `
    -UserPrincipalName "founding-admin@somedomainsomewhere.com" `
    -EmergencyAccessUpn @(
        "emergency01@somedomainsomewhere.onmicrosoft.com",
        "emergency02@somedomainsomewhere.onmicrosoft.com"
    )

Reruns the readiness audit after security-key registration. Confirm AccountEnabled, CloudOnly,
UsesOnMicrosoftDomain, PermanentActiveDirectGA, and HasFido2OrCertificateMethod are True for both
emergency accounts. Then test each physical key in a clean private-browser session and confirm the
expected sign-in alert; those operational checks cannot be proven by registration metadata alone.

.EXAMPLE
./Invoke-M365IncidentResponse.ps1 -Action AuditEmergencyAccessConditionalAccess `
    -UserPrincipalName "founding-admin@somedomainsomewhere.com" `
    -EmergencyAccessUpn "emergency01@somedomainsomewhere.onmicrosoft.com","emergency02@somedomainsomewhere.onmicrosoft.com" `
    -SuspectIpAddress "203.0.113.20"

Evaluates the emergency accounts against current Conditional Access policies across common admin
resources, clients, platforms, risk states, device code flow, security-info registration, and the
optional source IP addresses.

.EXAMPLE
Get-Help ./Invoke-M365IncidentResponse.ps1 -Full

Displays the complete workflow, parameter descriptions, examples, outputs, and safety notes.

.NOTES
Run in PowerShell 7 from a trusted administrative workstation. Required modules are
Microsoft.Graph.Authentication and ExchangeOnlineManagement. Required roles and licensing vary by
component; see docs\COLLECTOR.md in this repository.

Recommended emergency-access sequence: audit the accounts, register and independently test distinct
FIDO2 security keys, verify sign-in alerts, rerun the account and Conditional Access audits, review
report-only impact, enable the device-code policy with a dedicated nonadministrator test identity,
and collect an actual blocked-sign-in event as enforcement evidence. Keep at least two emergency
accounts and maintain credential redundancy in separate secure locations.

Version history:
1.2.2 (2026-11-18) Sign-in collection now includes non-interactive sign-ins (signInEventTypes
filter); added a SignInEventTypes column to the flattened sign-in reports
           Exchange sign-in uses -DisableWAM to avoid the Graph/Exchange MSAL clash
1.2.1 (2026-11-16) Fixed the SHA256SUMS.csv "being used by another process" error with a relative
-OutputRoot; removed -NoTypeInformation (obsolete in PowerShell 7)
1.2.0 Device-code policy proof and enforcement actions

The SHA-256 manifest detects later changes to collected files. It does not by itself establish a
complete legal chain of custody.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [ValidateSet(
        "Collect",
        "CreateDeviceCodePolicyReportOnly",
        "ExportDeviceCodePolicyProof",
        "EnableDeviceCodePolicy",
        "CollectDeviceCodePolicyEnforcementEvidence",
        "AuditEmergencyAccessAccounts",
        "AuditEmergencyAccessConditionalAccess"
    )]
    [string]$Action = "Collect",

    [Parameter(Mandatory)]
    [Alias("Mailbox")]
    [ValidateNotNullOrEmpty()]
    [string]$UserPrincipalName,

    [datetimeoffset]$StartUtc = [datetimeoffset]::UtcNow.AddDays(-30),

    [datetimeoffset]$EndUtc = [datetimeoffset]::UtcNow,

    [string]$OutputRoot = (Join-Path $PSScriptRoot "Evidence-Runs"),

    [ValidateSet(
        "Identity",
        "DirectoryAudit",
        "Applications",
        "Devices",
        "ConditionalAccess",
        "Mailbox",
        "UnifiedAudit",
        "MessageTrace"
    )]
    [string[]]$Components = @(
        "Identity",
        "DirectoryAudit",
        "Applications",
        "Devices",
        "ConditionalAccess",
        "Mailbox",
        "UnifiedAudit",
        "MessageTrace"
    ),

    [string[]]$SuspectIpAddress = @(),

    [string[]]$SuspectDeviceId = @(),

    [string]$CampaignSubject,

    [string]$PolicyName = "CA-BLOCK-Device-Code-Flow-All-Users",

    [string]$TestUserUpn,

    [string[]]$EmergencyAccessUpn = @(),

    [string[]]$ApprovedDeviceCodeGroupId = @(),

    [switch]$ExcludeDeviceRegistrationService,

    [switch]$ConfirmPolicyEnable,

    [ValidateRange(5, 1440)]
    [int]$SignInLookbackMinutes = 120,

    [string]$TestResourceAppId = "00000002-0000-0ff1-ce00-000000000000",

    [switch]$DisconnectWhenFinished
)

$ErrorActionPreference = "Stop"
$script:ToolVersion = "1.2.2"
$script:EvidenceIndex = [System.Collections.Generic.List[object]]::new()
$script:CollectionErrors = [System.Collections.Generic.List[object]]::new()
$script:StepResults = [System.Collections.Generic.List[object]]::new()
$script:GraphConnectedByScript = $false
$script:ExchangeConnectedByScript = $false
$script:TranscriptStarted = $false
$script:ResolvedUser = $null
$script:RunDirectory = $null
$script:Paths = @{}

function Write-IncidentLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR")][string]$Level = "INFO"
    )

    $line = "[{0}] [{1}] {2}" -f (Get-Date).ToUniversalTime().ToString("o"), $Level, $Message
    switch ($Level) {
        "WARN"  { Write-Warning $line }
        "ERROR" { Write-Error $line -ErrorAction Continue }
        default { Write-Host $line }
    }
}

function Join-IncidentValues {
    [CmdletBinding()]
    param($Value)

    if ($null -eq $Value) { return $null }
    return (@($Value) | ForEach-Object { $_.ToString() }) -join "; "
}

function Get-SafeFileName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)

    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $result = $Value
    foreach ($character in $invalid) {
        $result = $result.Replace($character, "_")
    }
    return $result
}

function Add-CollectionError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Component,
        [Parameter(Mandatory)][string]$Step,
        [Parameter(Mandatory)]$ErrorRecord
    )

    $exception = $ErrorRecord.Exception
    [void]$script:CollectionErrors.Add([pscustomobject]@{
        TimeUtc              = (Get-Date).ToUniversalTime().ToString("o")
        Component            = $Component
        Step                 = $Step
        Message              = $exception.Message
        ExceptionType        = $exception.GetType().FullName
        FullyQualifiedErrorId = $ErrorRecord.FullyQualifiedErrorId
        ScriptStackTrace     = $ErrorRecord.ScriptStackTrace
    })
}

function Add-EvidenceIndexEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Component,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Path,
        [int]$RecordCount = -1,
        [string]$Source
    )

    $relativePath = [System.IO.Path]::GetRelativePath($script:RunDirectory, $Path)
    [void]$script:EvidenceIndex.Add([pscustomobject]@{
        Component   = $Component
        Description = $Description
        RecordCount = $RecordCount
        Source      = $Source
        RelativePath = $relativePath
    })
}

function Write-JsonEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Data,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Component,
        [Parameter(Mandatory)][string]$Description,
        [int]$RecordCount = -1,
        [string]$Source
    )

    ConvertTo-Json -InputObject $Data -Depth 100 |
        Set-Content -LiteralPath $Path -Encoding utf8
    Add-EvidenceIndexEntry -Component $Component -Description $Description -Path $Path `
        -RecordCount $RecordCount -Source $Source
}

function Export-CsvEvidence {
    [CmdletBinding()]
    param(
        $Data,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Component,
        [Parameter(Mandatory)][string]$Description,
        [string]$Source
    )

    $items = @($Data | Where-Object { $null -ne $_ })
    if ($items.Count -gt 0) {
        $items | Export-Csv -LiteralPath $Path -Encoding utf8
    }
    else {
        Set-Content -LiteralPath $Path -Value "# No records returned" -Encoding utf8
    }

    Add-EvidenceIndexEntry -Component $Component -Description $Description -Path $Path `
        -RecordCount $items.Count -Source $Source
}

function Invoke-CollectionStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Component,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [switch]$Fatal
    )

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-IncidentLog -Message "$Component - $Name"
    try {
        & $ScriptBlock
        $status = "Success"
    }
    catch {
        $status = "Failed"
        Add-CollectionError -Component $Component -Step $Name -ErrorRecord $_
        Write-IncidentLog -Level WARN -Message "$Component - $Name failed: $($_.Exception.Message)"
        if ($Fatal) { throw }
    }
    finally {
        $timer.Stop()
        [void]$script:StepResults.Add([pscustomobject]@{
            Component       = $Component
            Step            = $Name
            Status          = $status
            DurationSeconds = [math]::Round($timer.Elapsed.TotalSeconds, 2)
        })
    }
}

function Initialize-EvidenceRun {
    [CmdletBinding()]
    param()

    if ($EndUtc -le $StartUtc) {
        throw "EndUtc must be later than StartUtc."
    }

    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmssZ")
    $safeUser = Get-SafeFileName -Value $UserPrincipalName
    $runName = "{0}-{1}-{2}" -f $stamp, $Action, $safeUser
    # Resolve to a full path: the manifest step compares full paths, and a relative
    # -OutputRoot such as .\Evidence made it hash SHA256SUMS.csv while writing it (fixed in 1.2.1)
    $script:RunDirectory = Join-Path $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputRoot) $runName

    if (Test-Path -LiteralPath $script:RunDirectory) {
        $script:RunDirectory = "$($script:RunDirectory)-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    }

    $script:Paths = @{
        Run               = Join-Path $script:RunDirectory "00-Run"
        Identity          = Join-Path $script:RunDirectory "01-Identity"
        DirectoryAudit    = Join-Path $script:RunDirectory "02-Directory-Audit"
        Applications      = Join-Path $script:RunDirectory "03-Applications"
        Devices           = Join-Path $script:RunDirectory "04-Devices"
        ConditionalAccess = Join-Path $script:RunDirectory "05-Conditional-Access"
        Mailbox           = Join-Path $script:RunDirectory "06-Mailbox"
        UnifiedAudit      = Join-Path $script:RunDirectory "07-Unified-Audit"
        MessageTrace      = Join-Path $script:RunDirectory "08-Message-Trace"
        Manifest          = Join-Path $script:RunDirectory "99-Manifest"
    }

    New-Item -ItemType Directory -Path $script:RunDirectory -Force | Out-Null
    foreach ($path in $script:Paths.Values) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }

    $metadata = [ordered]@{
        ToolName              = "Invoke-M365IncidentResponse.ps1"
        ToolVersion           = $script:ToolVersion
        CollectionStartedUtc  = (Get-Date).ToUniversalTime().ToString("o")
        Action                = $Action
        TargetUser            = $UserPrincipalName
        StartUtc              = $StartUtc.UtcDateTime.ToString("o")
        EndUtcExclusive       = $EndUtc.UtcDateTime.ToString("o")
        Components            = @($Components)
        SuspectIpAddresses    = @($SuspectIpAddress)
        SuspectDeviceIds      = @($SuspectDeviceId)
        CampaignSubject       = $CampaignSubject
        PolicyName            = $PolicyName
        TestUserUpn           = if ($TestUserUpn) { $TestUserUpn } else { $UserPrincipalName }
        ComputerName          = $env:COMPUTERNAME
        PowerShellVersion     = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition     = $PSVersionTable.PSEdition
        CurrentUser           = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        OutputDirectory       = $script:RunDirectory
    }

    Write-JsonEvidence -Data $metadata `
        -Path (Join-Path $script:Paths.Run "Collection-Metadata.json") `
        -Component "Run" -Description "Collection parameters and execution environment" -RecordCount 1

    $transcriptPath = Join-Path $script:Paths.Run "Collection-Transcript.txt"
    Start-Transcript -LiteralPath $transcriptPath -Force | Out-Null
    $script:TranscriptStarted = $true
    Add-EvidenceIndexEntry -Component "Run" -Description "PowerShell collection transcript" `
        -Path $transcriptPath -RecordCount -1 -Source "PowerShell transcript"
}

function Complete-EvidenceRun {
    [CmdletBinding()]
    param()

    if ($script:TranscriptStarted) {
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
        $script:TranscriptStarted = $false
    }

    Export-CsvEvidence -Data $script:StepResults `
        -Path (Join-Path $script:Paths.Run "Collection-Steps.csv") `
        -Component "Run" -Description "Collection step status and duration"

    Export-CsvEvidence -Data $script:CollectionErrors `
        -Path (Join-Path $script:Paths.Run "Collection-Errors.csv") `
        -Component "Run" -Description "Errors and partial-collection warnings"

    $summary = [ordered]@{
        CollectionCompletedUtc = (Get-Date).ToUniversalTime().ToString("o")
        Action                 = $Action
        TargetUser             = $UserPrincipalName
        EvidenceFilesIndexed   = $script:EvidenceIndex.Count + 2
        StepsRun               = $script:StepResults.Count
        FailedSteps            = @($script:StepResults | Where-Object Status -eq "Failed").Count
        ErrorsRecorded         = $script:CollectionErrors.Count
        OutputDirectory        = $script:RunDirectory
        ReviewRequired         = $script:CollectionErrors.Count -gt 0
    }
    Write-JsonEvidence -Data $summary `
        -Path (Join-Path $script:Paths.Run "Collection-Summary.json") `
        -Component "Run" -Description "Collection completion summary" -RecordCount 1

    $indexPath = Join-Path $script:Paths.Manifest "Evidence-Index.csv"
    Add-EvidenceIndexEntry -Component "Run" -Description "Index of collected evidence files" `
        -Path $indexPath -RecordCount ($script:EvidenceIndex.Count + 1)
    $script:EvidenceIndex |
        Export-Csv -LiteralPath $indexPath -Encoding utf8

    $manifestPath = Join-Path $script:Paths.Manifest "SHA256SUMS.csv"
    # Collect the file list before Export-Csv creates the manifest file
    @(Get-ChildItem -LiteralPath $script:RunDirectory -File -Recurse |
        Where-Object FullName -ne $manifestPath) |
        Get-FileHash -Algorithm SHA256 |
        ForEach-Object {
            [pscustomobject]@{
                RelativePath = [System.IO.Path]::GetRelativePath($script:RunDirectory, $_.Path)
                Algorithm    = $_.Algorithm
                Hash         = $_.Hash
            }
        } |
        Sort-Object RelativePath |
        Export-Csv -LiteralPath $manifestPath -Encoding utf8

    Write-IncidentLog -Message "Evidence run complete: $script:RunDirectory"
    if ($script:CollectionErrors.Count -gt 0) {
        Write-IncidentLog -Level WARN -Message "One or more steps failed. Review 00-Run\Collection-Errors.csv before relying on completeness."
    }
}

function Get-GraphResponseProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Response,
        [Parameter(Mandatory)][string]$Name
    )

    if ($Response -is [System.Collections.IDictionary]) {
        return $Response[$Name]
    }
    $property = $Response.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Get-GraphCollection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri)

    $results = [System.Collections.Generic.List[object]]::new()
    do {
        $page = Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop
        $values = Get-GraphResponseProperty -Response $page -Name "value"
        foreach ($item in @($values)) {
            if ($null -ne $item) { [void]$results.Add($item) }
        }
        $Uri = Get-GraphResponseProperty -Response $page -Name "@odata.nextLink"
    }
    while ($Uri)

    return $results.ToArray()
}

function Connect-IncidentGraph {
    [CmdletBinding()]
    param(
        [switch]$ConditionalAccessWrite,
        [switch]$EmergencyAccessAudit
    )

    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
        throw "Microsoft.Graph.Authentication is unavailable. Install or update it in PowerShell 7."
    }

    $requiredScopes = [System.Collections.Generic.List[string]]::new()
    foreach ($scope in @(
        "AuditLog.Read.All",
        "Directory.Read.All",
        "Device.Read.All",
        "Application.Read.All",
        "DelegatedPermissionGrant.Read.All",
        "Policy.Read.All",
        "User.Read.All"
    )) { [void]$requiredScopes.Add($scope) }

    if ($ConditionalAccessWrite) {
        [void]$requiredScopes.Add("Policy.ReadWrite.ConditionalAccess")
    }

    if ($EmergencyAccessAudit) {
        [void]$requiredScopes.Add("RoleManagement.Read.Directory")
        [void]$requiredScopes.Add("UserAuthenticationMethod.Read.All")
    }

    $context = Get-MgContext
    $missingScopes = @()
    if ($null -ne $context) {
        $granted = @($context.Scopes)
        $missingScopes = @($requiredScopes | Where-Object { $granted -notcontains $_ })
    }

    if ($null -eq $context -or $missingScopes.Count -gt 0) {
        Connect-MgGraph -Scopes $requiredScopes.ToArray() -NoWelcome -ContextScope Process
        $script:GraphConnectedByScript = $true
    }

    $context = Get-MgContext
    if ($null -eq $context) { throw "Microsoft Graph connection was not established." }
    Write-IncidentLog -Message "Connected to Microsoft Graph tenant $($context.TenantId) as $($context.Account)."
}

function Connect-IncidentExchange {
    [CmdletBinding()]
    param()

    if (-not (Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue)) {
        throw "ExchangeOnlineManagement is unavailable. Install or update it in PowerShell 7."
    }
    # Graph is already connected, so Graph's newer MSAL library is loaded. With the Windows broker
    # (WAM), Connect-ExchangeOnline then fails with a NullReferenceException in RuntimeBroker.
    # Browser sign-in (-DisableWAM) avoids the clash; it must be used on the first attempt.
    $exchangeArgs = @{ ShowBanner = $false; ErrorAction = "Stop" }
    if ((Get-Command Connect-ExchangeOnline).Parameters.ContainsKey("DisableWAM")) {
        $exchangeArgs["DisableWAM"] = $true
    }
    Connect-ExchangeOnline @exchangeArgs
    $script:ExchangeConnectedByScript = $true
    Write-IncidentLog -Message "Connected to Exchange Online."
}

function Resolve-IncidentUser {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Upn)

    $encodedUpn = [uri]::EscapeDataString($Upn)
    return Invoke-MgGraphRequest -Method GET -Uri (
        "https://graph.microsoft.com/v1.0/users/$encodedUpn" +
        "?`$select=id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime," +
        "onPremisesSyncEnabled,userType"
    )
}

function Get-GraphSignIns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetimeoffset]$RangeStartUtc,
        [Parameter(Mandatory)][datetimeoffset]$RangeEndUtc,
        [string]$UserId,
        [string]$IpAddress,
        # v1.0 and an unfiltered beta query return only interactive sign-ins. Token refreshes and
        # other non-interactive sign-ins (where a stolen session keeps working) need this filter.
        [ValidateSet("interactiveUser", "nonInteractiveUser")]
        [string[]]$SignInEventType = @("interactiveUser", "nonInteractiveUser")
    )

    $eventTypeFilter = "signInEventTypes/any(t: " +
        (($SignInEventType | ForEach-Object { "t eq '$_'" }) -join " or ") + ")"
    $deduplicated = [ordered]@{}
    $cursor = $RangeStartUtc.UtcDateTime
    $end = $RangeEndUtc.UtcDateTime

    while ($cursor -lt $end) {
        $sliceEnd = $cursor.AddDays(1)
        if ($sliceEnd -gt $end) { $sliceEnd = $end }

        $parts = [System.Collections.Generic.List[string]]::new()
        [void]$parts.Add("createdDateTime ge $($cursor.ToString('yyyy-MM-ddTHH:mm:ssZ'))")
        [void]$parts.Add("createdDateTime lt $($sliceEnd.ToString('yyyy-MM-ddTHH:mm:ssZ'))")
        if ($UserId) { [void]$parts.Add("userId eq '$($UserId.Replace("'", "''"))'") }
        if ($IpAddress) { [void]$parts.Add("ipAddress eq '$($IpAddress.Replace("'", "''"))'") }
        [void]$parts.Add($eventTypeFilter)

        $encodedFilter = [uri]::EscapeDataString($parts -join " and ")
        $items = @(Get-GraphCollection -Uri (
            "https://graph.microsoft.com/beta/auditLogs/signIns?" +
            "`$filter=$encodedFilter&`$top=1000"
        ))
        foreach ($item in $items) {
            $key = if ($item.id) { $item.id } else { "$($item.createdDateTime)|$($item.correlationId)|$($item.ipAddress)" }
            if (-not $deduplicated.Contains($key)) { $deduplicated[$key] = $item }
        }
        $cursor = $sliceEnd
    }

    return @($deduplicated.Values)
}

function ConvertTo-SignInReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$SignIn)

    $appliedPolicies = @(
        $SignIn.appliedConditionalAccessPolicies | ForEach-Object {
            "$($_.displayName):$($_.result):$($_.id)"
        }
    )
    $authenticationDetails = @(
        $SignIn.authenticationDetails | ForEach-Object {
            "$($_.authenticationStepDateTime):$($_.authenticationMethod):$($_.authenticationStepResultDetail):succeeded=$($_.succeeded)"
        }
    )

    [pscustomobject]@{
        CreatedUtc                  = $SignIn.createdDateTime
        UserPrincipalName           = $SignIn.userPrincipalName
        UserId                      = $SignIn.userId
        IPAddress                   = $SignIn.ipAddress
        Location                    = "$($SignIn.location.city), $($SignIn.location.state), $($SignIn.location.countryOrRegion)"
        App                         = $SignIn.appDisplayName
        AppId                       = $SignIn.appId
        Resource                    = $SignIn.resourceDisplayName
        ResourceId                  = $SignIn.resourceId
        ClientApp                   = $SignIn.clientAppUsed
        Interactive                 = $SignIn.isInteractive
        SignInEventTypes            = @($SignIn.signInEventTypes) -join ","
        AuthenticationProtocol      = $SignIn.authenticationProtocol
        OriginalTransferMethod      = $SignIn.originalTransferMethod
        IncomingTokenType           = $SignIn.incomingTokenType
        AuthenticationRequirement   = $SignIn.authenticationRequirement
        ConditionalAccess           = $SignIn.conditionalAccessStatus
        AppliedConditionalAccess    = $appliedPolicies -join "; "
        ErrorCode                   = $SignIn.status.errorCode
        FailureReason               = $SignIn.status.failureReason
        AdditionalDetails           = $SignIn.status.additionalDetails
        SessionId                   = $SignIn.sessionId
        CorrelationId               = $SignIn.correlationId
        DeviceName                  = $SignIn.deviceDetail.displayName
        DeviceId                    = $SignIn.deviceDetail.deviceId
        OperatingSystem             = $SignIn.deviceDetail.operatingSystem
        Browser                     = $SignIn.deviceDetail.browser
        Managed                     = $SignIn.deviceDetail.isManaged
        Compliant                   = $SignIn.deviceDetail.isCompliant
        TrustType                   = $SignIn.deviceDetail.trustType
        TokenProtection             = $SignIn.tokenProtectionStatusDetails.signInSessionStatus
        RiskLevel                   = $SignIn.riskLevelDuringSignIn
        RiskState                   = $SignIn.riskState
        RiskDetail                  = $SignIn.riskDetail
        AutonomousSystemNumber      = $SignIn.autonomousSystemNumber
        AuthenticationDetails       = $authenticationDetails -join "; "
        SignInEventId               = $SignIn.id
    }
}

function Get-DirectoryAuditsForRange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetimeoffset]$RangeStartUtc,
        [Parameter(Mandatory)][datetimeoffset]$RangeEndUtc
    )

    $deduplicated = [ordered]@{}
    $cursor = $RangeStartUtc.UtcDateTime
    $end = $RangeEndUtc.UtcDateTime
    while ($cursor -lt $end) {
        $sliceEnd = $cursor.AddDays(1)
        if ($sliceEnd -gt $end) { $sliceEnd = $end }
        $filter = [uri]::EscapeDataString(
            "activityDateTime ge $($cursor.ToString('yyyy-MM-ddTHH:mm:ssZ')) and " +
            "activityDateTime lt $($sliceEnd.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        )
        foreach ($item in @(Get-GraphCollection -Uri (
            "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?" +
            "`$filter=$filter&`$top=999"
        ))) {
            $key = if ($item.id) { $item.id } else { "$($item.activityDateTime)|$($item.correlationId)" }
            if (-not $deduplicated.Contains($key)) { $deduplicated[$key] = $item }
        }
        $cursor = $sliceEnd
    }
    return @($deduplicated.Values)
}

function ConvertTo-DirectoryAuditReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Event)

    $initiator = $Event.initiatedBy.user.userPrincipalName
    if (-not $initiator) { $initiator = $Event.initiatedBy.app.displayName }
    $targets = @()
    $modified = @()
    foreach ($target in @($Event.targetResources)) {
        $targets += "$($target.type):$($target.displayName):$($target.id):$($target.userPrincipalName)"
        foreach ($property in @($target.modifiedProperties)) {
            $modified += "$($property.displayName):$($property.oldValue) -> $($property.newValue)"
        }
    }

    [pscustomobject]@{
        ActivityDateTimeUtc = $Event.activityDateTime
        Activity            = $Event.activityDisplayName
        Category            = $Event.category
        LoggedByService     = $Event.loggedByService
        Result              = $Event.result
        ResultReason        = $Event.resultReason
        InitiatedBy         = $initiator
        InitiatorUserId     = $Event.initiatedBy.user.id
        InitiatorIP         = $Event.initiatedBy.user.ipAddress
        InitiatorAppId      = $Event.initiatedBy.app.appId
        CorrelationId       = $Event.correlationId
        Targets             = $targets -join "; "
        ModifiedProperties  = $modified -join "; "
        AuditId             = $Event.id
    }
}

function Collect-IdentityEvidence {
    [CmdletBinding()]
    param()

    $script:ResolvedUser = Resolve-IncidentUser -Upn $UserPrincipalName
    Write-JsonEvidence -Data $script:ResolvedUser `
        -Path (Join-Path $script:Paths.Identity "Target-User.json") `
        -Component "Identity" -Description "Current target user object" -RecordCount 1 `
        -Source "Microsoft Graph /users"

    $signIns = @(Get-GraphSignIns -RangeStartUtc $StartUtc -RangeEndUtc $EndUtc -UserId $script:ResolvedUser.id)
    Write-JsonEvidence -Data $signIns `
        -Path (Join-Path $script:Paths.Identity "User-SignIns-Raw.json") `
        -Component "Identity" -Description "Raw target-user sign-ins" -RecordCount $signIns.Count `
        -Source "Microsoft Graph beta /auditLogs/signIns"

    $report = @($signIns | ForEach-Object { ConvertTo-SignInReport -SignIn $_ } | Sort-Object CreatedUtc)
    Export-CsvEvidence -Data $report `
        -Path (Join-Path $script:Paths.Identity "User-SignIns-All.csv") `
        -Component "Identity" -Description "Flattened target-user sign-ins" `
        -Source "Microsoft Graph beta /auditLogs/signIns"

    $exchangeSignIns = @(
        $report | Where-Object {
            $_.Resource -match "Exchange|Microsoft Graph|Office 365" -or
            $_.App -match "Outlook|Exchange"
        }
    )
    Export-CsvEvidence -Data $exchangeSignIns `
        -Path (Join-Path $script:Paths.Identity "Exchange-And-Graph-SignIns.csv") `
        -Component "Identity" -Description "Sign-ins related to Exchange, Outlook, Office, or Graph"

    foreach ($ip in @($SuspectIpAddress | Where-Object { $_ })) {
        $ipSignIns = @(Get-GraphSignIns -RangeStartUtc $StartUtc -RangeEndUtc $EndUtc -IpAddress $ip)
        $safeIp = Get-SafeFileName -Value $ip
        Write-JsonEvidence -Data $ipSignIns `
            -Path (Join-Path $script:Paths.Identity "SignIns-$safeIp-Raw.json") `
            -Component "Identity" -Description "Raw tenant sign-ins from suspect IP $ip" `
            -RecordCount $ipSignIns.Count -Source "Microsoft Graph beta /auditLogs/signIns"
        Export-CsvEvidence -Data @($ipSignIns | ForEach-Object { ConvertTo-SignInReport -SignIn $_ }) `
            -Path (Join-Path $script:Paths.Identity "SignIns-$safeIp.csv") `
            -Component "Identity" -Description "Flattened tenant sign-ins from suspect IP $ip"
    }
}

function Collect-DirectoryAuditEvidence {
    [CmdletBinding()]
    param()

    if ($null -eq $script:ResolvedUser) {
        $script:ResolvedUser = Resolve-IncidentUser -Upn $UserPrincipalName
    }

    $audits = @(Get-DirectoryAuditsForRange -RangeStartUtc $StartUtc -RangeEndUtc $EndUtc)
    Write-JsonEvidence -Data $audits `
        -Path (Join-Path $script:Paths.DirectoryAudit "Directory-Audit-Raw.json") `
        -Component "DirectoryAudit" -Description "Raw tenant directory audit events for search interval" `
        -RecordCount $audits.Count -Source "Microsoft Graph /auditLogs/directoryAudits"

    $report = @($audits | ForEach-Object { ConvertTo-DirectoryAuditReport -Event $_ } | Sort-Object ActivityDateTimeUtc)
    Export-CsvEvidence -Data $report `
        -Path (Join-Path $script:Paths.DirectoryAudit "Directory-Audit-All.csv") `
        -Component "DirectoryAudit" -Description "Flattened tenant directory audit events"

    $userPattern = [regex]::Escape($script:ResolvedUser.userPrincipalName)
    $userIdPattern = [regex]::Escape($script:ResolvedUser.id)
    $userRelevant = @(
        $report | Where-Object {
            $_.InitiatorUserId -eq $script:ResolvedUser.id -or
            $_.InitiatedBy -match $userPattern -or
            $_.Targets -match $userPattern -or
            $_.Targets -match $userIdPattern -or
            $_.ModifiedProperties -match $userPattern
        }
    )
    Export-CsvEvidence -Data $userRelevant `
        -Path (Join-Path $script:Paths.DirectoryAudit "Directory-Audit-User-Relevant.csv") `
        -Component "DirectoryAudit" -Description "Directory audit events relevant to target user"

    Export-CsvEvidence -Data @(
        $userRelevant | Where-Object {
            $_.Activity -match "consent|permission|OAuth|app role|service principal|application"
        }
    ) -Path (Join-Path $script:Paths.DirectoryAudit "App-Consent-And-Permission-Changes.csv") `
        -Component "DirectoryAudit" -Description "Application consent and permission changes"

    Export-CsvEvidence -Data @(
        $userRelevant | Where-Object {
            $_.Activity -match "device|authentication|security info|credential|MFA|password"
        }
    ) -Path (Join-Path $script:Paths.DirectoryAudit "Device-And-Authentication-Changes.csv") `
        -Component "DirectoryAudit" -Description "Device, credential, MFA, and authentication changes"
}

function Collect-ApplicationEvidence {
    [CmdletBinding()]
    param()

    if ($null -eq $script:ResolvedUser) {
        $script:ResolvedUser = Resolve-IncidentUser -Upn $UserPrincipalName
    }

    $servicePrincipals = @(Get-GraphCollection -Uri (
        "https://graph.microsoft.com/v1.0/servicePrincipals?" +
        "`$select=id,appId,displayName,servicePrincipalType,accountEnabled,verifiedPublisher," +
        "createdDateTime,homepage,replyUrls&`$top=999"
    ))
    Write-JsonEvidence -Data $servicePrincipals `
        -Path (Join-Path $script:Paths.Applications "Service-Principals-Raw.json") `
        -Component "Applications" -Description "Current tenant service principals" `
        -RecordCount $servicePrincipals.Count -Source "Microsoft Graph /servicePrincipals"

    $spById = @{}
    foreach ($sp in $servicePrincipals) { $spById[$sp.id] = $sp }

    $allGrants = @(Get-GraphCollection -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$top=999")
    Write-JsonEvidence -Data $allGrants `
        -Path (Join-Path $script:Paths.Applications "Current-All-Delegated-App-Consent-Raw.json") `
        -Component "Applications" -Description "Current tenant OAuth2 delegated permission grants" `
        -RecordCount $allGrants.Count -Source "Microsoft Graph /oauth2PermissionGrants"

    $grantReport = foreach ($grant in $allGrants) {
        $client = $spById[$grant.clientId]
        $resource = $spById[$grant.resourceId]
        [pscustomobject]@{
            RelevantToTarget   = $grant.principalId -eq $script:ResolvedUser.id -or $grant.consentType -eq "AllPrincipals"
            GrantId            = $grant.id
            ConsentType        = $grant.consentType
            PrincipalId        = $grant.principalId
            ClientDisplayName  = $client.displayName
            ClientAppId        = $client.appId
            ClientObjectId     = $grant.clientId
            ClientEnabled      = $client.accountEnabled
            VerifiedPublisher  = $client.verifiedPublisher.displayName
            ResourceName       = $resource.displayName
            ResourceAppId      = $resource.appId
            ResourceObjectId   = $grant.resourceId
            Scopes             = $grant.scope
            StartTime          = $grant.startTime
            ExpiryTime         = $grant.expiryTime
        }
    }
    Export-CsvEvidence -Data $grantReport `
        -Path (Join-Path $script:Paths.Applications "Current-All-Delegated-App-Consent.csv") `
        -Component "Applications" -Description "Resolved tenant OAuth2 delegated permission grants"
    Export-CsvEvidence -Data @($grantReport | Where-Object RelevantToTarget) `
        -Path (Join-Path $script:Paths.Applications "Current-User-Or-Tenantwide-App-Consent.csv") `
        -Component "Applications" -Description "Target-user and tenantwide delegated permission grants"

    $appRoleAssignments = @(Get-GraphCollection -Uri (
        "https://graph.microsoft.com/v1.0/users/$($script:ResolvedUser.id)/appRoleAssignments?`$top=999"
    ))
    Write-JsonEvidence -Data $appRoleAssignments `
        -Path (Join-Path $script:Paths.Applications "Current-User-App-Role-Assignments-Raw.json") `
        -Component "Applications" -Description "Current app role assignments for target user" `
        -RecordCount $appRoleAssignments.Count -Source "Microsoft Graph /users/appRoleAssignments"
    Export-CsvEvidence -Data @(
        $appRoleAssignments | Select-Object id,createdDateTime,principalDisplayName,principalId,
            resourceDisplayName,resourceId,appRoleId
    ) -Path (Join-Path $script:Paths.Applications "Current-User-App-Role-Assignments.csv") `
        -Component "Applications" -Description "Flattened app role assignments for target user"
}

function Get-DeviceRelationshipLabels {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DeviceObjectId,
        [ValidateSet("registeredOwners", "registeredUsers")][string]$Relationship
    )

    $items = @(Get-GraphCollection -Uri (
        "https://graph.microsoft.com/v1.0/devices/$DeviceObjectId/$Relationship" +
        "?`$select=id,displayName,userPrincipalName"
    ))
    return @($items | ForEach-Object { "$($_.displayName) <$($_.userPrincipalName)> [$($_.id)]" })
}

function Collect-DeviceEvidence {
    [CmdletBinding()]
    param()

    if ($null -eq $script:ResolvedUser) {
        $script:ResolvedUser = Resolve-IncidentUser -Upn $UserPrincipalName
    }

    $deviceSelect = "id,deviceId,displayName,accountEnabled,registrationDateTime," +
        "approximateLastSignInDateTime,operatingSystem,operatingSystemVersion,trustType," +
        "isManaged,isCompliant"
    $allDevices = @(Get-GraphCollection -Uri (
        "https://graph.microsoft.com/beta/devices?`$select=$deviceSelect&`$top=999"
    ))
    Write-JsonEvidence -Data $allDevices `
        -Path (Join-Path $script:Paths.Devices "Tenant-Devices-Raw.json") `
        -Component "Devices" -Description "Current tenant device objects" -RecordCount $allDevices.Count `
        -Source "Microsoft Graph beta /devices"

    Export-CsvEvidence -Data @(
        $allDevices | Select-Object displayName,deviceId,id,accountEnabled,registrationDateTime,
            approximateLastSignInDateTime,operatingSystem,operatingSystemVersion,trustType,
            isManaged,isCompliant
    ) -Path (Join-Path $script:Paths.Devices "Tenant-Devices-All.csv") `
        -Component "Devices" -Description "Flattened tenant device inventory"

    $owned = @(Get-GraphCollection -Uri (
        "https://graph.microsoft.com/v1.0/users/$($script:ResolvedUser.id)/ownedDevices/" +
        "microsoft.graph.device?`$select=$deviceSelect&`$top=999"
    ))
    $registered = @(Get-GraphCollection -Uri (
        "https://graph.microsoft.com/v1.0/users/$($script:ResolvedUser.id)/registeredDevices/" +
        "microsoft.graph.device?`$select=$deviceSelect&`$top=999"
    ))

    $targetObjectIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($device in @($owned + $registered)) { if ($device.id) { [void]$targetObjectIds.Add($device.id) } }

    $suspectIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in @($SuspectDeviceId | Where-Object { $_ })) { [void]$suspectIds.Add($id) }

    $candidates = @(
        $allDevices | Where-Object {
            $_.displayName -like "DESKTOP-*" -or
            $targetObjectIds.Contains($_.id) -or
            $suspectIds.Contains($_.deviceId)
        }
    )

    $candidateReport = foreach ($device in $candidates) {
        $owners = @(Get-DeviceRelationshipLabels -DeviceObjectId $device.id -Relationship registeredOwners)
        $registeredUsers = @(Get-DeviceRelationshipLabels -DeviceObjectId $device.id -Relationship registeredUsers)
        [pscustomobject]@{
            KnownSuspect          = $suspectIds.Contains($device.deviceId)
            TargetUserRelated     = $targetObjectIds.Contains($device.id)
            GenericDesktopName    = $device.displayName -like "DESKTOP-*"
            DisplayName           = $device.displayName
            DeviceId              = $device.deviceId
            ObjectId              = $device.id
            Enabled               = $device.accountEnabled
            RegistrationUTC       = $device.registrationDateTime
            LastSignInUTC         = $device.approximateLastSignInDateTime
            OperatingSystem       = $device.operatingSystem
            OperatingSystemBuild  = $device.operatingSystemVersion
            TrustType             = $device.trustType
            Managed               = $device.isManaged
            Compliant             = $device.isCompliant
            Owners                = $owners -join "; "
            RegisteredUsers       = $registeredUsers -join "; "
        }
    }
    Export-CsvEvidence -Data $candidateReport `
        -Path (Join-Path $script:Paths.Devices "Candidate-Devices-With-Owners.csv") `
        -Component "Devices" -Description "Generic, target-related, and explicitly suspect devices with relationships"
    Export-CsvEvidence -Data @($candidateReport | Where-Object GenericDesktopName) `
        -Path (Join-Path $script:Paths.Devices "Tenant-DESKTOP-Devices.csv") `
        -Component "Devices" -Description "Tenant devices with generic DESKTOP names"
    Export-CsvEvidence -Data @($candidateReport | Where-Object TargetUserRelated) `
        -Path (Join-Path $script:Paths.Devices "Target-User-Devices.csv") `
        -Component "Devices" -Description "Devices owned or registered by target user"
    Export-CsvEvidence -Data @($candidateReport | Where-Object KnownSuspect) `
        -Path (Join-Path $script:Paths.Devices "Suspected-Devices.csv") `
        -Component "Devices" -Description "Devices matching explicitly supplied suspect device IDs"

    $tenantSignIns = @(Get-GraphSignIns -RangeStartUtc $StartUtc -RangeEndUtc $EndUtc)
    $deviceCodeSignIns = @(
        $tenantSignIns | Where-Object {
            $_.originalTransferMethod -eq "deviceCodeFlow" -or
            $_.authenticationProtocol -eq "deviceCode"
        }
    )
    Write-JsonEvidence -Data $deviceCodeSignIns `
        -Path (Join-Path $script:Paths.Devices "Tenant-Device-Code-SignIns-Raw.json") `
        -Component "Devices" -Description "Raw tenant sign-ins using or derived from device code flow" `
        -RecordCount $deviceCodeSignIns.Count -Source "Microsoft Graph beta /auditLogs/signIns"
    Export-CsvEvidence -Data @($deviceCodeSignIns | ForEach-Object { ConvertTo-SignInReport -SignIn $_ }) `
        -Path (Join-Path $script:Paths.Devices "Tenant-Device-Code-SignIns.csv") `
        -Component "Devices" -Description "Tenant device-code and device-code-derived sign-ins"
}

function Collect-ConditionalAccessSnapshot {
    [CmdletBinding()]
    param()

    $policies = @(Get-GraphCollection -Uri (
        "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$top=999"
    ))
    Write-JsonEvidence -Data $policies `
        -Path (Join-Path $script:Paths.ConditionalAccess "Conditional-Access-Policies-Raw.json") `
        -Component "ConditionalAccess" -Description "Current Conditional Access policies" `
        -RecordCount $policies.Count -Source "Microsoft Graph /identity/conditionalAccess/policies"

    $report = foreach ($policy in $policies) {
        [pscustomobject]@{
            DisplayName          = $policy.displayName
            Id                   = $policy.id
            State                = $policy.state
            CreatedDateTime      = $policy.createdDateTime
            ModifiedDateTime     = $policy.modifiedDateTime
            IncludeUsers         = Join-IncidentValues $policy.conditions.users.includeUsers
            ExcludeUsers         = Join-IncidentValues $policy.conditions.users.excludeUsers
            IncludeGroups        = Join-IncidentValues $policy.conditions.users.includeGroups
            ExcludeGroups        = Join-IncidentValues $policy.conditions.users.excludeGroups
            IncludeApplications  = Join-IncidentValues $policy.conditions.applications.includeApplications
            ExcludeApplications  = Join-IncidentValues $policy.conditions.applications.excludeApplications
            ClientAppTypes       = Join-IncidentValues $policy.conditions.clientAppTypes
            AuthenticationFlows  = Join-IncidentValues $policy.conditions.authenticationFlows.transferMethods
            GrantControls        = Join-IncidentValues $policy.grantControls.builtInControls
            SessionControls      = if ($policy.sessionControls) { $policy.sessionControls | ConvertTo-Json -Compress -Depth 20 }
        }
    }
    Export-CsvEvidence -Data $report `
        -Path (Join-Path $script:Paths.ConditionalAccess "Conditional-Access-Policies.csv") `
        -Component "ConditionalAccess" -Description "Flattened Conditional Access policy inventory"
}

function Search-IncidentUnifiedAuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$RangeStart,
        [Parameter(Mandatory)][datetime]$RangeEnd,
        [string[]]$UserIds,
        [string[]]$Operations,
        [Parameter(Mandatory)][string]$Label
    )

    $allResults = [System.Collections.Generic.List[object]]::new()
    $cursor = $RangeStart
    while ($cursor -lt $RangeEnd) {
        $sliceEnd = $cursor.AddDays(1)
        if ($sliceEnd -gt $RangeEnd) { $sliceEnd = $RangeEnd }
        $sessionId = "M365IR-$Label-$($cursor.ToString('yyyyMMdd'))-$([guid]::NewGuid())"
        $pageCount = 0
        do {
            $parameters = @{
                StartDate      = $cursor
                EndDate        = $sliceEnd
                SessionId      = $sessionId
                SessionCommand = "ReturnLargeSet"
                ResultSize     = 5000
                ErrorAction    = "Stop"
            }
            if ($UserIds) { $parameters.UserIds = $UserIds }
            if ($Operations) { $parameters.Operations = $Operations }
            $batch = @(Search-UnifiedAuditLog @parameters | Where-Object { $null -ne $_ })
            foreach ($record in $batch) { [void]$allResults.Add($record) }
            $pageCount++
            if ($pageCount -ge 11 -and $batch.Count -gt 0) {
                Write-IncidentLog -Level WARN -Message (
                    "Unified audit search exceeded 50,000 records for $cursor through $sliceEnd. " +
                    "This interval might be incomplete and should be recollected in smaller slices."
                )
                break
            }
        }
        while ($batch.Count -gt 0)
        $cursor = $sliceEnd
    }
    return $allResults.ToArray()
}

function ConvertTo-UnifiedAuditReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record)

    $data = $null
    try { $data = $Record.AuditData | ConvertFrom-Json -Depth 100 }
    catch { }
    $parameters = @($data.Parameters | ForEach-Object { "$($_.Name)=$($_.Value)" })
    $operationProperties = @($data.OperationProperties | ForEach-Object { "$($_.Name)=$($_.Value)" })
    $clientIp = if ($data.ClientIPAddress) { $data.ClientIPAddress } else { $data.ClientIP }
    $subject = if ($data.Item.Subject) { $data.Item.Subject } else { $data.Subject }
    $folder = if ($data.Folder.Path) { $data.Folder.Path } else { $data.FolderPathName }

    [pscustomobject]@{
        CreationTimeUtc     = $Record.CreationDate
        Operation           = if ($data.Operation) { $data.Operation } else { Join-IncidentValues $Record.Operations }
        Workload            = $data.Workload
        RecordType          = $Record.RecordType
        ResultStatus        = $data.ResultStatus
        Actor               = $data.UserId
        UserType            = $data.UserType
        MailboxOwner        = $data.MailboxOwnerUPN
        ClientIP            = $clientIp
        ClientInfo          = $data.ClientInfoString
        LogonType           = $data.LogonType
        LogonUserSid        = $data.LogonUserSid
        ExternalAccess      = $data.ExternalAccess
        AppId               = $data.AppId
        ClientAppId         = $data.ClientAppId
        SessionId           = $data.SessionId
        ObjectId            = $data.ObjectId
        ItemSubject         = $subject
        InternetMessageId   = $data.Item.InternetMessageId
        FolderPath          = $folder
        Parameters          = $parameters -join "; "
        OperationProperties = $operationProperties -join "; "
        AuditRecordId       = $Record.Identity
    }
}

function Get-IncidentMailboxContext {
    [CmdletBinding()]
    param()

    $mailbox = Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop
    $addresses = @(
        $mailbox.EmailAddresses |
            ForEach-Object { $_.ToString() } |
            Where-Object { $_ -match "^(?i)smtp:" } |
            ForEach-Object { $_.Substring(5).ToLowerInvariant() } |
            Sort-Object -Unique
    )
    return [pscustomobject]@{
        Mailbox      = $mailbox
        PrimarySmtp = $mailbox.PrimarySmtpAddress.ToString().ToLowerInvariant()
        SmtpAliases  = $addresses
    }
}

function Collect-MailboxCurrentState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$MailboxContext)

    $mailbox = $MailboxContext.Mailbox
    Export-CsvEvidence -Data @(
        $mailbox | Select-Object DisplayName,UserPrincipalName,PrimarySmtpAddress,
            @{Name="EmailAddresses";Expression={ Join-IncidentValues $_.EmailAddresses }},
            ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward,
            RecipientTypeDetails,AuditEnabled,DefaultAuditSet
    ) -Path (Join-Path $script:Paths.Mailbox "Current-Mailbox-Configuration.csv") `
        -Component "Mailbox" -Description "Current mailbox aliases, forwarding, type, and auditing configuration" `
        -Source "Exchange Online Get-Mailbox"

    $rules = @(Get-InboxRule -Mailbox $UserPrincipalName -IncludeHidden -ErrorAction Stop)
    Export-CsvEvidence -Data @(
        $rules | Select-Object Name,Enabled,Priority,Identity,Description,
            @{Name="RedirectTo";Expression={ Join-IncidentValues $_.RedirectTo }},
            @{Name="ForwardTo";Expression={ Join-IncidentValues $_.ForwardTo }},
            @{Name="ForwardAsAttachmentTo";Expression={ Join-IncidentValues $_.ForwardAsAttachmentTo }},
            DeleteMessage,MoveToFolder,StopProcessingRules
    ) -Path (Join-Path $script:Paths.Mailbox "Current-Inbox-Rules.csv") `
        -Component "Mailbox" -Description "Current visible and hidden inbox rules" `
        -Source "Exchange Online Get-InboxRule"

    Export-CsvEvidence -Data @(
        Get-MailboxPermission -Identity $UserPrincipalName |
            Select-Object User,AccessRights,Deny,IsInherited
    ) -Path (Join-Path $script:Paths.Mailbox "Current-Mailbox-Permissions.csv") `
        -Component "Mailbox" -Description "Current mailbox permissions" `
        -Source "Exchange Online Get-MailboxPermission"

    Export-CsvEvidence -Data @(
        Get-RecipientPermission -Identity $UserPrincipalName |
            Select-Object Trustee,AccessRights,IsInherited
    ) -Path (Join-Path $script:Paths.Mailbox "Current-Recipient-Permissions.csv") `
        -Component "Mailbox" -Description "Current recipient SendAs permissions" `
        -Source "Exchange Online Get-RecipientPermission"
}

function Collect-UnifiedAuditEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$MailboxContext)

    $start = $StartUtc.UtcDateTime
    $end = $EndUtc.UtcDateTime
    $userIds = @($UserPrincipalName, $MailboxContext.PrimarySmtp) | Sort-Object -Unique
    $userAudit = @(Search-IncidentUnifiedAuditLog -RangeStart $start -RangeEnd $end `
        -UserIds $userIds -Label "TargetUser")

    $configurationOperations = @(
        "New-InboxRule", "Set-InboxRule", "Remove-InboxRule", "UpdateInboxRules", "Set-Mailbox",
        "Add-MailboxPermission", "Remove-MailboxPermission", "Add-RecipientPermission", "Remove-RecipientPermission"
    )
    $configurationAudit = @(Search-IncidentUnifiedAuditLog -RangeStart $start -RangeEnd $end `
        -Operations $configurationOperations -Label "Configuration")

    $addressPatterns = @($MailboxContext.SmtpAliases | ForEach-Object { [regex]::Escape($_) })
    $configurationRelevant = @(
        $configurationAudit | Where-Object {
            $text = $_.AuditData
            @($addressPatterns | Where-Object { $text -match $_ }).Count -gt 0
        }
    )

    $mailboxActivityOperations = @(
        "MailItemsAccessed", "FolderBind", "MessageBind", "MailboxLogin",
        "Send", "SendAs", "SendOnBehalf", "SoftDelete", "HardDelete", "MoveToDeletedItems"
    )
    try {
        $mailboxActivityAudit = @(Search-IncidentUnifiedAuditLog -RangeStart $start -RangeEnd $end `
            -Operations $mailboxActivityOperations -Label "MailboxActivity")
        $mailboxActivityRelevant = @(
            $mailboxActivityAudit | Where-Object {
                $text = $_.AuditData
                @($addressPatterns | Where-Object { $text -match $_ }).Count -gt 0
            }
        )
    }
    catch {
        Add-CollectionError -Component "UnifiedAudit" -Step "Tenantwide mailbox activity search" -ErrorRecord $_
        Write-IncidentLog -Level WARN -Message (
            "The tenantwide mailbox-activity search failed. User-scoped activity is still preserved. " +
            $_.Exception.Message
        )
        $mailboxActivityRelevant = @()
    }

    $deduplicated = [ordered]@{}
    foreach ($record in @($userAudit + $configurationRelevant + $mailboxActivityRelevant)) {
        $key = if ($record.Identity) { $record.Identity } else { $record.AuditData }
        if (-not $deduplicated.Contains($key)) { $deduplicated[$key] = $record }
    }
    $rawAudit = @($deduplicated.Values)
    Write-JsonEvidence -Data $rawAudit `
        -Path (Join-Path $script:Paths.UnifiedAudit "Unified-Audit-Raw.json") `
        -Component "UnifiedAudit" -Description "Raw target-user and mailbox-configuration audit results" `
        -RecordCount $rawAudit.Count -Source "Search-UnifiedAuditLog"
    Export-CsvEvidence -Data @(
        $rawAudit | Select-Object CreationDate,Identity,RecordType,ResultIndex,ResultCount,
            UserIds,Operations,AuditData
    ) -Path (Join-Path $script:Paths.UnifiedAudit "Unified-Audit-Raw.csv") `
        -Component "UnifiedAudit" -Description "Raw audit result envelopes with embedded AuditData"

    $report = @($rawAudit | ForEach-Object { ConvertTo-UnifiedAuditReport -Record $_ } | Sort-Object CreationTimeUtc)
    Export-CsvEvidence -Data $report `
        -Path (Join-Path $script:Paths.UnifiedAudit "Unified-Audit-All.csv") `
        -Component "UnifiedAudit" -Description "Flattened unified audit events"
    Export-CsvEvidence -Data @(
        $report | Where-Object {
            $_.Operation -match "InboxRule|UpdateInboxRules" -or
            $_.Parameters -match "RedirectTo|ForwardTo|ForwardAsAttachmentTo|MoveToFolder|DeleteMessage"
        }
    ) -Path (Join-Path $script:Paths.UnifiedAudit "Inbox-Rule-Changes.csv") `
        -Component "UnifiedAudit" -Description "Inbox rule creation, change, and deletion activity"
    Export-CsvEvidence -Data @(
        $report | Where-Object {
            $_.Operation -eq "Set-Mailbox" -or
            $_.Parameters -match "ForwardingAddress|ForwardingSmtpAddress|DeliverToMailboxAndForward"
        }
    ) -Path (Join-Path $script:Paths.UnifiedAudit "Mailbox-Forwarding-Changes.csv") `
        -Component "UnifiedAudit" -Description "Mailbox forwarding configuration changes"
    Export-CsvEvidence -Data @(
        $report | Where-Object {
            $_.Operation -match "MailItemsAccessed|FolderBind|MessageBind|MailboxLogin|SoftDelete|HardDelete|Move|Create|Update"
        }
    ) -Path (Join-Path $script:Paths.UnifiedAudit "Mailbox-Access-And-Item-Actions.csv") `
        -Component "UnifiedAudit" -Description "Mailbox access and item-level actions"
    Export-CsvEvidence -Data @(
        $report | Where-Object { $_.Operation -in @("Send", "SendAs", "SendOnBehalf") }
    ) -Path (Join-Path $script:Paths.UnifiedAudit "Audited-Send-Actions.csv") `
        -Component "UnifiedAudit" -Description "Audited send, SendAs, and SendOnBehalf actions"
    Export-CsvEvidence -Data @(
        $report | Where-Object {
            $_.Operation -match "MailboxPermission|RecipientPermission" -or
            $_.Parameters -match "AccessRights|SendAs|FullAccess"
        }
    ) -Path (Join-Path $script:Paths.UnifiedAudit "Mailbox-Permission-Changes.csv") `
        -Component "UnifiedAudit" -Description "Mailbox and recipient permission changes"
}

function Get-MessageTraceRange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$RangeStart,
        [Parameter(Mandatory)][datetime]$RangeEnd,
        [Parameter(Mandatory)][string]$SenderAddress
    )

    $rows = @(
        Get-MessageTraceV2 -SenderAddress $SenderAddress -StartDate $RangeStart -EndDate $RangeEnd `
            -ResultSize 5000 -ErrorAction Stop |
            Where-Object { $null -ne $_ }
    )
    if ($rows.Count -ge 5000 -and ($RangeEnd - $RangeStart).TotalMinutes -gt 30) {
        $midpoint = $RangeStart.AddTicks([math]::Floor(($RangeEnd.Ticks - $RangeStart.Ticks) / 2))
        return @(
            Get-MessageTraceRange -RangeStart $RangeStart -RangeEnd $midpoint -SenderAddress $SenderAddress
            Get-MessageTraceRange -RangeStart $midpoint -RangeEnd $RangeEnd -SenderAddress $SenderAddress
        )
    }
    if ($rows.Count -ge 5000) {
        Write-IncidentLog -Level WARN -Message (
            "Message trace interval $RangeStart through $RangeEnd for $SenderAddress returned 5,000 rows and might be truncated."
        )
    }
    return $rows
}

function Collect-MessageTraceEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$MailboxContext)

    if ($StartUtc -lt [datetimeoffset]::UtcNow.AddDays(-90)) {
        Write-IncidentLog -Level WARN -Message "Get-MessageTraceV2 retains 90 days. The requested start predates the available trace window."
    }

    $deduplicated = [ordered]@{}
    foreach ($sender in $MailboxContext.SmtpAliases) {
        $cursor = $StartUtc.UtcDateTime
        $end = $EndUtc.UtcDateTime
        while ($cursor -lt $end) {
            $sliceEnd = $cursor.AddDays(1)
            if ($sliceEnd -gt $end) { $sliceEnd = $end }
            foreach ($row in @(Get-MessageTraceRange -RangeStart $cursor -RangeEnd $sliceEnd -SenderAddress $sender)) {
                $key = "$($row.MessageTraceId)|$($row.RecipientAddress)|$($row.Received)|$($row.Status)"
                if (-not $deduplicated.Contains($key)) { $deduplicated[$key] = $row }
            }
            $cursor = $sliceEnd
        }
    }

    $trace = @($deduplicated.Values | Sort-Object Received)
    Write-JsonEvidence -Data $trace `
        -Path (Join-Path $script:Paths.MessageTrace "Outbound-Message-Trace-Raw.json") `
        -Component "MessageTrace" -Description "Raw outbound message trace for all mailbox SMTP identities" `
        -RecordCount $trace.Count -Source "Exchange Online Get-MessageTraceV2"
    Export-CsvEvidence -Data @(
        $trace | Select-Object Received,SenderAddress,RecipientAddress,Subject,Status,
            MessageTraceId,MessageId,FromIP,ToIP
    ) -Path (Join-Path $script:Paths.MessageTrace "Outbound-Message-Trace-All.csv") `
        -Component "MessageTrace" -Description "Outbound trace rows for all mailbox SMTP identities"

    $summary = foreach ($group in @($trace | Group-Object Subject,FromIP)) {
        $rows = @($group.Group)
        [pscustomobject]@{
            Subject          = $rows[0].Subject
            FromIP           = $rows[0].FromIP
            FirstReceivedUtc = ($rows | Sort-Object Received | Select-Object -First 1).Received
            LastReceivedUtc  = ($rows | Sort-Object Received | Select-Object -Last 1).Received
            TraceRows        = $rows.Count
            UniqueRecipients = @($rows.RecipientAddress | Sort-Object -Unique).Count
            Statuses         = Join-IncidentValues @($rows.Status | Sort-Object -Unique)
        }
    }
    Export-CsvEvidence -Data $summary `
        -Path (Join-Path $script:Paths.MessageTrace "Outbound-Message-Trace-Summary.csv") `
        -Component "MessageTrace" -Description "Outbound message trace grouped by subject and source IP"

    if ($CampaignSubject) {
        $campaignRows = @(
            $trace | Where-Object {
                $_.Subject -and [string]::Equals(
                    $_.Subject.ToString().Trim(),
                    $CampaignSubject.Trim(),
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            }
        )
        Export-CsvEvidence -Data $campaignRows `
            -Path (Join-Path $script:Paths.MessageTrace "Campaign-Raw.csv") `
            -Component "MessageTrace" -Description "Exact-subject campaign trace rows"

        $recipientReport = foreach ($group in @(
            $campaignRows | Where-Object RecipientAddress |
                Group-Object { $_.RecipientAddress.ToString().Trim().ToLowerInvariant() }
        )) {
            $statuses = @($group.Group.Status | ForEach-Object { $_.ToString() } | Sort-Object -Unique)
            [pscustomobject]@{
                RecipientAddress = $group.Name
                Delivered        = $statuses -contains "Delivered"
                Statuses         = $statuses -join "; "
                TraceRows        = $group.Count
                FirstReceivedUtc = ($group.Group | Sort-Object Received | Select-Object -First 1).Received
                LastReceivedUtc  = ($group.Group | Sort-Object Received | Select-Object -Last 1).Received
            }
        }
        Export-CsvEvidence -Data $recipientReport `
            -Path (Join-Path $script:Paths.MessageTrace "Campaign-All-Targets.csv") `
            -Component "MessageTrace" -Description "Unique exact-subject campaign recipients and statuses"
        Export-CsvEvidence -Data @($recipientReport | Where-Object Delivered) `
            -Path (Join-Path $script:Paths.MessageTrace "Campaign-Delivered-Recipients.csv") `
            -Component "MessageTrace" -Description "Unique campaign recipients with Delivered status"
        Export-CsvEvidence -Data @(
            $recipientReport | Select-Object RecipientAddress,Delivered,Statuses
        ) -Path (Join-Path $script:Paths.MessageTrace "Campaign-Notification-List.csv") `
            -Component "MessageTrace" -Description "Recipient notification working list"
    }
}

function Get-DeviceCodePolicy {
    [CmdletBinding()]
    param()

    $escaped = $PolicyName.Replace("'", "''")
    $filter = [uri]::EscapeDataString("displayName eq '$escaped'")
    $policies = @(Get-GraphCollection -Uri (
        "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$filter=$filter"
    ))
    if ($policies.Count -gt 1) { throw "More than one policy is named '$PolicyName'. Resolve duplicate names first." }
    if ($policies.Count -eq 0) { return $null }
    return $policies[0]
}

function Test-DeviceCodePolicyConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Policy)

    [pscustomobject]@{
        IncludesAllUsers      = @($Policy.conditions.users.includeUsers) -contains "All"
        IncludesAllResources  = @($Policy.conditions.applications.includeApplications) -contains "All"
        TargetsDeviceCodeFlow = @($Policy.conditions.authenticationFlows.transferMethods) -contains "deviceCodeFlow"
        GrantControlBlocks    = @($Policy.grantControls.builtInControls) -contains "block"
        IsEnabled             = $Policy.state -eq "enabled"
        IsReportOnly          = $Policy.state -eq "enabledForReportingButNotEnforced"
    }
}

function Export-DeviceCodePolicyProof {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Policy)

    $testUpn = if ($TestUserUpn) { $TestUserUpn } else { $UserPrincipalName }
    $testUser = Resolve-IncidentUser -Upn $testUpn
    $request = @{
        signInIdentity = @{
            "@odata.type" = "#microsoft.graph.userSignIn"
            userId = $testUser.id
        }
        signInContext = @{
            "@odata.type" = "#microsoft.graph.applicationContext"
            includeApplications = @($TestResourceAppId)
        }
        signInConditions = @{
            devicePlatform = "windows"
            clientAppType = "mobileAppsAndDesktopClients"
            authenticationFlow = @{ transferMethod = "deviceCodeFlow" }
        }
        appliedPoliciesOnly = $true
    }
    $maxWhatIfAttempts = 1
    if ($Policy.createdDateTime) {
        $policyAge = [datetimeoffset]::UtcNow - [datetimeoffset]$Policy.createdDateTime
        if ($policyAge.TotalMinutes -lt 10) { $maxWhatIfAttempts = 6 }
    }

    $evaluation = $null
    for ($attempt = 1; $attempt -le $maxWhatIfAttempts; $attempt++) {
        $response = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/evaluate" `
            -Body ($request | ConvertTo-Json -Depth 30) -ContentType "application/json"
        $items = @(Get-GraphResponseProperty -Response $response -Name "value")
        $matchingItems = @($items | Where-Object id -eq $Policy.id | Select-Object -First 1)
        $evaluation = if ($matchingItems.Count -gt 0) { $matchingItems[0] } else { $null }

        if ($null -ne $evaluation) { break }
        if ($attempt -lt $maxWhatIfAttempts) {
            Write-IncidentLog -Level WARN -Message (
                "The newly created policy is not visible to Conditional Access What If yet. " +
                "Waiting 10 seconds before attempt $($attempt + 1) of $maxWhatIfAttempts."
            )
            Start-Sleep -Seconds 10
        }
    }
    $configuration = Test-DeviceCodePolicyConfiguration -Policy $Policy
    $whatIfApplies = $null -ne $evaluation -and $evaluation.policyApplies -eq $true
    $whatIfBlocks = $null -ne $evaluation -and @($evaluation.grantControls.builtInControls) -contains "block"

    $summary = [ordered]@{
        EvidenceGeneratedUtc      = (Get-Date).ToUniversalTime().ToString("o")
        TenantId                  = (Get-MgContext).TenantId
        ExportingAccount          = (Get-MgContext).Account
        PolicyName                = $Policy.displayName
        PolicyId                  = $Policy.id
        PolicyState               = $Policy.state
        IncludesAllUsers          = $configuration.IncludesAllUsers
        ExcludedUserIds           = @($Policy.conditions.users.excludeUsers)
        ExcludedGroupIds          = @($Policy.conditions.users.excludeGroups)
        IncludesAllResources      = $configuration.IncludesAllResources
        ExcludedApplicationIds    = @($Policy.conditions.applications.excludeApplications)
        TargetsDeviceCodeFlow     = $configuration.TargetsDeviceCodeFlow
        GrantControlBlocks        = $configuration.GrantControlBlocks
        WhatIfTestUser            = $testUser.userPrincipalName
        WhatIfResourceAppId       = $TestResourceAppId
        WhatIfPolicyApplies       = $whatIfApplies
        WhatIfGrantControlBlocks  = $whatIfBlocks
        ConfigurationValid        = $configuration.IncludesAllUsers -and
            $configuration.IncludesAllResources -and
            $configuration.TargetsDeviceCodeFlow -and
            $configuration.GrantControlBlocks
        EnforcementConfigured     = $configuration.IsEnabled
        EnforcementProofStatement = if ($configuration.IsEnabled -and $whatIfApplies -and $whatIfBlocks) {
            "The enabled policy applies a block control to the simulated device-code-flow sign-in."
        }
        elseif ($configuration.IsReportOnly -and $whatIfApplies -and $whatIfBlocks) {
            "The report-only policy would apply a block control but is not yet enforcing."
        }
        else {
            "The export does not prove that an enabled device-code block applies."
        }
    }

    Write-JsonEvidence -Data $Policy `
        -Path (Join-Path $script:Paths.ConditionalAccess "Device-Code-Policy.json") `
        -Component "ConditionalAccess" -Description "Named device-code Conditional Access policy" -RecordCount 1
    Write-JsonEvidence -Data $request `
        -Path (Join-Path $script:Paths.ConditionalAccess "Device-Code-What-If-Request.json") `
        -Component "ConditionalAccess" -Description "Conditional Access What If request" -RecordCount 1
    Write-JsonEvidence -Data $response `
        -Path (Join-Path $script:Paths.ConditionalAccess "Device-Code-What-If-Response.json") `
        -Component "ConditionalAccess" -Description "Conditional Access What If response" `
        -RecordCount $items.Count
    Write-JsonEvidence -Data $summary `
        -Path (Join-Path $script:Paths.ConditionalAccess "Device-Code-Policy-Proof-Summary.json") `
        -Component "ConditionalAccess" -Description "Device-code policy configuration proof summary" -RecordCount 1

    return [pscustomobject]$summary
}

function New-DeviceCodePolicyReportOnly {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
    param()

    if ($EmergencyAccessUpn.Count -lt 1) {
        throw "Specify at least one verified emergency-access account with -EmergencyAccessUpn. Two are recommended."
    }
    if ($null -ne (Get-DeviceCodePolicy)) {
        throw "A policy named '$PolicyName' already exists. It will not be overwritten."
    }

    $excludedUserIds = @(
        foreach ($upn in $EmergencyAccessUpn) {
            try {
                (Resolve-IncidentUser -Upn $upn).id
            }
            catch {
                throw (
                    "Emergency-access account '$upn' could not be resolved in this tenant. " +
                    "Replace example values with the exact userPrincipalName of a verified, enabled " +
                    "emergency-access account. The policy was not created. Graph error: " +
                    $_.Exception.Message
                )
            }
        }
    )
    $excludedApplications = @()
    if ($ExcludeDeviceRegistrationService) {
        $excludedApplications += "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"
    }
    $body = @{
        displayName = $PolicyName
        state = "enabledForReportingButNotEnforced"
        conditions = @{
            users = @{
                includeUsers = @("All")
                excludeUsers = $excludedUserIds
                includeGroups = @()
                excludeGroups = @($ApprovedDeviceCodeGroupId)
                includeRoles = @()
                excludeRoles = @()
            }
            applications = @{
                includeApplications = @("All")
                excludeApplications = $excludedApplications
                includeUserActions = @()
                includeAuthenticationContextClassReferences = @()
            }
            clientAppTypes = @("all")
            authenticationFlows = @{ transferMethods = "deviceCodeFlow" }
        }
        grantControls = @{ operator = "OR"; builtInControls = @("block") }
    }

    if ($PSCmdlet.ShouldProcess($PolicyName, "Create report-only Conditional Access device-code block policy")) {
        return Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
            -Body ($body | ConvertTo-Json -Depth 30) -ContentType "application/json"
    }
    return $null
}

function Enable-DeviceCodePolicy {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
    param([Parameter(Mandatory)]$Policy)

    if (-not $ConfirmPolicyEnable) {
        throw "Enabling is gated. Re-run with -ConfirmPolicyEnable after reviewing report-only results and emergency-access exclusions."
    }
    $configuration = Test-DeviceCodePolicyConfiguration -Policy $Policy
    if (-not ($configuration.IncludesAllUsers -and $configuration.IncludesAllResources -and
        $configuration.TargetsDeviceCodeFlow -and $configuration.GrantControlBlocks)) {
        throw "The policy does not match the expected all-users/all-resources/device-code/block configuration."
    }
    if ($PSCmdlet.ShouldProcess($Policy.displayName, "Enable Conditional Access policy")) {
        Invoke-MgGraphRequest -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($Policy.id)" `
            -Body (@{ state = "enabled" } | ConvertTo-Json) -ContentType "application/json" | Out-Null
        return Get-DeviceCodePolicy
    }
    return $null
}

function Collect-DeviceCodeEnforcementEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Policy)

    if ($Policy.state -ne "enabled") {
        throw "Policy state is '$($Policy.state)', not enabled."
    }
    $testUpn = if ($TestUserUpn) { $TestUserUpn } else { $UserPrincipalName }
    $testUser = Resolve-IncidentUser -Upn $testUpn
    $lookbackStart = [datetimeoffset]::UtcNow.AddMinutes(-$SignInLookbackMinutes)
    $signIns = @(Get-GraphSignIns -RangeStartUtc $lookbackStart -RangeEndUtc ([datetimeoffset]::UtcNow `
        ) -UserId $testUser.id)
    $deviceCode = @(
        $signIns | Where-Object {
            $_.originalTransferMethod -eq "deviceCodeFlow" -or $_.authenticationProtocol -eq "deviceCode"
        }
    )
    $blocked = @(
        $deviceCode | Where-Object {
            $event = $_
            $matching = @($event.appliedConditionalAccessPolicies | Where-Object id -eq $Policy.id)
            $event.status.errorCode -ne 0 -and $event.conditionalAccessStatus -eq "failure" -and
            @($matching | Where-Object result -eq "failure").Count -gt 0
        }
    )
    $summary = [ordered]@{
        EvidenceGeneratedUtc       = (Get-Date).ToUniversalTime().ToString("o")
        PolicyName                 = $Policy.displayName
        PolicyId                   = $Policy.id
        PolicyState                = $Policy.state
        TestUser                   = $testUser.userPrincipalName
        SearchStartUtc             = $lookbackStart.UtcDateTime.ToString("o")
        DeviceCodeEventsFound      = $deviceCode.Count
        EventsBlockedByThisPolicy  = $blocked.Count
        EnforcementProven          = $blocked.Count -gt 0
        ProofStandard              = "Failed device-code sign-in with CA failure and this policy recorded as failure."
    }
    Write-JsonEvidence -Data $deviceCode `
        -Path (Join-Path $script:Paths.ConditionalAccess "Device-Code-Test-SignIns.json") `
        -Component "ConditionalAccess" -Description "Recent device-code test sign-ins" -RecordCount $deviceCode.Count
    Write-JsonEvidence -Data $blocked `
        -Path (Join-Path $script:Paths.ConditionalAccess "Device-Code-Events-Blocked-By-Policy.json") `
        -Component "ConditionalAccess" -Description "Device-code events blocked by named policy" -RecordCount $blocked.Count
    Write-JsonEvidence -Data $summary `
        -Path (Join-Path $script:Paths.ConditionalAccess "Device-Code-Enforcement-Proof-Summary.json") `
        -Component "ConditionalAccess" -Description "Actual enforcement proof summary" -RecordCount 1
    return [pscustomobject]$summary
}

function Collect-EmergencyAccessAccountAudit {
    [CmdletBinding()]
    param()

    if ($EmergencyAccessUpn.Count -lt 1) {
        throw "Specify at least one emergency-access account with -EmergencyAccessUpn. Two are recommended."
    }

    $globalAdministratorRoleId = "62e90394-69f5-4237-9190-012177145e10"
    $accountUpns = @($UserPrincipalName) + @($EmergencyAccessUpn)
    $accountUpns = @(
        $accountUpns |
        Where-Object { $_ } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
    )
    $summaryRows = [System.Collections.Generic.List[object]]::new()
    $rawRecords = [System.Collections.Generic.List[object]]::new()
    $roleFootprints = @{}

    foreach ($upn in $accountUpns) {
        if ($upn -notmatch '^[^@\s<>]+@[^@\s<>]+$') {
            throw (
                "Account value '$upn' is not a valid exact userPrincipalName. " +
                "Remove placeholder characters such as '<' or '>' and use the UPN shown on the Entra user object."
            )
        }

        try {
            $user = Resolve-IncidentUser -Upn $upn
        }
        catch {
            throw "Account '$upn' could not be resolved by exact userPrincipalName. $($_.Exception.Message)"
        }

        $userId = Get-GraphResponseProperty -Response $user -Name "id"
        if (-not $userId) { throw "Graph returned no object ID for '$upn'." }
        $encodedFilter = [uri]::EscapeDataString("principalId eq '$userId'")

        $activeAssignments = @(Get-GraphCollection -Uri (
            "https://graph.microsoft.com/v1.0/roleManagement/directory/" +
            "roleAssignmentScheduleInstances?`$filter=$encodedFilter&`$expand=roleDefinition"
        ))
        $eligibleAssignments = @(Get-GraphCollection -Uri (
            "https://graph.microsoft.com/v1.0/roleManagement/directory/" +
            "roleEligibilityScheduleInstances?`$filter=$encodedFilter&`$expand=roleDefinition"
        ))
        $authenticationMethods = @(Get-GraphCollection -Uri (
            "https://graph.microsoft.com/v1.0/users/$userId/authentication/methods"
        ))

        $activeRoleDetails = foreach ($assignment in $activeAssignments) {
            $definition = Get-GraphResponseProperty -Response $assignment -Name "roleDefinition"
            $roleName = if ($null -ne $definition) {
                Get-GraphResponseProperty -Response $definition -Name "displayName"
            }
            else {
                Get-GraphResponseProperty -Response $assignment -Name "roleDefinitionId"
            }
            $roleDefinitionId = Get-GraphResponseProperty -Response $assignment -Name "roleDefinitionId"
            $scope = Get-GraphResponseProperty -Response $assignment -Name "directoryScopeId"
            [pscustomobject]@{
                Key              = "$roleDefinitionId|$scope"
                RoleName         = $roleName
                RoleDefinitionId = $roleDefinitionId
                DirectoryScope   = $scope
                AssignmentType   = Get-GraphResponseProperty -Response $assignment -Name "assignmentType"
                MemberType       = Get-GraphResponseProperty -Response $assignment -Name "memberType"
                StartDateTime    = Get-GraphResponseProperty -Response $assignment -Name "startDateTime"
                EndDateTime      = Get-GraphResponseProperty -Response $assignment -Name "endDateTime"
            }
        }

        $eligibleRoleDetails = foreach ($assignment in $eligibleAssignments) {
            $definition = Get-GraphResponseProperty -Response $assignment -Name "roleDefinition"
            $roleName = if ($null -ne $definition) {
                Get-GraphResponseProperty -Response $definition -Name "displayName"
            }
            else {
                Get-GraphResponseProperty -Response $assignment -Name "roleDefinitionId"
            }
            [pscustomobject]@{
                RoleName         = $roleName
                RoleDefinitionId = Get-GraphResponseProperty -Response $assignment -Name "roleDefinitionId"
                DirectoryScope   = Get-GraphResponseProperty -Response $assignment -Name "directoryScopeId"
                MemberType       = Get-GraphResponseProperty -Response $assignment -Name "memberType"
                StartDateTime    = Get-GraphResponseProperty -Response $assignment -Name "startDateTime"
                EndDateTime      = Get-GraphResponseProperty -Response $assignment -Name "endDateTime"
            }
        }

        $authenticationMethodTypes = @(
            $authenticationMethods | ForEach-Object {
                Get-GraphResponseProperty -Response $_ -Name "@odata.type"
            } | Where-Object { $_ } | Sort-Object -Unique
        )

        $permanentDirectGlobalAdministrator = @(
            $activeAssignments | Where-Object {
                (Get-GraphResponseProperty -Response $_ -Name "roleDefinitionId") -eq $globalAdministratorRoleId -and
                (Get-GraphResponseProperty -Response $_ -Name "assignmentType") -eq "Assigned" -and
                (Get-GraphResponseProperty -Response $_ -Name "memberType") -eq "Direct" -and
                (Get-GraphResponseProperty -Response $_ -Name "directoryScopeId") -eq "/" -and
                -not (Get-GraphResponseProperty -Response $_ -Name "endDateTime")
            }
        ).Count -gt 0
        $eligibleGlobalAdministrator = @(
            $eligibleAssignments | Where-Object {
                (Get-GraphResponseProperty -Response $_ -Name "roleDefinitionId") -eq $globalAdministratorRoleId
            }
        ).Count -gt 0

        $resolvedUpn = Get-GraphResponseProperty -Response $user -Name "userPrincipalName"
        $upnKey = $resolvedUpn.ToString().ToLowerInvariant()
        $roleFootprints[$upnKey] = @($activeRoleDetails)
        [void]$rawRecords.Add([pscustomobject]@{
            User                  = $user
            ActiveAssignments     = $activeAssignments
            EligibleAssignments   = $eligibleAssignments
            AuthenticationMethods = $authenticationMethods
        })

        [void]$summaryRows.Add([pscustomobject]@{
            AccountPurpose                 = if ($resolvedUpn -ieq $UserPrincipalName) { "Reference administrator" } else { "Emergency access" }
            DisplayName                    = Get-GraphResponseProperty -Response $user -Name "displayName"
            UserPrincipalName              = $resolvedUpn
            ObjectId                       = $userId
            AccountEnabled                 = Get-GraphResponseProperty -Response $user -Name "accountEnabled"
            CloudOnly                      = (Get-GraphResponseProperty -Response $user -Name "onPremisesSyncEnabled") -ne $true
            UsesOnMicrosoftDomain          = $resolvedUpn -like "*.onmicrosoft.com"
            PermanentActiveDirectGA        = $permanentDirectGlobalAdministrator
            EligibleGlobalAdministrator    = $eligibleGlobalAdministrator
            ActiveRoles                    = @($activeRoleDetails | ForEach-Object { "$($_.RoleName) [$($_.DirectoryScope)]" } | Sort-Object -Unique) -join "; "
            EligibleRoles                  = @($eligibleRoleDetails | ForEach-Object { "$($_.RoleName) [$($_.DirectoryScope)]" } | Sort-Object -Unique) -join "; "
            AuthenticationMethodTypes      = $authenticationMethodTypes -join "; "
            HasFido2OrCertificateMethod    = @($authenticationMethodTypes | Where-Object {
                $_ -match "fido2AuthenticationMethod|x509CertificateAuthenticationMethod"
            }).Count -gt 0
        })
    }

    $referenceKey = $UserPrincipalName.ToLowerInvariant()
    $referenceRoles = @($roleFootprints[$referenceKey])
    $comparisonRows = foreach ($emergencyUpn in $EmergencyAccessUpn) {
        $emergencyKey = $emergencyUpn.ToLowerInvariant()
        $emergencyRoles = @($roleFootprints[$emergencyKey])
        foreach ($referenceRole in $referenceRoles) {
            [pscustomobject]@{
                ReferenceAdministrator = $UserPrincipalName
                EmergencyAccount       = $emergencyUpn
                RoleName               = $referenceRole.RoleName
                RoleDefinitionId       = $referenceRole.RoleDefinitionId
                DirectoryScope         = $referenceRole.DirectoryScope
                EmergencyHasAssignment = @($emergencyRoles | Where-Object Key -eq $referenceRole.Key).Count -gt 0
                Interpretation          = "Informational only; permanent active Global Administrator is the emergency-access baseline."
            }
        }
    }

    $emergencyGroupAudit = @()
    $deviceCodePolicy = Get-DeviceCodePolicy
    if ($null -ne $deviceCodePolicy) {
        $excludedGroupIds = @($deviceCodePolicy.conditions.users.excludeGroups | Where-Object { $_ })
        $expectedEmergencyUpns = @($EmergencyAccessUpn | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)

        $emergencyGroupAudit = foreach ($groupId in $excludedGroupIds) {
            $group = Invoke-MgGraphRequest -Method GET -Uri (
                "https://graph.microsoft.com/v1.0/groups/${groupId}?" +
                "`$select=id,displayName,securityEnabled,groupTypes,membershipRule,isAssignableToRole"
            )
            $directMembers = @(Get-GraphCollection -Uri (
                "https://graph.microsoft.com/v1.0/groups/$groupId/members/microsoft.graph.user?" +
                "`$select=id,displayName,userPrincipalName,accountEnabled&`$top=999"
            ))
            $directMemberUpns = @(
                $directMembers |
                ForEach-Object { Get-GraphResponseProperty -Response $_ -Name "userPrincipalName" } |
                Where-Object { $_ } |
                ForEach-Object { $_.ToLowerInvariant() } |
                Sort-Object -Unique
            )
            $missingExpected = @($expectedEmergencyUpns | Where-Object { $directMemberUpns -notcontains $_ })
            $unexpectedMembers = @($directMemberUpns | Where-Object { $expectedEmergencyUpns -notcontains $_ })
            $groupTypes = @(Get-GraphResponseProperty -Response $group -Name "groupTypes")

            [pscustomobject]@{
                PolicyName                    = $deviceCodePolicy.displayName
                PolicyId                      = $deviceCodePolicy.id
                ExcludedGroupId               = Get-GraphResponseProperty -Response $group -Name "id"
                ExcludedGroupName             = Get-GraphResponseProperty -Response $group -Name "displayName"
                SecurityEnabled               = Get-GraphResponseProperty -Response $group -Name "securityEnabled"
                DynamicMembership             = $groupTypes -contains "DynamicMembership"
                MembershipRule                = Get-GraphResponseProperty -Response $group -Name "membershipRule"
                IsAssignableToRole            = Get-GraphResponseProperty -Response $group -Name "isAssignableToRole"
                ExpectedEmergencyAccounts     = $expectedEmergencyUpns -join "; "
                DirectMemberAccounts          = $directMemberUpns -join "; "
                AllExpectedAreDirectMembers   = $missingExpected.Count -eq 0
                MissingExpectedAccounts       = $missingExpected -join "; "
                UnexpectedDirectMemberAccounts = $unexpectedMembers -join "; "
                DirectMemberCount             = $directMemberUpns.Count
            }
        }
    }

    Write-JsonEvidence -Data $rawRecords.ToArray() `
        -Path (Join-Path $script:Paths.Identity "Emergency-Access-Audit-Raw.json") `
        -Component "EmergencyAccess" -Description "Raw users, role schedules, and authentication methods" `
        -RecordCount $rawRecords.Count -Source "Microsoft Graph"
    Export-CsvEvidence -Data $summaryRows.ToArray() `
        -Path (Join-Path $script:Paths.Identity "Emergency-Access-Account-Audit.csv") `
        -Component "EmergencyAccess" -Description "Emergency-access account readiness summary"
    Export-CsvEvidence -Data $comparisonRows `
        -Path (Join-Path $script:Paths.Identity "Emergency-Access-Entra-Role-Comparison.csv") `
        -Component "EmergencyAccess" -Description "Informational comparison to reference administrator active Entra roles"
    Export-CsvEvidence -Data $emergencyGroupAudit `
        -Path (Join-Path $script:Paths.Identity "Emergency-Access-Conditional-Access-Group-Audit.csv") `
        -Component "EmergencyAccess" -Description "Direct membership audit of groups excluded by the named device-code policy"

    return [pscustomobject]@{
        AccountAudit = $summaryRows.ToArray()
        ConditionalAccessExcludedGroupAudit = @($emergencyGroupAudit)
    }
}

function Test-EmergencyAccessConditionalAccess {
    [CmdletBinding()]
    param()

    if ($EmergencyAccessUpn.Count -lt 1) {
        throw "Specify at least one emergency-access account with -EmergencyAccessUpn. Two are recommended."
    }

    $resourceDefinitions = @(
        [pscustomobject]@{
            Name  = "Azure Resource Manager"
            AppId = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
        },
        [pscustomobject]@{
            Name  = "Microsoft Graph"
            AppId = "00000003-0000-0000-c000-000000000000"
        },
        [pscustomobject]@{
            Name  = "Exchange Online"
            AppId = "00000002-0000-0ff1-ce00-000000000000"
        },
        [pscustomobject]@{
            Name  = "SharePoint Online"
            AppId = "00000003-0000-0ff1-ce00-000000000000"
        }
    )

    $scenarioTemplates = @(
        [pscustomobject]@{
            Name = "Windows browser baseline"; DevicePlatform = "windows"; ClientAppType = "browser"
            SignInRisk = $null; UserRisk = $null; AuthenticationFlow = $null; DeviceState = $null
        },
        [pscustomobject]@{
            Name = "Windows desktop client"; DevicePlatform = "windows"; ClientAppType = "mobileAppsAndDesktopClients"
            SignInRisk = $null; UserRisk = $null; AuthenticationFlow = $null; DeviceState = $null
        },
        [pscustomobject]@{
            Name = "macOS browser"; DevicePlatform = "macOS"; ClientAppType = "browser"
            SignInRisk = $null; UserRisk = $null; AuthenticationFlow = $null; DeviceState = $null
        },
        [pscustomobject]@{
            Name = "Linux browser"; DevicePlatform = "linux"; ClientAppType = "browser"
            SignInRisk = $null; UserRisk = $null; AuthenticationFlow = $null; DeviceState = $null
        },
        [pscustomobject]@{
            Name = "iOS browser"; DevicePlatform = "iOS"; ClientAppType = "browser"
            SignInRisk = $null; UserRisk = $null; AuthenticationFlow = $null; DeviceState = $null
        },
        [pscustomobject]@{
            Name = "Android browser"; DevicePlatform = "android"; ClientAppType = "browser"
            SignInRisk = $null; UserRisk = $null; AuthenticationFlow = $null; DeviceState = $null
        },
        [pscustomobject]@{
            Name = "High-risk Windows browser"; DevicePlatform = "windows"; ClientAppType = "browser"
            SignInRisk = "high"; UserRisk = "high"; AuthenticationFlow = $null; DeviceState = $null
        },
        [pscustomobject]@{
            Name = "Noncompliant unregistered Windows browser"; DevicePlatform = "windows"; ClientAppType = "browser"
            SignInRisk = $null; UserRisk = $null; AuthenticationFlow = $null; DeviceState = "NoncompliantOrUnregistered"
        },
        [pscustomobject]@{
            Name = "Windows device code flow"; DevicePlatform = "windows"; ClientAppType = "mobileAppsAndDesktopClients"
            SignInRisk = $null; UserRisk = $null; AuthenticationFlow = "deviceCodeFlow"; DeviceState = $null
        }
    )

    $scenarios = [System.Collections.Generic.List[object]]::new()
    foreach ($resource in $resourceDefinitions) {
        foreach ($template in $scenarioTemplates) {
            [void]$scenarios.Add([pscustomobject]@{
                Name               = "$($template.Name) - $($resource.Name)"
                ContextType        = "Application"
                ResourceName       = $resource.Name
                ResourceAppId      = $resource.AppId
                UserAction         = $null
                DevicePlatform     = $template.DevicePlatform
                ClientAppType      = $template.ClientAppType
                SignInRisk         = $template.SignInRisk
                UserRisk           = $template.UserRisk
                AuthenticationFlow = $template.AuthenticationFlow
                DeviceState        = $template.DeviceState
                IpAddress          = $null
            })
        }

        foreach ($ipAddress in @($SuspectIpAddress | Where-Object { $_ })) {
            [void]$scenarios.Add([pscustomobject]@{
                Name               = "Specified IP $ipAddress - $($resource.Name)"
                ContextType        = "Application"
                ResourceName       = $resource.Name
                ResourceAppId      = $resource.AppId
                UserAction         = $null
                DevicePlatform     = "windows"
                ClientAppType      = "browser"
                SignInRisk         = $null
                UserRisk           = $null
                AuthenticationFlow = $null
                DeviceState        = $null
                IpAddress          = $ipAddress
            })
        }
    }

    [void]$scenarios.Add([pscustomobject]@{
        Name               = "Register security information"
        ContextType        = "UserAction"
        ResourceName       = "Register security information"
        ResourceAppId      = $null
        UserAction         = "registerSecurityInformation"
        DevicePlatform     = "windows"
        ClientAppType      = "browser"
        SignInRisk         = $null
        UserRisk           = $null
        AuthenticationFlow = $null
        DeviceState        = $null
        IpAddress          = $null
    })

    $policies = @(Get-GraphCollection -Uri (
        "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$top=999"
    ))
    $policyById = @{}
    foreach ($policy in $policies) {
        $policyId = Get-GraphResponseProperty -Response $policy -Name "id"
        if ($policyId) { $policyById[$policyId.ToString()] = $policy }
    }

    $rawEvaluations = [System.Collections.Generic.List[object]]::new()
    $scenarioRows = [System.Collections.Generic.List[object]]::new()
    $appliedPolicyRows = [System.Collections.Generic.List[object]]::new()
    $unresolvedPolicyRows = [System.Collections.Generic.List[object]]::new()

    foreach ($upn in @($EmergencyAccessUpn | ForEach-Object { $_.Trim() } | Sort-Object -Unique)) {
        if ($upn -notmatch '^[^@\s<>]+@[^@\s<>]+$') {
            throw "Account value '$upn' is not a valid exact userPrincipalName."
        }
        $user = Resolve-IncidentUser -Upn $upn
        $userId = Get-GraphResponseProperty -Response $user -Name "id"
        $resolvedUpn = Get-GraphResponseProperty -Response $user -Name "userPrincipalName"

        foreach ($scenario in $scenarios) {
            $signInConditions = [ordered]@{
                devicePlatform = $scenario.DevicePlatform
                clientAppType  = $scenario.ClientAppType
            }
            if ($scenario.SignInRisk) { $signInConditions.signInRiskLevel = $scenario.SignInRisk }
            if ($scenario.UserRisk) { $signInConditions.userRiskLevel = $scenario.UserRisk }
            if ($scenario.IpAddress) { $signInConditions.ipAddress = $scenario.IpAddress }
            if ($scenario.AuthenticationFlow) {
                $signInConditions.authenticationFlow = @{
                    transferMethod = $scenario.AuthenticationFlow
                }
            }
            if ($scenario.DeviceState -eq "NoncompliantOrUnregistered") {
                $signInConditions.deviceInfo = @{
                    isCompliant = $false
                }
            }

            $signInContext = if ($scenario.ContextType -eq "UserAction") {
                @{
                    "@odata.type" = "#microsoft.graph.userActionContext"
                    userAction    = $scenario.UserAction
                }
            }
            else {
                @{
                    "@odata.type"       = "#microsoft.graph.applicationContext"
                    includeApplications = @($scenario.ResourceAppId)
                }
            }

            $request = [ordered]@{
                signInIdentity = @{
                    "@odata.type" = "#microsoft.graph.userSignIn"
                    userId         = $userId
                }
                signInContext      = $signInContext
                signInConditions   = $signInConditions
                appliedPoliciesOnly = $false
            }

            try {
                $response = Invoke-MgGraphRequest -Method POST `
                    -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/evaluate" `
                    -Body ($request | ConvertTo-Json -Depth 30) -ContentType "application/json" `
                    -ErrorAction Stop
                $items = @(Get-GraphResponseProperty -Response $response -Name "value")
                $appliedItems = @($items | Where-Object {
                    (Get-GraphResponseProperty -Response $_ -Name "policyApplies") -eq $true
                })
                $unresolvedItems = @($items | Where-Object {
                    $reason = Get-GraphResponseProperty -Response $_ -Name "analysisReasons"
                    (Get-GraphResponseProperty -Response $_ -Name "policyApplies") -ne $true -and
                    $reason -in @("notEnoughInformation", "invalidCondition", "invalidPolicy", "unknownFutureValue")
                })

                [void]$rawEvaluations.Add([pscustomobject]@{
                    UserPrincipalName = $resolvedUpn
                    Scenario          = $scenario
                    Request           = $request
                    Response          = $response
                    Error             = $null
                })

                $enabledCount = 0
                $reportOnlyCount = 0
                $unknownCount = 0
                $explicitBlockCount = 0
                $unresolvedEnabledOrUnknownCount = 0
                foreach ($item in $appliedItems) {
                    $itemPolicyId = Get-GraphResponseProperty -Response $item -Name "id"
                    $sourcePolicy = if ($itemPolicyId -and $policyById.ContainsKey($itemPolicyId.ToString())) {
                        $policyById[$itemPolicyId.ToString()]
                    }
                    else { $null }

                    $policyName = if ($null -ne $sourcePolicy) {
                        Get-GraphResponseProperty -Response $sourcePolicy -Name "displayName"
                    }
                    else { Get-GraphResponseProperty -Response $item -Name "displayName" }
                    $policyState = if ($null -ne $sourcePolicy) {
                        Get-GraphResponseProperty -Response $sourcePolicy -Name "state"
                    }
                    else { Get-GraphResponseProperty -Response $item -Name "state" }
                    if (-not $policyState) { $policyState = "Unknown" }

                    $grantControls = Get-GraphResponseProperty -Response $item -Name "grantControls"
                    if ($null -eq $grantControls -and $null -ne $sourcePolicy) {
                        $grantControls = Get-GraphResponseProperty -Response $sourcePolicy -Name "grantControls"
                    }
                    $builtInControls = if ($null -ne $grantControls) {
                        @(Get-GraphResponseProperty -Response $grantControls -Name "builtInControls")
                    }
                    else { @() }
                    $authenticationStrength = if ($null -ne $grantControls) {
                        Get-GraphResponseProperty -Response $grantControls -Name "authenticationStrength"
                    }
                    else { $null }
                    $authenticationStrengthId = if ($null -ne $authenticationStrength) {
                        Get-GraphResponseProperty -Response $authenticationStrength -Name "id"
                    }
                    else { $null }
                    $sessionControls = Get-GraphResponseProperty -Response $item -Name "sessionControls"
                    if ($null -eq $sessionControls -and $null -ne $sourcePolicy) {
                        $sessionControls = Get-GraphResponseProperty -Response $sourcePolicy -Name "sessionControls"
                    }
                    $explicitBlock = $builtInControls -contains "block"

                    switch ($policyState) {
                        "enabled" { $enabledCount++ }
                        "enabledForReportingButNotEnforced" { $reportOnlyCount++ }
                        default { $unknownCount++ }
                    }
                    if ($policyState -eq "enabled" -and $explicitBlock) { $explicitBlockCount++ }

                    [void]$appliedPolicyRows.Add([pscustomobject]@{
                        UserPrincipalName      = $resolvedUpn
                        Scenario               = $scenario.Name
                        Resource               = $scenario.ResourceName
                        ResourceAppId          = $scenario.ResourceAppId
                        IpAddress              = $scenario.IpAddress
                        PolicyName             = $policyName
                        PolicyId               = $itemPolicyId
                        PolicyState            = $policyState
                        ExplicitBlock          = $explicitBlock
                        GrantOperator          = if ($null -ne $grantControls) { Get-GraphResponseProperty -Response $grantControls -Name "operator" }
                        BuiltInGrantControls   = Join-IncidentValues $builtInControls
                        AuthenticationStrength = $authenticationStrengthId
                        HasSessionControls     = $null -ne $sessionControls
                        AnalysisReasons        = Join-IncidentValues (Get-GraphResponseProperty -Response $item -Name "analysisReasons")
                    })
                }

                foreach ($item in $unresolvedItems) {
                    $itemPolicyId = Get-GraphResponseProperty -Response $item -Name "id"
                    $sourcePolicy = if ($itemPolicyId -and $policyById.ContainsKey($itemPolicyId.ToString())) {
                        $policyById[$itemPolicyId.ToString()]
                    }
                    else { $null }
                    $policyName = if ($null -ne $sourcePolicy) {
                        Get-GraphResponseProperty -Response $sourcePolicy -Name "displayName"
                    }
                    else { Get-GraphResponseProperty -Response $item -Name "displayName" }
                    $policyState = if ($null -ne $sourcePolicy) {
                        Get-GraphResponseProperty -Response $sourcePolicy -Name "state"
                    }
                    else { Get-GraphResponseProperty -Response $item -Name "state" }
                    if (-not $policyState) { $policyState = "Unknown" }
                    if ($policyState -in @("enabled", "Unknown", "unknownFutureValue")) {
                        $unresolvedEnabledOrUnknownCount++
                    }

                    [void]$unresolvedPolicyRows.Add([pscustomobject]@{
                        UserPrincipalName = $resolvedUpn
                        Scenario          = $scenario.Name
                        Resource          = $scenario.ResourceName
                        ResourceAppId     = $scenario.ResourceAppId
                        IpAddress         = $scenario.IpAddress
                        PolicyName        = $policyName
                        PolicyId          = $itemPolicyId
                        PolicyState       = $policyState
                        AnalysisReasons   = Get-GraphResponseProperty -Response $item -Name "analysisReasons"
                    })
                }

                [void]$scenarioRows.Add([pscustomobject]@{
                    UserPrincipalName       = $resolvedUpn
                    Scenario                = $scenario.Name
                    Resource                = $scenario.ResourceName
                    ResourceAppId           = $scenario.ResourceAppId
                    DevicePlatform          = $scenario.DevicePlatform
                    ClientAppType           = $scenario.ClientAppType
                    SignInRisk              = $scenario.SignInRisk
                    UserRisk                = $scenario.UserRisk
                    AuthenticationFlow      = $scenario.AuthenticationFlow
                    DeviceState             = $scenario.DeviceState
                    IpAddress               = $scenario.IpAddress
                    EvaluationSucceeded     = $true
                    AppliedPolicyCount      = $appliedItems.Count
                    EnabledPolicyCount      = $enabledCount
                    ReportOnlyPolicyCount   = $reportOnlyCount
                    UnknownStatePolicyCount = $unknownCount
                    EnabledExplicitBlocks   = $explicitBlockCount
                    UnresolvedEnabledOrUnknownPolicies = $unresolvedEnabledOrUnknownCount
                    Error                   = $null
                })
            }
            catch {
                [void]$rawEvaluations.Add([pscustomobject]@{
                    UserPrincipalName = $resolvedUpn
                    Scenario          = $scenario
                    Request           = $request
                    Response          = $null
                    Error             = $_.Exception.Message
                })
                [void]$scenarioRows.Add([pscustomobject]@{
                    UserPrincipalName       = $resolvedUpn
                    Scenario                = $scenario.Name
                    Resource                = $scenario.ResourceName
                    ResourceAppId           = $scenario.ResourceAppId
                    DevicePlatform          = $scenario.DevicePlatform
                    ClientAppType           = $scenario.ClientAppType
                    SignInRisk              = $scenario.SignInRisk
                    UserRisk                = $scenario.UserRisk
                    AuthenticationFlow      = $scenario.AuthenticationFlow
                    DeviceState             = $scenario.DeviceState
                    IpAddress               = $scenario.IpAddress
                    EvaluationSucceeded     = $false
                    AppliedPolicyCount      = $null
                    EnabledPolicyCount      = $null
                    ReportOnlyPolicyCount   = $null
                    UnknownStatePolicyCount = $null
                    EnabledExplicitBlocks   = $null
                    UnresolvedEnabledOrUnknownPolicies = $null
                    Error                   = $_.Exception.Message
                })
                Write-IncidentLog -Level WARN -Message (
                    "Conditional Access What If failed for '$resolvedUpn', scenario '$($scenario.Name)': " +
                    $_.Exception.Message
                )
            }
        }
    }

    $accountSummary = foreach ($upn in @($EmergencyAccessUpn | ForEach-Object { $_.Trim() } | Sort-Object -Unique)) {
        $resolved = @($scenarioRows | Where-Object UserPrincipalName -IEQ $upn | Select-Object -First 1)
        $summaryUpn = if ($resolved.Count -gt 0) { $resolved[0].UserPrincipalName } else { $upn }
        $accountScenarios = @($scenarioRows | Where-Object UserPrincipalName -IEQ $summaryUpn)
        $accountPolicies = @($appliedPolicyRows | Where-Object UserPrincipalName -IEQ $summaryUpn)
        $enabledPolicies = @($accountPolicies | Where-Object PolicyState -EQ "enabled" |
            Select-Object PolicyId,PolicyName -Unique)
        $reportOnlyPolicies = @($accountPolicies | Where-Object PolicyState -EQ "enabledForReportingButNotEnforced" |
            Select-Object PolicyId,PolicyName -Unique)
        $unknownPolicies = @($accountPolicies | Where-Object PolicyState -EQ "Unknown" |
            Select-Object PolicyId,PolicyName -Unique)
        $enabledBlocks = @($accountPolicies | Where-Object {
            $_.PolicyState -eq "enabled" -and $_.ExplicitBlock
        } | Select-Object PolicyId,PolicyName -Unique)
        $unresolvedPolicies = @($unresolvedPolicyRows | Where-Object {
            $_.UserPrincipalName -ieq $summaryUpn -and
            $_.PolicyState -in @("enabled", "Unknown", "unknownFutureValue")
        } | Select-Object PolicyId,PolicyName -Unique)
        $evaluationErrors = @($accountScenarios | Where-Object EvaluationSucceeded -EQ $false)

        [pscustomobject]@{
            UserPrincipalName                 = $summaryUpn
            ScenariosEvaluated                = $accountScenarios.Count
            ScenarioErrors                    = $evaluationErrors.Count
            EnabledPoliciesApplied            = $enabledPolicies.Count
            EnabledPolicyNames                = Join-IncidentValues $enabledPolicies.PolicyName
            ReportOnlyPoliciesApplied         = $reportOnlyPolicies.Count
            ReportOnlyPolicyNames             = Join-IncidentValues $reportOnlyPolicies.PolicyName
            UnknownStatePoliciesApplied       = $unknownPolicies.Count
            UnknownStatePolicyNames           = Join-IncidentValues $unknownPolicies.PolicyName
            EnabledExplicitBlockPolicies      = $enabledBlocks.Count
            EnabledExplicitBlockPolicyNames   = Join-IncidentValues $enabledBlocks.PolicyName
            UnresolvedEnabledOrUnknownPolicies = $unresolvedPolicies.Count
            UnresolvedPolicyNames             = Join-IncidentValues $unresolvedPolicies.PolicyName
            NoEnabledOrUnknownPolicyApplies   = $enabledPolicies.Count -eq 0 -and $unknownPolicies.Count -eq 0
            EvaluationComplete                = $evaluationErrors.Count -eq 0
            EmergencyAccessCaReadinessPass    = $enabledPolicies.Count -eq 0 -and
                $unknownPolicies.Count -eq 0 -and $unresolvedPolicies.Count -eq 0 -and
                $evaluationErrors.Count -eq 0
        }
    }

    $coverage = [ordered]@{
        EvidenceGeneratedUtc = (Get-Date).ToUniversalTime().ToString("o")
        TenantId             = (Get-MgContext).TenantId
        ExportingAccount     = (Get-MgContext).Account
        EmergencyAccounts   = @($EmergencyAccessUpn)
        ResourcesEvaluated  = @($resourceDefinitions | ForEach-Object { "$($_.Name) [$($_.AppId)]" })
        SpecifiedIpAddresses = @($SuspectIpAddress)
        ScenarioCountPerUser = $scenarios.Count
        Interpretation       = (
            "Pass means no enabled or unknown-state Conditional Access policy applied in any tested scenario. " +
            "It also means no enabled or unknown-state policy was unresolved because the evaluator lacked " +
            "information. Report-only policies are listed because enabling them later could change emergency access."
        )
        Limitation           = (
            "Conditional Access is contextual. This matrix materially reduces manual review but cannot prove " +
            "every possible future application, named location, authentication context, device, risk, service " +
            "dependency, or policy change. Independently test each emergency account and monitor it."
        )
    }

    Write-JsonEvidence -Data $policies `
        -Path (Join-Path $script:Paths.ConditionalAccess "Emergency-Access-CA-Policies-Raw.json") `
        -Component "EmergencyAccess" -Description "Conditional Access policies at evaluation time" `
        -RecordCount $policies.Count -Source "Microsoft Graph /identity/conditionalAccess/policies"
    Write-JsonEvidence -Data $rawEvaluations.ToArray() `
        -Path (Join-Path $script:Paths.ConditionalAccess "Emergency-Access-CA-WhatIf-Raw.json") `
        -Component "EmergencyAccess" -Description "Raw Conditional Access What If requests and responses" `
        -RecordCount $rawEvaluations.Count -Source "Microsoft Graph /identity/conditionalAccess/evaluate"
    Export-CsvEvidence -Data $scenarioRows.ToArray() `
        -Path (Join-Path $script:Paths.ConditionalAccess "Emergency-Access-CA-Scenario-Summary.csv") `
        -Component "EmergencyAccess" -Description "Scenario-by-scenario Conditional Access results"
    Export-CsvEvidence -Data $appliedPolicyRows.ToArray() `
        -Path (Join-Path $script:Paths.ConditionalAccess "Emergency-Access-CA-Applied-Policies.csv") `
        -Component "EmergencyAccess" -Description "Policies applying to emergency accounts in tested scenarios"
    Export-CsvEvidence -Data $unresolvedPolicyRows.ToArray() `
        -Path (Join-Path $script:Paths.ConditionalAccess "Emergency-Access-CA-Unresolved-Policies.csv") `
        -Component "EmergencyAccess" -Description "Policies the What If evaluator could not conclusively evaluate"
    Export-CsvEvidence -Data $accountSummary `
        -Path (Join-Path $script:Paths.ConditionalAccess "Emergency-Access-CA-Account-Summary.csv") `
        -Component "EmergencyAccess" -Description "Emergency account Conditional Access readiness summary"
    Write-JsonEvidence -Data $coverage `
        -Path (Join-Path $script:Paths.ConditionalAccess "Emergency-Access-CA-Coverage.json") `
        -Component "EmergencyAccess" -Description "Conditional Access matrix coverage and limitations" -RecordCount 1

    return [pscustomobject]@{
        AccountSummary = @($accountSummary)
        Coverage       = [pscustomobject]$coverage
    }
}

function Invoke-ReadOnlyCollection {
    [CmdletBinding()]
    param()

    $graphComponents = @("Identity", "DirectoryAudit", "Applications", "Devices", "ConditionalAccess")
    $exchangeComponents = @("Mailbox", "UnifiedAudit", "MessageTrace")
    $needGraph = @($Components | Where-Object { $_ -in $graphComponents }).Count -gt 0
    $needExchange = @($Components | Where-Object { $_ -in $exchangeComponents }).Count -gt 0

    $graphAvailable = $false
    if ($needGraph) {
        try {
            Connect-IncidentGraph
            $graphAvailable = $true
        }
        catch {
            Add-CollectionError -Component "Graph" -Step "Connect" -ErrorRecord $_
            Write-IncidentLog -Level WARN -Message "Graph collection will be skipped: $($_.Exception.Message)"
        }
    }

    if ($graphAvailable) {
        if ($Components -contains "Identity") {
            Invoke-CollectionStep -Component "Identity" -Name "Collect user and source-IP sign-ins" `
                -ScriptBlock { Collect-IdentityEvidence }
        }
        if ($Components -contains "DirectoryAudit") {
            Invoke-CollectionStep -Component "DirectoryAudit" -Name "Collect directory audit history" `
                -ScriptBlock { Collect-DirectoryAuditEvidence }
        }
        if ($Components -contains "Applications") {
            Invoke-CollectionStep -Component "Applications" -Name "Collect app consent and assignments" `
                -ScriptBlock { Collect-ApplicationEvidence }
        }
        if ($Components -contains "Devices") {
            Invoke-CollectionStep -Component "Devices" -Name "Collect devices and tenant device-code sign-ins" `
                -ScriptBlock { Collect-DeviceEvidence }
        }
        if ($Components -contains "ConditionalAccess") {
            Invoke-CollectionStep -Component "ConditionalAccess" -Name "Export Conditional Access snapshot" `
                -ScriptBlock { Collect-ConditionalAccessSnapshot }
        }
    }

    $exchangeAvailable = $false
    $mailboxContext = $null
    if ($needExchange) {
        try {
            Connect-IncidentExchange
            $exchangeAvailable = $true
            $mailboxContext = Get-IncidentMailboxContext
        }
        catch {
            Add-CollectionError -Component "Exchange" -Step "Connect and resolve mailbox" -ErrorRecord $_
            Write-IncidentLog -Level WARN -Message "Exchange collection will be skipped: $($_.Exception.Message)"
        }
    }

    if ($exchangeAvailable) {
        if ($Components -contains "Mailbox") {
            Invoke-CollectionStep -Component "Mailbox" -Name "Collect current mailbox state" `
                -ScriptBlock { Collect-MailboxCurrentState -MailboxContext $mailboxContext }
        }
        if ($Components -contains "UnifiedAudit") {
            Invoke-CollectionStep -Component "UnifiedAudit" -Name "Collect mailbox and configuration audit events" `
                -ScriptBlock { Collect-UnifiedAuditEvidence -MailboxContext $mailboxContext }
        }
        if ($Components -contains "MessageTrace") {
            Invoke-CollectionStep -Component "MessageTrace" -Name "Collect outbound trace and campaign recipients" `
                -ScriptBlock { Collect-MessageTraceEvidence -MailboxContext $mailboxContext }
        }
    }
}

$fatalError = $null
try {
    Initialize-EvidenceRun

    switch ($Action) {
        "Collect" {
            Invoke-ReadOnlyCollection
        }
        "CreateDeviceCodePolicyReportOnly" {
            Connect-IncidentGraph -ConditionalAccessWrite
            $policy = New-DeviceCodePolicyReportOnly
            if ($null -ne $policy) { Export-DeviceCodePolicyProof -Policy $policy | Format-List }
        }
        "ExportDeviceCodePolicyProof" {
            Connect-IncidentGraph
            $policy = Get-DeviceCodePolicy
            if ($null -eq $policy) { throw "No policy named '$PolicyName' was found." }
            Export-DeviceCodePolicyProof -Policy $policy | Format-List
        }
        "EnableDeviceCodePolicy" {
            Connect-IncidentGraph -ConditionalAccessWrite
            $policy = Get-DeviceCodePolicy
            if ($null -eq $policy) { throw "No policy named '$PolicyName' was found." }
            $enabledPolicy = Enable-DeviceCodePolicy -Policy $policy
            if ($null -ne $enabledPolicy) { Export-DeviceCodePolicyProof -Policy $enabledPolicy | Format-List }
        }
        "CollectDeviceCodePolicyEnforcementEvidence" {
            Connect-IncidentGraph
            $policy = Get-DeviceCodePolicy
            if ($null -eq $policy) { throw "No policy named '$PolicyName' was found." }
            Collect-DeviceCodeEnforcementEvidence -Policy $policy | Format-List
        }
        "AuditEmergencyAccessAccounts" {
            Connect-IncidentGraph -EmergencyAccessAudit
            Invoke-CollectionStep -Component "EmergencyAccess" -Name "Audit emergency-access accounts" `
                -Fatal -ScriptBlock {
                    $auditResult = Collect-EmergencyAccessAccountAudit
                    $auditResult.AccountAudit | Format-List
                    $auditResult.ConditionalAccessExcludedGroupAudit | Format-List
                }
        }
        "AuditEmergencyAccessConditionalAccess" {
            Connect-IncidentGraph
            Invoke-CollectionStep -Component "EmergencyAccess" `
                -Name "Evaluate emergency-access accounts against Conditional Access" `
                -Fatal -ScriptBlock {
                    $auditResult = Test-EmergencyAccessConditionalAccess
                    $auditResult.AccountSummary | Format-List
                    $auditResult.Coverage | Format-List
                }
        }
    }
}
catch {
    $fatalError = $_
    Add-CollectionError -Component "Run" -Step $Action -ErrorRecord $_
    Write-IncidentLog -Level ERROR -Message "Fatal run error: $($_.Exception.Message)"
}
finally {
    if ($DisconnectWhenFinished) {
        if ($script:ExchangeConnectedByScript) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        }
        if ($script:GraphConnectedByScript) {
            try { Disconnect-MgGraph -ErrorAction Stop | Out-Null }
            catch { Write-IncidentLog -Level WARN -Message "Graph disconnect/cache cleanup warning: $($_.Exception.Message)" }
        }
    }
    if ($script:RunDirectory) { Complete-EvidenceRun }
}

if ($null -ne $fatalError) { throw $fatalError }

[pscustomobject]@{
    Action          = $Action
    TargetUser      = $UserPrincipalName
    OutputDirectory = $script:RunDirectory
    ErrorsRecorded  = $script:CollectionErrors.Count
}
