<#
.SYNOPSIS
    Presents proof that a Conditional Access policy blocks device code flow, showing only fields
    that are safe to project.

.DESCRIPTION
    Invoke-DeviceCodeProofDemo.ps1 is a presentation wrapper around Invoke-M365IncidentResponse.ps1.
    It runs the collector's read-only proof actions quietly, then prints a short, curated view of
    the evidence they wrote. Tenant IDs, policy and group GUIDs, and run-folder paths stay in the
    evidence files and off the screen.

    1. Proof step: runs -Action ExportDeviceCodePolicyProof and shows the policy name, state,
       targeting, grant control, and the Conditional Access What If result.
    2. Attempt step: prints the exact device-code test the presenter performs in a second window
       with the dedicated test user, and the error that proves the block.
    3. Enforcement step: runs -Action CollectDeviceCodePolicyEnforcementEvidence and shows how many
       recent device-code sign-ins the policy blocked and whether enforcement is proven.
    4. Saved step: shows the same two views from an earlier (rehearsal) evidence run without
       signing in. This is the fallback when venue Wi-Fi or sign-in logs are slow.

    STEPS:
    Proof        Live. Microsoft Graph sign-in required (Policy.Read.All, Directory.Read.All).
    Attempt      Instructions only. Nothing runs.
    Enforcement  Live. Requires AuditLog.Read.All. Sign-in logs can take several minutes to arrive.
    Saved        Offline. Reads the newest proof and enforcement summaries under SavedEvidencePath.
    All          Proof, Attempt, then Enforcement, pausing between them.

    SAFETY:
    Every action used here is read-only. This wrapper never creates, enables, or changes a policy.
    Use a dedicated nonadministrator test user; never the presenter's account or an emergency-access
    account. Never enter a device code received from someone else, on stage or anywhere.

.PARAMETER Step
    Which part to run: Proof, Attempt, Enforcement, Saved, or All. Default: All.

.PARAMETER CollectorPath
    Path to Invoke-M365IncidentResponse.ps1. Default: ..\scripts\ in this repository.

.PARAMETER AdminUpn
    Administrator account that signs in to Microsoft Graph and runs the collector. Required for
    the Proof, Enforcement, and All steps.

.PARAMETER TestUserUpn
    Dedicated nonadministrator test user who attempts the device-code sign-in. Required for the
    Proof, Attempt, Enforcement, and All steps.

.PARAMETER TenantDomain
    Tenant domain shown in the Azure CLI command for the Attempt step (for example
    somedomainsomewhere.onmicrosoft.com). Default: the domain part of TestUserUpn.

.PARAMETER PolicyName
    Conditional Access policy to prove. Default: CA-BLOCK-Device-Code-Flow-All-Users.

.PARAMETER OutputRoot
    Folder where the collector writes its timestamped evidence runs. Default: Evidence-Runs beside
    this script.

.PARAMETER SavedEvidencePath
    Folder searched for earlier proof and enforcement summaries in the Saved step.
    Default: Evidence-Runs beside this script (the same folder
    the live steps write to).

.PARAMETER SignInLookbackMinutes
    How far back the Enforcement step searches for the test sign-in. Default: 30.

.EXAMPLE
    .\Invoke-DeviceCodeProofDemo.ps1 -Step Proof -AdminUpn admin@somedomainsomewhere.com -TestUserUpn ca-test@somedomainsomewhere.com

    Exports fresh policy and What If proof and shows the curated summary. Run this the evening
    before as a rehearsal and again live.

.EXAMPLE
    .\Invoke-DeviceCodeProofDemo.ps1 -Step Enforcement -AdminUpn admin@somedomainsomewhere.com -TestUserUpn ca-test@somedomainsomewhere.com 

    After a rehearsal device-code attempt, collects the blocked sign-in so the Saved step has real
    enforcement evidence to show later without signing in.

.EXAMPLE
    .\Invoke-DeviceCodeProofDemo.ps1 -Step Saved

    Shows the rehearsal proof and enforcement results without any sign-in or network access.

.NOTES
    Script Name  : Invoke-DeviceCodeProofDemo.ps1
    Version      : 1.0.0
    Author       : John O'Neill Sr.
    Company      : Azure Innovators
    Website      : https://www.azureinnovators.com
    Blog         : https://azureinnovators.com/blog

    Prerequisites:
    - PowerShell 7 or later on a trusted administrative workstation
    - Invoke-M365IncidentResponse.ps1 v1.2.0 or later and Microsoft.Graph.Authentication
    - The named policy already exists and is enabled (this wrapper only proves it)
    - Azure CLI in a second window for the Attempt step (any device-code client works)

    Change Log:
    v1.0.0 - 2026-11-05 - Initial release for the Live! 360 Orlando 2026 keynote demo.
#>

[CmdletBinding()]
param(
    [ValidateSet("Proof", "Attempt", "Enforcement", "Saved", "All")]
    [string]$Step = "All",
    [string]$CollectorPath = (Join-Path $PSScriptRoot "..\scripts\Invoke-M365IncidentResponse.ps1"),
    [string]$AdminUpn,
    [string]$TestUserUpn,
    [string]$TenantDomain,
    [string]$PolicyName = "CA-BLOCK-Device-Code-Flow-All-Users",
    [string]$OutputRoot = (Join-Path $PSScriptRoot "Evidence-Runs"),
    [string]$SavedEvidencePath = (Join-Path $PSScriptRoot "Evidence-Runs"),
    [ValidateRange(5, 1440)][int]$SignInLookbackMinutes = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Banner([string]$Text) {
    Write-Host ""
    Write-Host ("=" * 90) -ForegroundColor DarkMagenta
    Write-Host ("  {0}" -f $Text.ToUpperInvariant()) -ForegroundColor Magenta
    Write-Host ("=" * 90) -ForegroundColor DarkMagenta
}
function Write-Field([string]$Name, $Value, [string]$Good) {
    $text = "$Value"
    $color = if ($Good -and $text -eq $Good) { "Green" } elseif ($Good) { "Red" } else { "Gray" }
    Write-Host ("  {0,-28} " -f $Name) -NoNewline -ForegroundColor DarkCyan
    Write-Host $text -ForegroundColor $color
}
function Assert-Value([string]$Name, [string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "-$Name is required for -Step $Step." }
}
function Get-NewestFile([string]$Root, [string]$Name) {
    if (-not (Test-Path -LiteralPath $Root)) { return $null }
    Get-ChildItem -LiteralPath $Root -Recurse -Filter $Name -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
}
function Invoke-Collector([string]$Action) {
    if (-not (Test-Path -LiteralPath $CollectorPath)) { throw "Collector not found: $CollectorPath" }
    $collectorArgs = @{
        Action            = $Action
        UserPrincipalName = $AdminUpn
        TestUserUpn       = $TestUserUpn
        PolicyName        = $PolicyName
        OutputRoot        = $OutputRoot
    }
    if ($Action -eq "CollectDeviceCodePolicyEnforcementEvidence") { $collectorArgs.SignInLookbackMinutes = $SignInLookbackMinutes }
    Write-Host ("  Running the collector ({0})..." -f $Action) -ForegroundColor DarkGray
    # The collector prints run paths and identifiers; keep them in its transcript, not on screen.
    & $CollectorPath @collectorArgs 2>&1 6>&1 | Out-Null
}

function Show-Proof([System.IO.FileInfo]$File) {
    Write-Banner "1  Configuration and What If proof"
    if (-not $File) { Write-Host "  No Device-Code-Policy-Proof-Summary.json found." -ForegroundColor Red; return }
    $p = Get-Content -LiteralPath $File.FullName -Raw | ConvertFrom-Json
    Write-Field "Evidence generated (UTC)" $p.EvidenceGeneratedUTC
    Write-Field "Policy" $p.PolicyName
    Write-Field "State" $p.PolicyState "enabled"
    Write-Field "Includes all users" $p.IncludesAllUsers "True"
    Write-Field "Includes all resources" $p.IncludesAllResources "True"
    Write-Field "Excluded groups" (@($p.ExcludedGroupIds).Count)
    Write-Field "Targets device code flow" $p.TargetsDeviceCodeFlow "True"
    Write-Field "Grant control blocks" $p.GrantControlBlocks "True"
    Write-Field "What If: policy applies" $p.WhatIfPolicyApplies "True"
    Write-Field "What If: grant blocks" $p.WhatIfGrantControlBlocks "True"
    Write-Field "Enforcement configured" $p.EnforcementConfigured "True"
    Write-Host ""
    Write-Host ("  >> {0}" -f $p.EnforcementProofStatement) -ForegroundColor Yellow
}

function Show-Attempt {
    Write-Banner "2  Attempt a device-code sign-in (second window)"
    $domain = if ($TenantDomain) { $TenantDomain } else { ($TestUserUpn -split '@')[-1] }
    Write-Host "  In the second window, run:" -ForegroundColor Gray
    Write-Host ""
    Write-Host ("      az login --use-device-code --allow-no-subscriptions --tenant {0}" -f $domain) -ForegroundColor White
    Write-Host ""
    Write-Host "  Open microsoft.com/devicelogin, enter the code YOU just generated, sign in as" -ForegroundColor Gray
    Write-Host ("  {0}. Expected result:" -f $TestUserUpn) -ForegroundColor Gray
    Write-Host ""
    Write-Host "      AADSTS53003: Access has been blocked by Conditional Access policies." -ForegroundColor Green
    Write-Host ""
    Write-Host "  >> Never enter a device code that someone else sent you." -ForegroundColor Yellow
}

function Show-Enforcement([System.IO.FileInfo]$File) {
    Write-Banner "3  Enforcement proof from the sign-in log"
    if (-not $File) { Write-Host "  No Device-Code-Enforcement-Proof-Summary.json found." -ForegroundColor Red; return }
    $e = Get-Content -LiteralPath $File.FullName -Raw | ConvertFrom-Json
    Write-Field "Evidence generated (UTC)" $e.EvidenceGeneratedUtc
    Write-Field "Policy" $e.PolicyName
    Write-Field "State" $e.PolicyState "enabled"
    Write-Field "Test user" $e.TestUser
    Write-Field "Device-code events found" $e.DeviceCodeEventsFound
    Write-Field "Blocked by this policy" $e.EventsBlockedByThisPolicy
    Write-Field "Enforcement proven" $e.EnforcementProven "True"
    Write-Host ""
    Write-Host "  >> Configuration says it should block. What If says it would. The sign-in log proves it did." -ForegroundColor Yellow
}

switch ($Step) {
    "Proof" {
        Assert-Value "AdminUpn" $AdminUpn; Assert-Value "TestUserUpn" $TestUserUpn
        Invoke-Collector "ExportDeviceCodePolicyProof"
        Show-Proof (Get-NewestFile $OutputRoot "Device-Code-Policy-Proof-Summary.json")
    }
    "Attempt" { Assert-Value "TestUserUpn" $TestUserUpn; Show-Attempt }
    "Enforcement" {
        Assert-Value "AdminUpn" $AdminUpn; Assert-Value "TestUserUpn" $TestUserUpn
        Invoke-Collector "CollectDeviceCodePolicyEnforcementEvidence"
        Show-Enforcement (Get-NewestFile $OutputRoot "Device-Code-Enforcement-Proof-Summary.json")
    }
    "Saved" {
        Show-Proof (Get-NewestFile $SavedEvidencePath "Device-Code-Policy-Proof-Summary.json")
        Show-Enforcement (Get-NewestFile $SavedEvidencePath "Device-Code-Enforcement-Proof-Summary.json")
    }
    "All" {
        Assert-Value "AdminUpn" $AdminUpn; Assert-Value "TestUserUpn" $TestUserUpn
        Invoke-Collector "ExportDeviceCodePolicyProof"
        Show-Proof (Get-NewestFile $OutputRoot "Device-Code-Policy-Proof-Summary.json")
        [void](Read-Host "`n  [Enter] next")
        Show-Attempt
        [void](Read-Host "`n  [Enter] when the block is on screen")
        Invoke-Collector "CollectDeviceCodePolicyEnforcementEvidence"
        $file = Get-NewestFile $OutputRoot "Device-Code-Enforcement-Proof-Summary.json"
        $e = if ($file) { Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json } else { $null }
        if (-not $e -or -not $e.EnforcementProven) {
            Write-Host "  The new sign-in has not reached the log yet; showing the rehearsal run." -ForegroundColor DarkYellow
            $file = Get-NewestFile $SavedEvidencePath "Device-Code-Enforcement-Proof-Summary.json"
        }
        Show-Enforcement $file
    }
}
