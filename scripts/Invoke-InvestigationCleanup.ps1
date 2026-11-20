<#
.SYNOPSIS
    Reviews and removes what a Microsoft 365 compromise investigation leaves behind: the broad
    Microsoft Graph Command Line Tools consent grant and the disabled rogue devices.

.DESCRIPTION
    Evidence collection with Microsoft Graph PowerShell consents the Microsoft Graph Command Line
    Tools application to broad delegated scopes (AuditLog.Read.All, Directory.Read.All, and
    often write scopes left over from earlier admin work). That grant outlives the incident.
    This script finds it and removes or trims it, and deletes the rogue devices you disabled
    during containment once you no longer need them as evidence.

    1. Connects to Microsoft Graph with only the scopes the chosen -Action needs (or reuses
       an existing Connect-MgGraph session).
    2. Report (default, read-only): lists every delegated grant held by Microsoft Graph
       Command Line Tools for the target user, flags write and send scopes, warns about any
       tenant-wide admin consent, and lists the user's registered devices with their enabled
       state, OS build, and last sign-in.
    3. RemoveGrant: deletes the user's grants to Microsoft Graph Command Line Tools. The next
       Connect-MgGraph asks for consent again, for only the scopes it requests.
    4. TrimGrant: replaces the scopes on those grants with -KeepScopes.
    5. RemoveDevices: deletes the devices named in -DeviceId, but only if each one is
       registered to the target user and is already disabled.

    ORDER THAT MATTERS:
    Run RemoveGrant last. Connecting with DelegatedPermissionGrant.ReadWrite.All adds that
    scope to the very grant you are cleaning up, so anything you do afterwards in the same
    session re-widens it. The script disconnects from Graph after RemoveGrant or TrimGrant.
    Delete devices only after the evidence export holds them (Invoke-M365IncidentResponse.ps1
    -Action Collect writes Devices.json and the directory audit).

    SAFETY:
    Every change supports -WhatIf and asks for confirmation (ConfirmImpact High). The script
    never changes a tenant-wide (AllPrincipals) admin consent grant; it reports it so an
    administrator can decide deliberately. Enabled devices are never deleted.

.PARAMETER Action
    Report (default), RemoveGrant, TrimGrant, or RemoveDevices.

.PARAMETER UserPrincipalName
    The account whose grant and registered devices are reviewed. Default: the account signed
    in to Microsoft Graph. When the investigator and the compromised user differ, run the grant
    actions for the investigator and RemoveDevices for the compromised user.

.PARAMETER KeepScopes
    Scopes left on the grant by TrimGrant. Default: openid profile offline_access User.Read.

.PARAMETER DeviceId
    Directory object IDs (the Id column in the Report output) of the devices RemoveDevices
    deletes. Required for RemoveDevices; the script never picks devices on its own.

.PARAMETER PassThru
    Returns the report as an object (Grants, AdminConsent, Devices) in addition to the tables.

.EXAMPLE
    .\Invoke-InvestigationCleanup.ps1

    Read-only review of the signed-in account's Graph Command Line Tools grant and registered
    devices. Run this first.

.EXAMPLE
    .\Invoke-InvestigationCleanup.ps1 -Action RemoveDevices -UserPrincipalName alex@somedomainsomewhere.com -DeviceId 1b2c...,7d8e... -WhatIf

    Shows which disabled devices would be deleted without deleting them. Remove -WhatIf to
    delete after you confirm the evidence export holds them.

.EXAMPLE
    .\Invoke-InvestigationCleanup.ps1 -Action RemoveGrant -WhatIf

    Shows the grant that would be deleted. Run it again without -WhatIf as the last step of the
    cleanup.

.EXAMPLE
    .\Invoke-InvestigationCleanup.ps1 -Action TrimGrant -KeepScopes "openid profile offline_access User.Read AuditLog.Read.All"

    Keeps the grant but cuts it down to sign-in plus one read scope you still need.

.NOTES
    Script Name  : Invoke-InvestigationCleanup.ps1
    Version      : 1.0.1
    Author       : John O'Neill Sr.
    Company      : Azure Innovators
    Website      : https://www.azureinnovators.com
    Blog         : https://azureinnovators.com/blog

    Prerequisites:
    - PowerShell 7 or later and the Microsoft.Graph.Authentication module
    - Report: DelegatedPermissionGrant.Read.All, Application.Read.All, User.Read.All,
      Device.Read.All (Global Reader is enough)
    - RemoveGrant / TrimGrant: DelegatedPermissionGrant.ReadWrite.All (Privileged Role
      Administrator or Cloud Application Administrator)
    - RemoveDevices: Device.ReadWrite.All (Cloud Device Administrator or Intune Administrator)
    - Run from a trusted admin workstation; test in a nonproduction tenant first

    Change Log:
    v1.0.0 - 2026-11-06 - Initial release for the Live! 360 Orlando 2026 keynote download
                          (TM-KEY), as the companion to Invoke-M365IncidentResponse.ps1.
    v1.0.1 - 2026-11-06 - RoleManagement.Read.Directory was flagged as risky because the
                          pattern matched "Manage" inside the scope name; removed that term.
                          Dates now print as yyyy-MM-dd HH:mm UTC so the device table no longer
                          truncates them. Report now warns when a disabled device shows
                          activity inside the 30-day sign-in log window (found on the first
                          live run: a disabled rogue device with a later sign-in date).
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Report', 'RemoveGrant', 'TrimGrant', 'RemoveDevices')]
    [string]$Action = 'Report',
    [string]$UserPrincipalName,
    [string]$KeepScopes = 'openid profile offline_access User.Read',
    [string[]]$DeviceId,
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GraphCliAppId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph Command Line Tools, same in every tenant
$RiskPattern = 'ReadWrite|Write|\.Send|FullControl|AccessAsUser'

if ($Action -eq 'RemoveDevices' -and -not $DeviceId) {
    throw "RemoveDevices needs -DeviceId. Run the default Report first and copy the Id of each disabled rogue device."
}
if ($Action -eq 'TrimGrant' -and [string]::IsNullOrWhiteSpace($KeepScopes)) {
    throw "TrimGrant needs at least one scope in -KeepScopes. Use RemoveGrant to delete the grant instead."
}

#region Connect
$scopes = @('DelegatedPermissionGrant.Read.All', 'Application.Read.All', 'User.Read.All', 'Device.Read.All')
switch ($Action) {
    { $_ -in 'RemoveGrant', 'TrimGrant' } { $scopes += 'DelegatedPermissionGrant.ReadWrite.All' }
    'RemoveDevices' { $scopes += 'Device.ReadWrite.All' }
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
$ctx = Get-MgContext
$connectedHere = $false
if (-not $ctx -or @($scopes | Where-Object { $_ -notin $ctx.Scopes }).Count -gt 0) {
    Write-Host "Connecting to Microsoft Graph with: $($scopes -join ', ')" -ForegroundColor Cyan
    Connect-MgGraph -Scopes $scopes -NoWelcome
    $ctx = Get-MgContext
    $connectedHere = $true
}
if (-not $UserPrincipalName) { $UserPrincipalName = $ctx.Account }
#endregion

function Get-GraphPaged([string]$Uri) {
    $items = [System.Collections.Generic.List[object]]::new()
    while ($Uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        foreach ($v in @($page.value)) { $items.Add($v) }
        $Uri = if ($page.PSObject.Properties['@odata.nextLink']) { $page.'@odata.nextLink' } else { $null }
    }
    return $items
}

#region Gather
$user = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
    -Uri "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($UserPrincipalName))?`$select=id,userPrincipalName"
$sp = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$GraphCliAppId')?`$select=id,displayName"
$allGrants = Get-GraphPaged "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($sp.id)'"

$resourceNames = @{}
function Get-ResourceName([string]$Id) {
    if (-not $resourceNames.ContainsKey($Id)) {
        $r = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$Id`?`$select=displayName"
        $resourceNames[$Id] = $r.displayName
    }
    $resourceNames[$Id]
}
function ConvertTo-GrantRow($g) {
    $list = @($g.scope -split '\s+' | Where-Object { $_ } | Sort-Object -Unique)
    [pscustomobject]@{
        Id          = $g.id
        ConsentType = $g.consentType
        Resource    = Get-ResourceName $g.resourceId
        ScopeCount  = $list.Count
        RiskyScopes = (@($list | Where-Object { $_ -match $RiskPattern }) -join ' ')
        Scopes      = $list -join ' '
    }
}

$userGrants = @($allGrants | Where-Object { $_.consentType -eq 'Principal' -and $_.principalId -eq $user.id } |
    ForEach-Object { ConvertTo-GrantRow $_ })
$adminGrants = @($allGrants | Where-Object { $_.consentType -eq 'AllPrincipals' } | ForEach-Object { ConvertTo-GrantRow $_ })
$otherUsers = @($allGrants | Where-Object { $_.consentType -eq 'Principal' -and $_.principalId -ne $user.id } |
    Select-Object -ExpandProperty principalId -Unique).Count

$devSelect = 'id,deviceId,displayName,accountEnabled,operatingSystem,operatingSystemVersion,approximateLastSignInDateTime,trustType,isManaged,isCompliant'
$devices = @(Get-GraphPaged "https://graph.microsoft.com/v1.0/users/$($user.id)/registeredDevices/microsoft.graph.device?`$select=$devSelect" |
    ForEach-Object {
        [pscustomobject]@{
            Id             = $_.id
            DisplayName    = $_.displayName
            Enabled        = $_.accountEnabled
            OS             = "$($_.operatingSystem) $($_.operatingSystemVersion)".Trim()
            LastSignInUtc  = if ($_.approximateLastSignInDateTime) { ([datetime]$_.approximateLastSignInDateTime).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') } else { '' }
            TrustType      = $_.trustType
            ManagedCompliant = "$($_.isManaged) / $($_.isCompliant)"
        }
    } | Sort-Object Enabled, DisplayName)
#endregion

#region Report
Write-Host "`nMicrosoft Graph Command Line Tools grants for $($user.userPrincipalName)" -ForegroundColor Cyan
if ($userGrants.Count) {
    $userGrants | Format-List Id, Resource, ScopeCount, RiskyScopes, Scopes | Out-Host
} else {
    Write-Host "  None. Nothing to clean up for this account." -ForegroundColor Green
}
if ($adminGrants.Count) {
    Write-Warning "Tenant-wide admin consent exists for Microsoft Graph Command Line Tools ($($adminGrants.Count) grant(s)). It applies to every user. This script reports it but never changes it."
    $adminGrants | Format-List Id, Resource, ScopeCount, RiskyScopes | Out-Host
}
if ($otherUsers) { Write-Host "  $otherUsers other user(s) also hold their own grant to this app." -ForegroundColor DarkGray }

Write-Host "`nRegistered devices for $($user.userPrincipalName)" -ForegroundColor Cyan
if ($devices.Count) {
    $devices | Format-Table Id, DisplayName, Enabled, OS, LastSignInUtc -AutoSize | Out-Host
    $cutoff = (Get-Date).ToUniversalTime().AddDays(-30).ToString('yyyy-MM-dd HH:mm')
    foreach ($r in @($devices | Where-Object { -not $_.Enabled -and $_.LastSignInUtc -and $_.LastSignInUtc -ge $cutoff })) {
        Write-Warning "$($r.DisplayName) is disabled but shows activity on $($r.LastSignInUtc) UTC, inside the 30-day sign-in log window. Investigate it (interactive and non-interactive sign-ins, directory audit) and export the evidence before you delete it."
    }
    $disabled = @($devices | Where-Object { -not $_.Enabled }).Count
    Write-Host "  $disabled disabled. Delete them with -Action RemoveDevices -DeviceId <Id> once the evidence export holds them." -ForegroundColor DarkGray
} else {
    Write-Host "  None." -ForegroundColor Green
}
#endregion

#region Act
switch ($Action) {
    'RemoveGrant' {
        foreach ($g in $userGrants) {
            if ($PSCmdlet.ShouldProcess("$($user.userPrincipalName) -> $($g.Resource) ($($g.ScopeCount) scopes)", 'Delete Graph Command Line Tools grant')) {
                Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($g.Id)"
                Write-Host "Deleted grant $($g.Id) ($($g.Resource))." -ForegroundColor Green
            }
        }
    }
    'TrimGrant' {
        foreach ($g in $userGrants) {
            if ($PSCmdlet.ShouldProcess("$($user.userPrincipalName) -> $($g.Resource)", "Replace $($g.ScopeCount) scopes with '$KeepScopes'")) {
                Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($g.Id)" `
                    -Body (@{ scope = $KeepScopes } | ConvertTo-Json) -ContentType 'application/json'
                Write-Host "Trimmed grant $($g.Id) ($($g.Resource)) to: $KeepScopes" -ForegroundColor Green
            }
        }
    }
    'RemoveDevices' {
        foreach ($id in $DeviceId) {
            $d = $devices | Where-Object { $_.Id -eq $id }
            if (-not $d) { Write-Warning "Skipped $id`: not registered to $($user.userPrincipalName)."; continue }
            if ($d.Enabled) { Write-Warning "Skipped $($d.DisplayName) ($id): still enabled. Disable and preserve it first."; continue }
            if ($PSCmdlet.ShouldProcess("$($d.DisplayName) ($id), $($d.OS)", 'Delete device object')) {
                Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/devices/$id"
                Write-Host "Deleted device $($d.DisplayName) ($id)." -ForegroundColor Green
            }
        }
    }
}
#endregion

if ($Action -in 'RemoveGrant', 'TrimGrant' -and -not $WhatIfPreference) {
    Disconnect-MgGraph | Out-Null
    Write-Host "Disconnected from Microsoft Graph so this session can't re-widen the grant. Access tokens already issued expire within about an hour." -ForegroundColor DarkGray
} elseif ($connectedHere -and $Action -ne 'Report') {
    Disconnect-MgGraph | Out-Null
}

if ($PassThru) {
    [pscustomobject]@{ User = $user.userPrincipalName; Grants = $userGrants; AdminConsent = $adminGrants; Devices = $devices }
}
