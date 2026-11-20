<#
.SYNOPSIS
Prepares, previews, tests, and sends personalized incident notifications through Microsoft Graph
or Azure Communication Services (ACS) SMTP.

.DESCRIPTION
Send-M365IncidentRecipientNotifications.ps1 converts a recipient-address CSV into an operator-
reviewed notification queue and sends one message per recipient through Microsoft Graph or ACS
SMTP. Microsoft Graph remains the default transport for backward compatibility.

Prepare is the default mode and never connects to Microsoft Graph. It validates and deduplicates
the source list, assigns the standard message version, and requires explicit approval in a new CSV.
Preview renders the approved plan without sending. Test sends both template versions to one test
address. Send requires ConfirmSend, prompts once through ShouldProcess, throttles submissions,
records each transport acceptance immediately, and skips previously accepted recipients when the
same output directory is reused.

Microsoft Graph returning 202 Accepted does not prove final delivery. Use Exchange Online message
trace after a Graph run to determine delivery status. ACS SMTP acceptance also does not prove final
delivery. Use ACS Email operational logs, delivery-status events, and diagnostics after an ACS run.

.PARAMETER Mode
Prepare, Preview, Test, or Send. The default is Prepare.

.PARAMETER RecipientCsvPath
Source recipient CSV for Prepare, or the reviewed queue CSV for Preview and Send. Prepare accepts
RecipientAddress, EmailAddress, or Address. Preview and Send require RecipientAddress,
DisplayName, MessageVersion, and SendApproved. DisplayName is optional: executive messages use a
neutral "Hello," greeting when it is blank.

.PARAMETER ReconciliationCsvPath
Optional recipient-level reconciliation CSV for Send. It must contain RecipientAddress,
TraceClassification, and NextAction. Delivered or No-resend rows are always excluded. Failed rows
are eligible for retry even when the address was previously AcceptedByGraph. Unresolved or
contradictory rows block sending. This is safer than the broad
ResendRecipientsPreviouslyAcceptedByGraph switch.

.PARAMETER TemplatePath
Markdown file containing headings named Standard recipient version and Personal follow-up for
executives, security firms, and training partners. Each section must contain a **Subject:** line.
Defaults to templates\Notification-Template.md in this repository. Preview, Test, and Send stop if
any <...> placeholder remains in the template.

.PARAMETER OutputDirectory
Directory for the review queue, previews, plans, and append-only submission logs. Reuse the same
directory when resuming a partially completed Send run.

.PARAMETER SenderUpn
Microsoft Entra sign-in identity. Required for MicrosoftGraph Test and Send; unused for AcsSmtp.

.PARAMETER Transport
MicrosoftGraph or AcsSmtp. Defaults to MicrosoftGraph.

.PARAMETER FromAddress
Address placed in the From field. For MicrosoftGraph it must be a primary or proxy address of the
connected mailbox and defaults to SenderUpn. For AcsSmtp it is required and must exactly match a
MailFrom address configured on the linked ACS Email domain.

.PARAMETER FromDisplayName
Friendly display name used with AcsSmtp. Defaults to Security Incident Notice.

.PARAMETER ReplyToAddress
Optional reply address. It is supported by both transports. For ACS, use a monitored mailbox that
can receive responses even when the original Microsoft 365 mailbox is restricted from sending.

.PARAMETER TestRecipient
Address that receives both message versions in Test mode.

.PARAMETER ConfirmSend
Required explicit acknowledgement for Send mode. The script then presents one batch-level
PowerShell confirmation. Do not add the common -Confirm parameter; it is unnecessary.

.PARAMETER DelaySeconds
Delay between submissions. Defaults to 6 seconds.

.PARAMETER BatchSize
Number of processed submissions before an additional batch pause. Defaults to 25 for Graph. When
AcsSmtp is selected and this parameter is not explicitly supplied, the effective default is 15.

.PARAMETER BatchPauseSeconds
Additional pause between batches. Defaults to 120 seconds for Graph. When AcsSmtp is selected and
this parameter is not explicitly supplied, the effective default is 900 seconds.

.PARAMETER MaxMessages
Maximum pending messages submitted during one Send invocation. Defaults to 25 and cannot exceed
500. ACS can safely automate a longer run because the script enforces persistent rolling rate
limits from its ACS submission log.

.PARAMETER SendVersion
Limits Send mode to All, Standard, or Executive approved rows. Defaults to All. Use Executive for
the first personally reviewed high-trust batch, then Standard for the remaining approved recipients.

.PARAMETER MaxRetryCount
Maximum submission attempts for transient throttling or service errors. Defaults to 4.

.PARAMETER SmtpServer
ACS SMTP server. Defaults to smtp.azurecomm.net.

.PARAMETER SmtpPort
ACS SMTP port. Defaults to 587.

.PARAMETER SmtpUsername
Exact, complete ACS SMTP username shown in Communication Service > SMTP Usernames. Required for
AcsSmtp Test and Send. Unlike Deploy-ACSEmail.ps1, this script does not append a domain.

.PARAMETER SmtpPassword
SecureString containing the client-secret value for the Entra application linked to SmtpUsername.
If omitted during AcsSmtp Test or Send, the script prompts securely once.

.PARAMETER AcsMessagesPerMinute
Local rolling ACS submission ceiling. Defaults to 20 and cannot exceed the Microsoft default of 30.

.PARAMETER AcsMessagesPerHour
Local rolling ACS submission ceiling. Defaults to 60 and cannot exceed the Microsoft default of
100. The script reconstructs the window from ACS-Submission-Log.csv when a run resumes.

.PARAMETER AcsMaxConsecutiveFailures
Stops an ACS Send run after this many consecutive SMTP submission failures. Defaults to 2.

.PARAMETER RecentTestMaxAgeHours
Maximum permitted age of a successful matching ACS Test run before Send. Defaults to 24 hours.

.PARAMETER SkipRecentAcsTestRequirement
Explicitly bypasses the matching recent ACS test requirement. Use only after documenting an
equivalent successful test.

.PARAMETER ResendRecipientsPreviouslyAcceptedByGraph
For AcsSmtp only, ignores prior AcceptedByGraph entries when determining pending recipients. Prior
ACS acceptances are still skipped. Use only with a reconciled queue after message trace or NDR
review, otherwise recipients may receive duplicate notices. It cannot be combined with
ReconciliationCsvPath.

.EXAMPLE
.\Send-M365IncidentRecipientNotifications.ps1 -Mode Prepare `
    -RecipientCsvPath ".\Recipients.csv" `
    -OutputDirectory ".\Notification-Runs\Recipient-Notice"

Creates Notification-Review-Queue.csv. Edit the queue to classify executives, add names, and set
SendApproved to True only after review.

.EXAMPLE
.\Send-M365IncidentRecipientNotifications.ps1 -Mode Preview `
    -RecipientCsvPath ".\Notification-Runs\Recipient-Notice\Notification-Review-Queue.csv" `
    -OutputDirectory ".\Notification-Runs\Recipient-Notice"

Validates the reviewed queue and creates a planned-message CSV plus standard and executive samples.

.EXAMPLE
.\Send-M365IncidentRecipientNotifications.ps1 -Mode Test `
    -SenderUpn "alex@somedomainsomewhere.com" `
    -FromAddress "alex@somedomainsomewhere.com" `
    -TestRecipient "alex@somedomainsomewhere.com" `
    -OutputDirectory ".\Notification-Runs\Recipient-Notice"

Sends both message versions only to the test address.

.EXAMPLE
.\Send-M365IncidentRecipientNotifications.ps1 -Mode Send `
    -RecipientCsvPath ".\Notification-Runs\Recipient-Notice\Notification-Review-Queue.csv" `
    -SenderUpn "alex@somedomainsomewhere.com" `
    -FromAddress "alex@somedomainsomewhere.com" `
    -OutputDirectory ".\Notification-Runs\Recipient-Notice" `
    -SendVersion Executive `
    -MaxMessages 25 `
    -ConfirmSend

Submits at most 25 approved, not-previously-accepted messages and logs every result.

.EXAMPLE
$smtpSecret = Read-Host "Incident ACS SMTP client secret" -AsSecureString

.\Send-M365IncidentRecipientNotifications.ps1 -Mode Test `
    -Transport AcsSmtp `
    -FromAddress "DoNotReply@notify.somedomainsomewhere.com" `
    -FromDisplayName "Security Incident Notice" `
    -ReplyToAddress "alex@somedomainsomewhere.com" `
    -SmtpUsername "incident-notifications-smtp@somedomainsomewhere.com" `
    -SmtpPassword $smtpSecret `
    -TestRecipient "controlled-test@example.com" `
    -OutputDirectory ".\Notification-Runs\Recipient-Notice"

Submits both template versions to one controlled address through ACS SMTP and records the result.

.EXAMPLE
$smtpSecret = Read-Host "Incident ACS SMTP client secret" -AsSecureString

.\Send-M365IncidentRecipientNotifications.ps1 -Mode Send `
    -Transport AcsSmtp `
    -RecipientCsvPath ".\Notification-Runs\Recipient-Notice\Notification-Review-Queue_Final.csv" `
    -ReconciliationCsvPath ".\Notification-Runs\Recipient-Notice\Notification-Recipient-Reconciliation.csv" `
    -FromAddress "DoNotReply@notify.somedomainsomewhere.com" `
    -FromDisplayName "Security Incident Notice" `
    -ReplyToAddress "alex@somedomainsomewhere.com" `
    -SmtpUsername "incident-notifications-smtp@somedomainsomewhere.com" `
    -SmtpPassword $smtpSecret `
    -OutputDirectory ".\Notification-Runs\Recipient-Notice-AcsResume" `
    -MaxMessages 280 `
    -ConfirmSend

Uses the ACS effective defaults of 15 messages per batch, a 15-minute batch pause, and a persistent
60-per-hour rolling ceiling. Delivered reconciliation rows are excluded, failed rows are retried,
and prior ACS acceptances are skipped. It writes ACS-Submission-Log.csv and never claims final
delivery.

.NOTES
Run in PowerShell 7 from a trusted workstation. MicrosoftGraph requires
Microsoft.Graph.Authentication and delegated Mail.Send and User.Read. AcsSmtp requires an ACS SMTP
username, its linked Entra application's client-secret value, TLS connectivity to
smtp.azurecomm.net:587, and a configured MailFrom address. Do not attach forensic evidence or
recipient lists. Do not interpret transport acceptance as delivery.

Version history:
2.1.1 Default template moved to templates\Notification-Template.md; Preview, Test, and Send refuse
      a template that still contains <...> placeholders
2.1.0 ACS SMTP transport, recipient-level Graph reconciliation, and persistent rate guards
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [ValidateSet("Prepare", "Preview", "Test", "Send")]
    [string]$Mode = "Prepare",

    [string]$RecipientCsvPath,

    [string]$ReconciliationCsvPath,

    [string]$TemplatePath = (Join-Path $PSScriptRoot "..\templates\Notification-Template.md"),

    [string]$OutputDirectory = (Join-Path $PSScriptRoot (
        "Notification-Runs\{0}-Recipient-Notice" -f (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmssZ")
    )),

    [string]$SenderUpn,

    [ValidateSet("MicrosoftGraph", "AcsSmtp")]
    [string]$Transport = "MicrosoftGraph",

    [string]$FromAddress,

    [string]$FromDisplayName = "Security Incident Notice",

    [string]$ReplyToAddress,

    [string]$TestRecipient,

    [switch]$ConfirmSend,

    [ValidateRange(1, 60)]
    [int]$DelaySeconds = 6,

    [ValidateRange(1, 100)]
    [int]$BatchSize = 25,

    [ValidateRange(0, 3600)]
    [int]$BatchPauseSeconds = 120,

    [ValidateRange(1, 500)]
    [int]$MaxMessages = 25,

    [ValidateSet("All", "Standard", "Executive")]
    [string]$SendVersion = "All",

    [ValidateRange(1, 10)]
    [int]$MaxRetryCount = 4,

    [string]$SmtpServer = "smtp.azurecomm.net",

    [ValidateRange(1, 65535)]
    [int]$SmtpPort = 587,

    [string]$SmtpUsername,

    [SecureString]$SmtpPassword,

    [ValidateRange(1, 30)]
    [int]$AcsMessagesPerMinute = 20,

    [ValidateRange(1, 100)]
    [int]$AcsMessagesPerHour = 60,

    [ValidateRange(1, 10)]
    [int]$AcsMaxConsecutiveFailures = 2,

    [ValidateRange(1, 168)]
    [int]$RecentTestMaxAgeHours = 24,

    [switch]$SkipRecentAcsTestRequirement,

    [switch]$ResendRecipientsPreviouslyAcceptedByGraph
)

$ErrorActionPreference = "Stop"
$script:ToolVersion = "2.1.1"

function Test-EmailAddress {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Address)

    try {
        $parsed = [System.Net.Mail.MailAddress]::new($Address.Trim())
        return $parsed.Address -ieq $Address.Trim()
    }
    catch {
        return $false
    }
}

function ConvertTo-BooleanValue {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $false }
    return ([string]$Value).Trim() -match '^(?i:true|yes|y|1)$'
}

function Get-PropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$InputObject,
        [Parameter(Mandatory)][string[]]$Names
    )

    foreach ($name in $Names) {
        $property = $InputObject.PSObject.Properties[$name]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return ([string]$property.Value).Trim()
        }
    }

    return $null
}

function ConvertFrom-MarkdownTemplateSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Markdown,
        [Parameter(Mandatory)][string]$Heading,
        [Parameter(Mandatory)][ValidateSet("Standard", "Executive")][string]$Version
    )

    $escapedHeading = [regex]::Escape($Heading)
    $match = [regex]::Match(
        $Markdown,
        "(?ms)^##\s+$escapedHeading\s*\r?\n(?<section>.*?)(?=^##\s+|\z)"
    )

    if (-not $match.Success) {
        throw "Template heading '$Heading' was not found in '$TemplatePath'."
    }

    $section = $match.Groups['section'].Value.Trim()
    $subjectMatch = [regex]::Match($section, '(?m)^\*\*Subject:\*\*\s*(?<subject>.+?)\s*$')
    if (-not $subjectMatch.Success) {
        throw "Template heading '$Heading' does not contain a **Subject:** line."
    }

    $subject = $subjectMatch.Groups['subject'].Value.Trim()
    $body = $section.Remove($subjectMatch.Index, $subjectMatch.Length).Trim()
    $body = $body -replace '\*\*(.*?)\*\*', '$1'
    $body = [regex]::Replace(
        $body,
        '\[(?<label>.*?)\]\((?<target>[^)]+)\)',
        {
            param($linkMatch)
            $label = $linkMatch.Groups['label'].Value
            $target = $linkMatch.Groups['target'].Value
            if ($target -match '^(?i)mailto:') {
                return $label
            }
            return "$label ($target)"
        }
    )
    $body = $body -replace "\r?\n", [Environment]::NewLine

    [pscustomobject]@{
        Version = $Version
        Subject = $subject
        Body    = $body.Trim()
    }
}

function Get-NotificationTemplates {
    [CmdletBinding()]
    param()

    if (-not (Test-Path -LiteralPath $TemplatePath -PathType Leaf)) {
        throw "Template file '$TemplatePath' does not exist."
    }

    $markdown = Get-Content -LiteralPath $TemplatePath -Raw
    $standard = ConvertFrom-MarkdownTemplateSection -Markdown $markdown `
        -Heading "Standard recipient version" -Version Standard
    $executive = ConvertFrom-MarkdownTemplateSection -Markdown $markdown `
        -Heading "Personal follow-up for executives, security firms, and training partners" `
        -Version Executive

    foreach ($section in @($standard, $executive)) {
        if ($Mode -eq "Prepare") { break }
        $placeholder = [regex]::Match("$($section.Subject)`n$($section.Body)", '<[^<>\r\n]{1,40}>')
        if ($placeholder.Success) {
            throw ("Template section '{0}' still contains the placeholder '{1}'. " +
                "Replace every <...> placeholder in '{2}' before continuing.") -f
                $section.Version, $placeholder.Value, $TemplatePath
        }
    }

    return @{
        Standard  = $standard
        Executive = $executive
    }
}

function New-RenderedMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet("Standard", "Executive")][string]$MessageVersion,
        [AllowEmptyString()][string]$DisplayName = ""
    )

    $template = $script:Templates[$MessageVersion]
    $body = $template.Body

    if ($MessageVersion -eq "Executive") {
        if ([string]::IsNullOrWhiteSpace($DisplayName)) {
            $body = $body.Replace('Hi [Name],', 'Hello,')
        }
        else {
            $body = $body.Replace('[Name]', $DisplayName.Trim())
        }
    }

    [pscustomobject]@{
        Subject = $template.Subject
        Body    = $body
    }
}

function Export-CsvRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Record,
        [Parameter(Mandatory)][string]$Path
    )

    if (Test-Path -LiteralPath $Path) {
        $Record | Export-Csv -LiteralPath $Path -NoTypeInformation -Append -Confirm:$false
    }
    else {
        $Record | Export-Csv -LiteralPath $Path -NoTypeInformation -Confirm:$false
    }
}

function Get-ReviewedQueue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Reviewed queue '$Path' does not exist."
    }

    $rows = @(Import-Csv -LiteralPath $Path)
    if ($rows.Count -eq 0) {
        throw "Reviewed queue '$Path' is empty."
    }

    $requiredColumns = @("RecipientAddress", "DisplayName", "MessageVersion", "SendApproved")
    $columns = @($rows[0].PSObject.Properties.Name)
    $missing = @($requiredColumns | Where-Object { $columns -notcontains $_ })
    if ($missing.Count -gt 0) {
        throw "Reviewed queue is missing required columns: $($missing -join ', '). Run Prepare first."
    }

    $validated = foreach ($row in $rows) {
        $address = ([string]$row.RecipientAddress).Trim().ToLowerInvariant()
        $version = ([string]$row.MessageVersion).Trim()
        $displayName = ([string]$row.DisplayName).Trim()
        $issues = [System.Collections.Generic.List[string]]::new()

        if (-not (Test-EmailAddress -Address $address)) {
            $issues.Add("Invalid recipient address")
        }
        if ($version -notin @("Standard", "Executive")) {
            $issues.Add("MessageVersion must be Standard or Executive")
        }
        [pscustomobject]@{
            RecipientAddress = $address
            DisplayName      = $displayName
            MessageVersion   = $version
            SendApproved     = ConvertTo-BooleanValue -Value $row.SendApproved
            Notes            = [string]$row.Notes
            ValidationIssues = $issues -join "; "
        }
    }

    $duplicateAddresses = @(
        $validated |
        Group-Object RecipientAddress |
        Where-Object Count -gt 1 |
        Select-Object -ExpandProperty Name
    )

    foreach ($row in $validated) {
        if ($duplicateAddresses -contains $row.RecipientAddress) {
            $issueList = @(
                $row.ValidationIssues
                "Duplicate recipient address"
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            $row.ValidationIssues = $issueList -join "; "
        }
    }

    return @($validated)
}

function Get-RecipientReconciliation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Reconciliation CSV '$Path' does not exist."
    }

    $rows = @(Import-Csv -LiteralPath $Path)
    if ($rows.Count -eq 0) {
        throw "Reconciliation CSV '$Path' is empty."
    }

    $requiredColumns = @(
        "RecipientAddress",
        "TraceClassification",
        "NextAction"
    )
    $columns = @($rows[0].PSObject.Properties.Name)
    $missing = @($requiredColumns | Where-Object { $columns -notcontains $_ })
    if ($missing.Count -gt 0) {
        throw "Reconciliation CSV is missing required columns: $($missing -join ', ')."
    }

    $validated = foreach ($row in $rows) {
        $address = ([string]$row.RecipientAddress).Trim().ToLowerInvariant()
        $classification = ([string]$row.TraceClassification).Trim()
        $nextAction = ([string]$row.NextAction).Trim()
        $issues = [System.Collections.Generic.List[string]]::new()
        $disposition = "Unresolved"

        if (-not (Test-EmailAddress -Address $address)) {
            $issues.Add("Invalid recipient address")
        }

        if ($nextAction -match '^(?i:no resend)$') {
            $disposition = "NoResend"
        }
        elseif ($classification -eq "Delivered") {
            $issues.Add("Delivered classification must have NextAction 'No resend'")
        }
        elseif ($classification -eq "Failed" -and `
            $nextAction -match '(?i)\b(notify|resend|retry)\b') {
            $disposition = "Retry"
        }
        else {
            $issues.Add("Unresolved reconciliation classification or NextAction")
        }

        [pscustomobject]@{
            RecipientAddress    = $address
            TraceClassification = $classification
            TraceStatuses       = [string]$row.TraceStatuses
            NextAction          = $nextAction
            Disposition         = $disposition
            ValidationIssues    = $issues -join "; "
        }
    }

    $duplicateAddresses = @(
        $validated |
        Group-Object RecipientAddress |
        Where-Object Count -gt 1 |
        Select-Object -ExpandProperty Name
    )
    foreach ($row in $validated) {
        if ($duplicateAddresses -contains $row.RecipientAddress) {
            $issueList = @(
                $row.ValidationIssues
                "Duplicate reconciliation address"
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            $row.ValidationIssues = $issueList -join "; "
        }
    }

    return @($validated)
}

function Connect-NotificationGraph {
    [CmdletBinding()]
    param()

    if ([string]::IsNullOrWhiteSpace($SenderUpn)) {
        throw "SenderUpn is required for $Mode mode."
    }

    if (-not (Get-Module Microsoft.Graph.Authentication -ListAvailable)) {
        throw "Microsoft.Graph.Authentication is not installed. Install it in a fresh PowerShell 7 session."
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Connect-MgGraph -Scopes "Mail.Send", "User.Read" -ContextScope Process -NoWelcome

    $me = Invoke-MgGraphRequest -Method GET -Uri (
        "https://graph.microsoft.com/v1.0/me?" +
        "`$select=id,userPrincipalName,mail,proxyAddresses"
    )

    $identityAddresses = @(
        [string]$me.userPrincipalName
        [string]$me.mail
        @($me.proxyAddresses | ForEach-Object { ([string]$_) -replace '^(?i)smtp:', '' })
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    if ($identityAddresses -notcontains $SenderUpn) {
        throw "Connected identity '$($me.userPrincipalName)' does not own SenderUpn '$SenderUpn'."
    }

    $effectiveFrom = if ([string]::IsNullOrWhiteSpace($FromAddress)) { $SenderUpn } else { $FromAddress }
    if (-not (Test-EmailAddress -Address $effectiveFrom)) {
        throw "FromAddress '$effectiveFrom' is not a valid email address."
    }
    if ($identityAddresses -notcontains $effectiveFrom) {
        throw "FromAddress '$effectiveFrom' is not a primary or proxy address of the connected mailbox."
    }
    if (-not [string]::IsNullOrWhiteSpace($ReplyToAddress) -and `
        -not (Test-EmailAddress -Address $ReplyToAddress)) {
        throw "ReplyToAddress '$ReplyToAddress' is not a valid email address."
    }

    return [pscustomobject]@{
        UserPrincipalName = [string]$me.userPrincipalName
        Mail              = [string]$me.mail
        FromAddress       = $effectiveFrom.ToLowerInvariant()
    }
}

function Send-GraphNotification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RecipientAddress,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$Body,
        [Parameter(Mandatory)][string]$EffectiveFromAddress,
        [Parameter(Mandatory)][string]$NotificationId
    )

    $request = @{
        message = @{
            subject = $Subject
            body = @{
                contentType = "Text"
                content     = $Body
            }
            from = @{
                emailAddress = @{
                    address = $EffectiveFromAddress
                }
            }
            toRecipients = @(
                @{
                    emailAddress = @{
                        address = $RecipientAddress
                    }
                }
            )
            internetMessageHeaders = @(
                @{
                    name  = "x-incident-notification-id"
                    value = $NotificationId
                }
            )
        }
        saveToSentItems = $true
    }

    if (-not [string]::IsNullOrWhiteSpace($ReplyToAddress)) {
        $request.message.replyTo = @(
            @{
                emailAddress = @{
                    address = $ReplyToAddress.Trim().ToLowerInvariant()
                }
            }
        )
    }

    $attempt = 0
    while ($attempt -lt $MaxRetryCount) {
        $attempt++
        try {
            Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/me/sendMail" `
                -Body ($request | ConvertTo-Json -Depth 12 -Compress) `
                -ContentType "application/json" | Out-Null

            return [pscustomobject]@{
                Accepted = $true
                Attempts = $attempt
                Error    = ""
            }
        }
        catch {
            $message = $_.Exception.Message
            $transient = $message -match '(?i)(429|too many requests|503|service unavailable|504|gateway timeout|temporar)'
            if (-not $transient -or $attempt -ge $MaxRetryCount) {
                return [pscustomobject]@{
                    Accepted = $false
                    Attempts = $attempt
                    Error    = $message
                }
            }

            $retryDelay = [Math]::Min(60, 5 * [Math]::Pow(2, $attempt - 1))
            Write-Warning "Transient Graph submission error. Retrying in $retryDelay seconds (attempt $attempt of $MaxRetryCount)."
            Start-Sleep -Seconds $retryDelay
        }
    }
}

function Assert-AcsSmtpConfiguration {
    [CmdletBinding()]
    param()

    if ([string]::IsNullOrWhiteSpace($FromAddress) -or `
        -not (Test-EmailAddress -Address $FromAddress)) {
        throw "AcsSmtp requires a valid FromAddress that exactly matches a configured ACS MailFrom address."
    }
    if ([string]::IsNullOrWhiteSpace($SmtpUsername)) {
        throw "AcsSmtp requires SmtpUsername. Supply the exact complete username shown in the ACS portal."
    }
    if ([string]::IsNullOrWhiteSpace($SmtpServer)) {
        throw "AcsSmtp requires SmtpServer."
    }
    if (-not [string]::IsNullOrWhiteSpace($ReplyToAddress) -and `
        -not (Test-EmailAddress -Address $ReplyToAddress)) {
        throw "ReplyToAddress '$ReplyToAddress' is not a valid email address."
    }
    if ($SmtpServer -ieq "smtp.azurecomm.net" -and $SmtpPort -notin @(25, 587)) {
        throw "ACS SMTP supports port 587 (recommended) or port 25. Port '$SmtpPort' is not permitted by this script."
    }
}

function Get-AcsSmtpSecret {
    [CmdletBinding()]
    param()

    if ($null -ne $SmtpPassword) {
        return $SmtpPassword
    }

    return Read-Host "ACS SMTP client-secret value for '$SmtpUsername'" -AsSecureString
}

function Get-AcsAcceptedTimestamps {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Paths)

    $timestamps = [System.Collections.Generic.List[datetime]]::new()
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            continue
        }

        foreach ($row in @(Import-Csv -LiteralPath $path)) {
            if ($row.Status -ne "AcceptedByAcsSmtp" -or `
                [string]::IsNullOrWhiteSpace([string]$row.TimestampUtc)) {
                continue
            }

            try {
                $parsed = [datetimeoffset]::Parse(
                    [string]$row.TimestampUtc,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::RoundtripKind
                )
                $timestamps.Add($parsed.UtcDateTime)
            }
            catch {
                Write-Warning "Ignored an invalid timestamp in '$path': $($row.TimestampUtc)"
            }
        }
    }

    return ,$timestamps
}

function Wait-AcsSubmissionCapacity {
    [CmdletBinding()]
    param()

    while ($true) {
        $now = [datetime]::UtcNow
        $recentHour = @(
            $script:AcsAcceptedTimestamps |
            Where-Object { $_ -gt $now.AddHours(-1) } |
            Sort-Object
        )
        $script:AcsAcceptedTimestamps = [System.Collections.Generic.List[datetime]]::new()
        foreach ($timestamp in $recentHour) {
            $script:AcsAcceptedTimestamps.Add($timestamp)
        }

        $recentMinute = @($recentHour | Where-Object { $_ -gt $now.AddMinutes(-1) })
        $waitSeconds = 0
        $reason = ""

        if ($recentMinute.Count -ge $AcsMessagesPerMinute) {
            $waitSeconds = [Math]::Ceiling(
                ($recentMinute[0].AddMinutes(1).AddSeconds(2) - $now).TotalSeconds
            )
            $reason = "$AcsMessagesPerMinute-message local rolling minute limit"
        }

        if ($recentHour.Count -ge $AcsMessagesPerHour) {
            $hourWait = [Math]::Ceiling(
                ($recentHour[0].AddHours(1).AddSeconds(2) - $now).TotalSeconds
            )
            if ($hourWait -gt $waitSeconds) {
                $waitSeconds = $hourWait
                $reason = "$AcsMessagesPerHour-message local rolling hour limit"
            }
        }

        if ($waitSeconds -le 0) {
            return
        }

        Write-Host "ACS rate guard: waiting $waitSeconds seconds for the $reason."
        Start-Sleep -Seconds $waitSeconds
    }
}

function Add-AcsAcceptedTimestamp {
    [CmdletBinding()]
    param([Parameter(Mandatory)][datetime]$TimestampUtc)

    $script:AcsAcceptedTimestamps.Add($TimestampUtc.ToUniversalTime())
}

function Send-AcsSmtpNotification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RecipientAddress,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$Body,
        [Parameter(Mandatory)][string]$EffectiveFromAddress,
        [Parameter(Mandatory)][string]$NotificationId,
        [Parameter(Mandatory)][SecureString]$Secret
    )

    $attempt = 0
    while ($attempt -lt $MaxRetryCount) {
        $attempt++
        Wait-AcsSubmissionCapacity

        $mail = $null
        $client = $null
        try {
            $mail = [System.Net.Mail.MailMessage]::new()
            $mail.From = [System.Net.Mail.MailAddress]::new(
                $EffectiveFromAddress,
                $FromDisplayName,
                [System.Text.Encoding]::UTF8
            )
            $mail.To.Add([System.Net.Mail.MailAddress]::new($RecipientAddress))
            if (-not [string]::IsNullOrWhiteSpace($ReplyToAddress)) {
                $mail.ReplyToList.Add(
                    [System.Net.Mail.MailAddress]::new($ReplyToAddress.Trim())
                )
            }
            $mail.Subject = $Subject
            $mail.Body = $Body
            $mail.IsBodyHtml = $false
            $mail.SubjectEncoding = [System.Text.Encoding]::UTF8
            $mail.BodyEncoding = [System.Text.Encoding]::UTF8
            $mail.HeadersEncoding = [System.Text.Encoding]::UTF8
            $mail.Headers.Add("X-Incident-Notification-Id", $NotificationId)
            $mail.Headers.Add("X-Incident-Notification-Transport", "ACS-SMTP")

            $client = [System.Net.Mail.SmtpClient]::new($SmtpServer, $SmtpPort)
            $client.EnableSsl = $true
            $client.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network
            $client.UseDefaultCredentials = $false
            $client.Credentials = [System.Net.NetworkCredential]::new($SmtpUsername, $Secret)
            $client.Timeout = 60000
            $client.Send($mail)

            $acceptedUtc = [datetime]::UtcNow
            Add-AcsAcceptedTimestamp -TimestampUtc $acceptedUtc
            return [pscustomobject]@{
                Accepted      = $true
                AcceptedUtc   = $acceptedUtc
                Attempts      = $attempt
                SmtpStatusCode = ""
                Error         = ""
            }
        }
        catch {
            $message = $_.Exception.Message
            $statusCode = if ($_.Exception -is [System.Net.Mail.SmtpException]) {
                [string]$_.Exception.StatusCode
            }
            else {
                ""
            }
            $transientStatusCodes = @(
                "ServiceNotAvailable",
                "MailboxBusy",
                "LocalErrorInProcessing",
                "TransactionFailed",
                "GeneralFailure"
            )
            $transient = $statusCode -in $transientStatusCodes -or `
                $message -match '(?i)(\b4\d\d\b|temporar|timeout|timed out|throttl|rate limit|try again)'

            if (-not $transient -or $attempt -ge $MaxRetryCount) {
                return [pscustomobject]@{
                    Accepted       = $false
                    AcceptedUtc    = $null
                    Attempts       = $attempt
                    SmtpStatusCode = $statusCode
                    Error          = $message
                }
            }

            $retryDelay = [Math]::Min(120, 5 * [Math]::Pow(2, $attempt - 1))
            Write-Warning "Transient ACS SMTP submission error. Retrying in $retryDelay seconds (attempt $attempt of $MaxRetryCount)."
            Start-Sleep -Seconds $retryDelay
        }
        finally {
            if ($null -ne $mail) { $mail.Dispose() }
            if ($null -ne $client) { $client.Dispose() }
        }
    }
}

function Test-RecentSuccessfulAcsTest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }

    $cutoff = [datetime]::UtcNow.AddHours(-$RecentTestMaxAgeHours)
    $matching = foreach ($row in @(Import-Csv -LiteralPath $Path)) {
        if ($row.Status -ne "AcceptedByAcsSmtp" -or `
            [string]$row.SmtpUsername -ine $SmtpUsername -or `
            [string]$row.FromAddress -ine $FromAddress) {
            continue
        }

        try {
            $timestamp = [datetimeoffset]::Parse(
                [string]$row.TimestampUtc,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind
            ).UtcDateTime
            if ($timestamp -ge $cutoff) { $row }
        }
        catch { }
    }

    $versions = @($matching | Select-Object -ExpandProperty MessageVersion -Unique)
    return ($versions -contains "Standard" -and $versions -contains "Executive")
}

New-Item -ItemType Directory -Path $OutputDirectory -Force `
    -Confirm:$false -WhatIf:$false | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$TemplatePath = (Resolve-Path -LiteralPath $TemplatePath).Path
$script:Templates = Get-NotificationTemplates

if ($Transport -eq "AcsSmtp") {
    if (-not [string]::IsNullOrWhiteSpace($SmtpUsername)) {
        $SmtpUsername = $SmtpUsername.Trim()
    }
    if (-not [string]::IsNullOrWhiteSpace($SmtpServer)) {
        $SmtpServer = $SmtpServer.Trim()
    }
    if (-not [string]::IsNullOrWhiteSpace($FromAddress)) {
        $FromAddress = $FromAddress.Trim()
    }
    if (-not [string]::IsNullOrWhiteSpace($ReplyToAddress)) {
        $ReplyToAddress = $ReplyToAddress.Trim()
    }
    $FromDisplayName = if ($null -eq $FromDisplayName) {
        ""
    }
    else {
        $FromDisplayName.Trim()
    }
}

if ($ResendRecipientsPreviouslyAcceptedByGraph -and $Transport -ne "AcsSmtp") {
    throw "ResendRecipientsPreviouslyAcceptedByGraph is valid only with Transport AcsSmtp."
}
if ($ResendRecipientsPreviouslyAcceptedByGraph -and `
    -not [string]::IsNullOrWhiteSpace($ReconciliationCsvPath)) {
    throw "Do not combine ReconciliationCsvPath with ResendRecipientsPreviouslyAcceptedByGraph. ReconciliationCsvPath provides the safer recipient-level decision."
}

$effectiveBatchSize = if ($Transport -eq "AcsSmtp" -and `
    -not $PSBoundParameters.ContainsKey("BatchSize")) {
    15
}
else {
    $BatchSize
}
$effectiveBatchPauseSeconds = if ($Transport -eq "AcsSmtp" -and `
    -not $PSBoundParameters.ContainsKey("BatchPauseSeconds")) {
    900
}
else {
    $BatchPauseSeconds
}

$graphSubmissionLogPath = Join-Path $OutputDirectory "Submission-Log.csv"
$acsSubmissionLogPath = Join-Path $OutputDirectory "ACS-Submission-Log.csv"
$acsTestLogPath = Join-Path $OutputDirectory "ACS-Test-Submission-Log.csv"

switch ($Mode) {
    "Prepare" {
        if ([string]::IsNullOrWhiteSpace($RecipientCsvPath)) {
            throw "RecipientCsvPath is required for Prepare mode."
        }
        if (-not (Test-Path -LiteralPath $RecipientCsvPath -PathType Leaf)) {
            throw "Recipient CSV '$RecipientCsvPath' does not exist."
        }

        $sourceRows = @(Import-Csv -LiteralPath $RecipientCsvPath)
        if ($sourceRows.Count -eq 0) {
            throw "Recipient CSV '$RecipientCsvPath' is empty."
        }

        $preparedRows = foreach ($sourceRow in $sourceRows) {
            $address = Get-PropertyValue -InputObject $sourceRow `
                -Names @("RecipientAddress", "EmailAddress", "Address")
            $displayName = Get-PropertyValue -InputObject $sourceRow `
                -Names @("DisplayName", "Name", "RecipientName")

            [pscustomobject]@{
                RecipientAddress = if ($address) { $address.ToLowerInvariant() } else { "" }
                DisplayName      = if ($displayName) { $displayName } else { "" }
                MessageVersion   = "Standard"
                SendApproved     = "False"
                Notes            = ""
            }
        }

        $rejected = @(
            $preparedRows |
            Where-Object { -not (Test-EmailAddress -Address $_.RecipientAddress) }
        )
        $valid = @(
            $preparedRows |
            Where-Object { Test-EmailAddress -Address $_.RecipientAddress } |
            Sort-Object RecipientAddress -Unique
        )
        $duplicateCount = $preparedRows.Count - $rejected.Count - $valid.Count

        $queuePath = Join-Path $OutputDirectory "Notification-Review-Queue.csv"
        $valid | Export-Csv -LiteralPath $queuePath -NoTypeInformation -Confirm:$false
        if ($rejected.Count -gt 0) {
            $rejected | Export-Csv -LiteralPath (
                Join-Path $OutputDirectory "Rejected-Recipients.csv"
            ) -NoTypeInformation -Confirm:$false
        }

        $summary = [pscustomobject]@{
            GeneratedUtc       = (Get-Date).ToUniversalTime().ToString("o")
            SourceRows         = $sourceRows.Count
            ValidUniqueRows    = $valid.Count
            RejectedRows       = $rejected.Count
            DuplicateRows      = $duplicateCount
            DefaultVersion     = "Standard"
            ApprovedRows       = 0
            ReviewQueue        = $queuePath
            NextAction         = "Classify executives, add names, set SendApproved=True after review, then run Preview."
        }
        $summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (
            Join-Path $OutputDirectory "Prepare-Summary.json"
        ) -Encoding utf8 -Confirm:$false
        $summary | Format-List
        break
    }

    "Preview" {
        if ([string]::IsNullOrWhiteSpace($RecipientCsvPath)) {
            throw "RecipientCsvPath must identify the reviewed queue for Preview mode."
        }
        $queue = @(Get-ReviewedQueue -Path $RecipientCsvPath)
        $invalidApproved = @($queue | Where-Object { $_.SendApproved -and $_.ValidationIssues })
        if ($invalidApproved.Count -gt 0) {
            $invalidApproved | Export-Csv -LiteralPath (
                Join-Path $OutputDirectory "Preview-Blocking-Issues.csv"
            ) -NoTypeInformation -Confirm:$false
            throw "$($invalidApproved.Count) approved rows have validation issues. Review Preview-Blocking-Issues.csv."
        }

        $approved = @($queue | Where-Object SendApproved)
        $plan = foreach ($row in $approved) {
            $rendered = New-RenderedMessage -MessageVersion $row.MessageVersion `
                -DisplayName $row.DisplayName
            [pscustomobject]@{
                RecipientAddress = $row.RecipientAddress
                DisplayName      = $row.DisplayName
                MessageVersion   = $row.MessageVersion
                Subject          = $rendered.Subject
            }
        }
        $planPath = Join-Path $OutputDirectory "Planned-Messages.csv"
        if (@($plan).Count -gt 0) {
            $plan | Export-Csv -LiteralPath $planPath -NoTypeInformation -Confirm:$false
        }
        else {
            '"RecipientAddress","DisplayName","MessageVersion","Subject"' |
                Set-Content -LiteralPath $planPath -Encoding utf8 -Confirm:$false
        }

        $standardSample = New-RenderedMessage -MessageVersion Standard
        @($standardSample.Subject, "", $standardSample.Body) | Set-Content -LiteralPath (
            Join-Path $OutputDirectory "Preview-Standard.txt"
        ) -Encoding utf8 -Confirm:$false

        $executiveSample = New-RenderedMessage -MessageVersion Executive -DisplayName "Sample Name"
        @($executiveSample.Subject, "", $executiveSample.Body) | Set-Content -LiteralPath (
            Join-Path $OutputDirectory "Preview-Executive.txt"
        ) -Encoding utf8 -Confirm:$false

        $executiveNoNameSample = New-RenderedMessage -MessageVersion Executive
        @($executiveNoNameSample.Subject, "", $executiveNoNameSample.Body) | Set-Content -LiteralPath (
            Join-Path $OutputDirectory "Preview-Executive-No-Name.txt"
        ) -Encoding utf8 -Confirm:$false

        [pscustomobject]@{
            QueueRows          = $queue.Count
            ApprovedRows       = $approved.Count
            StandardApproved   = @($approved | Where-Object MessageVersion -eq Standard).Count
            ExecutiveApproved  = @($approved | Where-Object MessageVersion -eq Executive).Count
            ValidationFailures = @($queue | Where-Object ValidationIssues).Count
            OutputDirectory    = $OutputDirectory
        } | Format-List
        break
    }

    "Test" {
        if ([string]::IsNullOrWhiteSpace($TestRecipient) -or `
            -not (Test-EmailAddress -Address $TestRecipient)) {
            throw "TestRecipient must be a valid email address for Test mode."
        }
        if (-not $PSCmdlet.ShouldProcess(
            $TestRecipient,
            "Send both notification template tests through $Transport"
        )) {
            break
        }

        $effectiveFromAddress = ""
        $testLogPath = ""
        $acsSecret = $null
        if ($Transport -eq "MicrosoftGraph") {
            $graphIdentity = Connect-NotificationGraph
            $effectiveFromAddress = $graphIdentity.FromAddress
            $testLogPath = Join-Path $OutputDirectory "Test-Submission-Log.csv"
        }
        else {
            Assert-AcsSmtpConfiguration
            $effectiveFromAddress = $FromAddress.Trim().ToLowerInvariant()
            $testLogPath = $acsTestLogPath
            $acsSecret = Get-AcsSmtpSecret
            $script:AcsAcceptedTimestamps = Get-AcsAcceptedTimestamps -Paths @(
                $acsSubmissionLogPath,
                $acsTestLogPath
            )
            [System.Net.ServicePointManager]::SecurityProtocol = `
                [System.Net.SecurityProtocolType]::Tls12
        }

        foreach ($version in @("Standard", "Executive")) {
            $rendered = New-RenderedMessage -MessageVersion $version -DisplayName "Test Recipient"
            $notificationId = "TEST-{0}" -f ([guid]::NewGuid().ToString())
            $subject = "[TEST - $version] $($rendered.Subject)"
            if ($Transport -eq "MicrosoftGraph") {
                $result = Send-GraphNotification `
                    -RecipientAddress $TestRecipient.ToLowerInvariant() `
                    -Subject $subject `
                    -Body $rendered.Body `
                    -EffectiveFromAddress $effectiveFromAddress `
                    -NotificationId $notificationId

                Export-CsvRecord -Path $testLogPath -Record ([pscustomobject]@{
                    TimestampUtc       = (Get-Date).ToUniversalTime().ToString("o")
                    RecipientAddress   = $TestRecipient.ToLowerInvariant()
                    MessageVersion     = $version
                    Subject            = $subject
                    NotificationId     = $notificationId
                    Status             = if ($result.Accepted) { "AcceptedByGraph" } else { "SubmissionFailed" }
                    Attempts           = $result.Attempts
                    Error              = $result.Error
                })
            }
            else {
                $result = Send-AcsSmtpNotification `
                    -RecipientAddress $TestRecipient.ToLowerInvariant() `
                    -Subject $subject `
                    -Body $rendered.Body `
                    -EffectiveFromAddress $effectiveFromAddress `
                    -NotificationId $notificationId `
                    -Secret $acsSecret

                $recordTimestamp = if ($result.AcceptedUtc) {
                    $result.AcceptedUtc.ToString("o")
                }
                else {
                    (Get-Date).ToUniversalTime().ToString("o")
                }
                Export-CsvRecord -Path $testLogPath -Record ([pscustomobject]@{
                    TimestampUtc       = $recordTimestamp
                    Transport          = "AcsSmtp"
                    RecipientAddress   = $TestRecipient.ToLowerInvariant()
                    DisplayName        = "Test Recipient"
                    MessageVersion     = $version
                    Subject            = $subject
                    FromAddress        = $effectiveFromAddress
                    FromDisplayName    = $FromDisplayName
                    ReplyToAddress     = if ($ReplyToAddress) { $ReplyToAddress.ToLowerInvariant() } else { "" }
                    SmtpServer         = $SmtpServer
                    SmtpPort           = $SmtpPort
                    SmtpUsername       = $SmtpUsername
                    NotificationId     = $notificationId
                    Status             = if ($result.Accepted) { "AcceptedByAcsSmtp" } else { "SubmissionFailed" }
                    Attempts           = $result.Attempts
                    SmtpStatusCode     = $result.SmtpStatusCode
                    Error              = $result.Error
                })
            }

            if (-not $result.Accepted) {
                throw "The $version test submission failed: $($result.Error)"
            }
            Start-Sleep -Seconds $DelaySeconds
        }

        if ($Transport -eq "MicrosoftGraph") {
            Write-Host "Both test messages were accepted by Microsoft Graph. Verify received From, rendering, links, and Sent Items before approving real recipients."
        }
        else {
            Write-Host "Both test messages were accepted by ACS SMTP. Verify receipt, From, Reply-To, rendering, links, SPF, DKIM, DMARC, and ACS diagnostic events before approving real recipients."
            Write-Host "SMTP acceptance is not proof of final delivery."
        }
        break
    }

    "Send" {
        $pauseMarker = Join-Path $OutputDirectory "SENDING-PAUSED.txt"
        if (Test-Path -LiteralPath $pauseMarker -PathType Leaf) {
            throw "Notification sending is paused. Review '$pauseMarker' and reconcile message trace before removing the marker."
        }
        if (-not $ConfirmSend) {
            throw "Send mode requires -ConfirmSend. Run Preview and Test first."
        }
        if ([string]::IsNullOrWhiteSpace($RecipientCsvPath)) {
            throw "RecipientCsvPath must identify the reviewed queue for Send mode."
        }

        $queue = @(Get-ReviewedQueue -Path $RecipientCsvPath)
        $invalidApproved = @($queue | Where-Object { $_.SendApproved -and $_.ValidationIssues })
        if ($invalidApproved.Count -gt 0) {
            $invalidApproved | Export-Csv -LiteralPath (
                Join-Path $OutputDirectory "Send-Blocking-Issues.csv"
            ) -NoTypeInformation -Confirm:$false
            throw "$($invalidApproved.Count) approved rows have validation issues. No messages were submitted."
        }

        $reconciliation = @()
        $reconciledRetry = @()
        $reconciledNoResend = @()
        if (-not [string]::IsNullOrWhiteSpace($ReconciliationCsvPath)) {
            $reconciliation = @(
                Get-RecipientReconciliation -Path $ReconciliationCsvPath
            )
            $reconciliationIssues = @(
                $reconciliation |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_.ValidationIssues) }
            )
            if ($reconciliationIssues.Count -gt 0) {
                $reconciliationIssues | Export-Csv -LiteralPath (
                    Join-Path $OutputDirectory "Reconciliation-Blocking-Issues.csv"
                ) -NoTypeInformation -Confirm:$false
                throw "$($reconciliationIssues.Count) reconciliation rows are unresolved or invalid. No messages were submitted."
            }

            $queueAddresses = @($queue | Select-Object -ExpandProperty RecipientAddress)
            $notInQueue = @(
                $reconciliation |
                Where-Object { $queueAddresses -notcontains $_.RecipientAddress }
            )
            if ($notInQueue.Count -gt 0) {
                $notInQueue | Export-Csv -LiteralPath (
                    Join-Path $OutputDirectory "Reconciliation-Addresses-Not-In-Queue.csv"
                ) -NoTypeInformation -Confirm:$false
                Write-Warning "$($notInQueue.Count) reconciliation addresses are not present in the reviewed queue. They cannot be selected for this run."
            }

            $reconciledRetry = @(
                $reconciliation |
                Where-Object Disposition -eq "Retry" |
                Select-Object -ExpandProperty RecipientAddress -Unique
            )
            $reconciledNoResend = @(
                $reconciliation |
                Where-Object Disposition -eq "NoResend" |
                Select-Object -ExpandProperty RecipientAddress -Unique
            )
        }

        $previouslyAcceptedByGraph = @()
        if (Test-Path -LiteralPath $graphSubmissionLogPath) {
            $previouslyAcceptedByGraph = @(
                Import-Csv -LiteralPath $graphSubmissionLogPath |
                Where-Object Status -eq "AcceptedByGraph" |
                ForEach-Object { $_.RecipientAddress.ToLowerInvariant() } |
                Sort-Object -Unique
            )
        }

        $previouslyAcceptedByAcs = @()
        if (Test-Path -LiteralPath $acsSubmissionLogPath) {
            $previouslyAcceptedByAcs = @(
                Import-Csv -LiteralPath $acsSubmissionLogPath |
                Where-Object Status -eq "AcceptedByAcsSmtp" |
                ForEach-Object { $_.RecipientAddress.ToLowerInvariant() } |
                Sort-Object -Unique
            )
        }

        $effectiveGraphAccepted = @(
            $previouslyAcceptedByGraph |
            Where-Object { $reconciledRetry -notcontains $_ }
        )

        $alreadyAccepted = if ($Transport -eq "AcsSmtp" -and `
            $ResendRecipientsPreviouslyAcceptedByGraph) {
            @($previouslyAcceptedByAcs)
        }
        else {
            @(
                @($effectiveGraphAccepted) + @($previouslyAcceptedByAcs) |
                Sort-Object -Unique
            )
        }

        $pending = @(
            $queue |
            Where-Object SendApproved |
            Where-Object { $SendVersion -eq "All" -or $_.MessageVersion -eq $SendVersion } |
            Where-Object { $reconciledNoResend -notcontains $_.RecipientAddress } |
            Where-Object { $alreadyAccepted -notcontains $_.RecipientAddress } |
            Sort-Object @{ Expression = {
                if ($_.MessageVersion -eq "Executive") { 0 } else { 1 }
            } }, RecipientAddress |
            Select-Object -First $MaxMessages
        )

        if ($pending.Count -eq 0) {
            Write-Host "No approved recipients are pending."
            break
        }

        $planPath = Join-Path $OutputDirectory "Current-Send-Plan.csv"
        $pending | Select-Object `
            @{Name = "Transport"; Expression = { $Transport } },
            RecipientAddress,DisplayName,MessageVersion,Notes,
            @{Name = "ReconciliationDisposition"; Expression = {
                if ($reconciledRetry -contains $_.RecipientAddress) { "Retry" }
                elseif ($reconciledNoResend -contains $_.RecipientAddress) { "NoResend" }
                else { "NotPreviouslyReconciled" }
            } },
            @{Name = "FromAddress"; Expression = { $FromAddress } },
            @{Name = "ReplyToAddress"; Expression = { $ReplyToAddress } } |
            Export-Csv -LiteralPath $planPath -NoTypeInformation `
                -Confirm:$false -WhatIf:$false

        $target = "$($pending.Count) individually addressed recipients"
        if (-not $PSCmdlet.ShouldProcess(
            $target,
            "Submit incident notification messages through $Transport"
        )) {
            break
        }

        $effectiveFromAddress = ""
        $activeSubmissionLogPath = ""
        $acsSecret = $null
        if ($Transport -eq "MicrosoftGraph") {
            $graphIdentity = Connect-NotificationGraph
            $effectiveFromAddress = $graphIdentity.FromAddress
            $activeSubmissionLogPath = $graphSubmissionLogPath
        }
        else {
            Assert-AcsSmtpConfiguration
            if (-not $SkipRecentAcsTestRequirement -and `
                -not (Test-RecentSuccessfulAcsTest -Path $acsTestLogPath)) {
                throw "AcsSmtp Send requires successful matching Standard and Executive tests within the last $RecentTestMaxAgeHours hours. Run Mode Test with the same OutputDirectory, FromAddress, and SmtpUsername, or use SkipRecentAcsTestRequirement only after documenting an equivalent test."
            }

            $effectiveFromAddress = $FromAddress.Trim().ToLowerInvariant()
            $activeSubmissionLogPath = $acsSubmissionLogPath
            $acsSecret = Get-AcsSmtpSecret
            $script:AcsAcceptedTimestamps = Get-AcsAcceptedTimestamps -Paths @(
                $acsSubmissionLogPath,
                $acsTestLogPath
            )
            [System.Net.ServicePointManager]::SecurityProtocol = `
                [System.Net.SecurityProtocolType]::Tls12
        }

        $acceptedThisRun = 0
        $failedThisRun = 0
        $processedThisRun = 0
        $consecutiveFailures = 0
        $sendingPaused = $false

        foreach ($row in $pending) {
            $processedThisRun++
            $rendered = New-RenderedMessage -MessageVersion $row.MessageVersion `
                -DisplayName $row.DisplayName
            $notificationId = [guid]::NewGuid().ToString()
            if ($Transport -eq "MicrosoftGraph") {
                $result = Send-GraphNotification `
                    -RecipientAddress $row.RecipientAddress `
                    -Subject $rendered.Subject `
                    -Body $rendered.Body `
                    -EffectiveFromAddress $effectiveFromAddress `
                    -NotificationId $notificationId

                $status = if ($result.Accepted) { "AcceptedByGraph" } else { "SubmissionFailed" }
                Export-CsvRecord -Path $activeSubmissionLogPath -Record ([pscustomobject]@{
                    TimestampUtc       = (Get-Date).ToUniversalTime().ToString("o")
                    RecipientAddress   = $row.RecipientAddress
                    DisplayName        = $row.DisplayName
                    MessageVersion     = $row.MessageVersion
                    Subject            = $rendered.Subject
                    FromAddress        = $effectiveFromAddress
                    NotificationId     = $notificationId
                    Status             = $status
                    Attempts           = $result.Attempts
                    Error              = $result.Error
                })
            }
            else {
                $result = Send-AcsSmtpNotification `
                    -RecipientAddress $row.RecipientAddress `
                    -Subject $rendered.Subject `
                    -Body $rendered.Body `
                    -EffectiveFromAddress $effectiveFromAddress `
                    -NotificationId $notificationId `
                    -Secret $acsSecret

                $status = if ($result.Accepted) { "AcceptedByAcsSmtp" } else { "SubmissionFailed" }
                $recordTimestamp = if ($result.AcceptedUtc) {
                    $result.AcceptedUtc.ToString("o")
                }
                else {
                    (Get-Date).ToUniversalTime().ToString("o")
                }
                Export-CsvRecord -Path $activeSubmissionLogPath -Record ([pscustomobject]@{
                    TimestampUtc       = $recordTimestamp
                    Transport          = "AcsSmtp"
                    RecipientAddress   = $row.RecipientAddress
                    DisplayName        = $row.DisplayName
                    MessageVersion     = $row.MessageVersion
                    Subject            = $rendered.Subject
                    FromAddress        = $effectiveFromAddress
                    FromDisplayName    = $FromDisplayName
                    ReplyToAddress     = if ($ReplyToAddress) { $ReplyToAddress.ToLowerInvariant() } else { "" }
                    SmtpServer         = $SmtpServer
                    SmtpPort           = $SmtpPort
                    SmtpUsername       = $SmtpUsername
                    NotificationId     = $notificationId
                    Status             = $status
                    Attempts           = $result.Attempts
                    SmtpStatusCode     = $result.SmtpStatusCode
                    Error              = $result.Error
                })
            }

            if ($result.Accepted) {
                $acceptedThisRun++
                $consecutiveFailures = 0
                $acceptanceLabel = if ($Transport -eq "MicrosoftGraph") {
                    "Accepted by Graph"
                }
                else {
                    "Accepted by ACS SMTP"
                }
                Write-Host "[$processedThisRun/$($pending.Count)] ${acceptanceLabel}: $($row.RecipientAddress)"
            }
            else {
                $failedThisRun++
                $consecutiveFailures++
                Write-Warning "[$processedThisRun/$($pending.Count)] Submission failed: $($row.RecipientAddress) - $($result.Error)"

                if ($Transport -eq "AcsSmtp" -and `
                    $consecutiveFailures -ge $AcsMaxConsecutiveFailures) {
                    $pauseText = @(
                        "ACS notification sending paused automatically."
                        "TimestampUTC: $((Get-Date).ToUniversalTime().ToString('o'))"
                        "Reason: $consecutiveFailures consecutive SMTP submission failures."
                        "LastRecipient: $($row.RecipientAddress)"
                        "LastError: $($result.Error)"
                        "Review ACS-Submission-Log.csv, ACS diagnostics, credentials, quota, and sender configuration before removing this marker."
                    )
                    $pauseText | Set-Content -LiteralPath $pauseMarker -Encoding utf8 -Confirm:$false
                    $sendingPaused = $true
                    Write-Warning "Sending paused after $consecutiveFailures consecutive ACS SMTP failures. Review '$pauseMarker'."
                    break
                }
            }

            if ($processedThisRun -lt $pending.Count) {
                Start-Sleep -Seconds $DelaySeconds
            }
            if ($processedThisRun % $effectiveBatchSize -eq 0 -and `
                $processedThisRun -lt $pending.Count -and `
                $effectiveBatchPauseSeconds -gt 0) {
                Write-Host "Batch pause: $effectiveBatchPauseSeconds seconds."
                Start-Sleep -Seconds $effectiveBatchPauseSeconds
            }
        }

        $acceptedGraphAfterRun = if (Test-Path -LiteralPath $graphSubmissionLogPath) {
            @(
                Import-Csv -LiteralPath $graphSubmissionLogPath |
                Where-Object Status -eq "AcceptedByGraph" |
                ForEach-Object { $_.RecipientAddress.ToLowerInvariant() } |
                Sort-Object -Unique
            )
        }
        else { @() }
        $acceptedAcsAfterRun = if (Test-Path -LiteralPath $acsSubmissionLogPath) {
            @(
                Import-Csv -LiteralPath $acsSubmissionLogPath |
                Where-Object Status -eq "AcceptedByAcsSmtp" |
                ForEach-Object { $_.RecipientAddress.ToLowerInvariant() } |
                Sort-Object -Unique
            )
        }
        else { @() }
        $effectiveGraphAcceptedAfterRun = @(
            $acceptedGraphAfterRun |
            Where-Object { $reconciledRetry -notcontains $_ }
        )
        $acceptedAfterRun = if ($Transport -eq "AcsSmtp" -and `
            $ResendRecipientsPreviouslyAcceptedByGraph) {
            @($acceptedAcsAfterRun)
        }
        else {
            @(
                @($effectiveGraphAcceptedAfterRun) + @($acceptedAcsAfterRun) |
                Sort-Object -Unique
            )
        }
        $remainingApproved = @(
            $queue |
            Where-Object SendApproved |
            Where-Object { $reconciledNoResend -notcontains $_.RecipientAddress } |
            Where-Object { $acceptedAfterRun -notcontains $_.RecipientAddress }
        ).Count

        [pscustomobject]@{
            Transport              = $Transport
            AcceptedThisRun        = $acceptedThisRun
            AcceptedByGraphThisRun = if ($Transport -eq "MicrosoftGraph") {
                $acceptedThisRun
            }
            else { 0 }
            AcceptedByAcsSmtpThisRun = if ($Transport -eq "AcsSmtp") {
                $acceptedThisRun
            }
            else { 0 }
            SubmissionFailures     = $failedThisRun
            PreviouslyAccepted     = $alreadyAccepted.Count
            ReconciliationRows     = $reconciliation.Count
            ReconciledRetry        = $reconciledRetry.Count
            ReconciledNoResend     = $reconciledNoResend.Count
            RemainingApproved      = $remainingApproved
            EffectiveBatchSize     = $effectiveBatchSize
            BatchPauseSeconds      = $effectiveBatchPauseSeconds
            AcsMessagesPerMinute   = if ($Transport -eq "AcsSmtp") { $AcsMessagesPerMinute } else { $null }
            AcsMessagesPerHour     = if ($Transport -eq "AcsSmtp") { $AcsMessagesPerHour } else { $null }
            SendingPaused          = $sendingPaused
            SubmissionLog          = $activeSubmissionLogPath
            DeliveryStatus         = if ($Transport -eq "MicrosoftGraph") {
                "Not determined; verify with Exchange Online message trace."
            }
            else {
                "Not determined; verify final recipient events in ACS Email operational logs and diagnostics."
            }
        } | Format-List
        break
    }
}
