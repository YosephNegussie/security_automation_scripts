<#
.SYNOPSIS
    Active Directory & Local User Account Security Auditor
.DESCRIPTION
    Audits user accounts and presents findings in clean, professional executive output 
    to satisfy ISO/IEC 27001:2022 Controls A.5.15 and A.5.18.
.AUTHOR
    Yoseph Negussie Alula, MSc | BSI ISO/IEC 27001 Lead Auditor
#>

[CmdletBinding()]
param (
    [int]$InactiveDaysThreshold = 90,
    [string]$ReportPath = ".\ISO27001_User_Audit_Report.html"
)

$AuditResults = @()

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "   Starting ISO/IEC 27001 Access Control Audit...       " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Active Directory Audit
# ---------------------------------------------------------------------------
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory
    Write-Host "[*] Connecting to Active Directory domain..." -ForegroundColor Yellow

    $CutoffDate = (Get-Date).AddDays(-$InactiveDaysThreshold)
    $ADUsers = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordNeverExpires, MemberOf

    foreach ($User in $ADUsers) {
        $Flags = @()

        if ($User.Enabled -and ($User.LastLogonDate -lt $CutoffDate) -and $User.LastLogonDate) {
            $Flags += "Inactive for over $InactiveDaysThreshold days"
        }
        if ($User.PasswordNeverExpires) {
            $Flags += "Password never expires policy enabled"
        }
        $Groups = ($User.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join ", "
        if ($Groups -match "Domain Admins|Enterprise Admins|Administrators") {
            $Flags += "Holds high-level privileged access"
        }

        if ($Flags.Count -gt 0) {
            $AuditResults += [PSCustomObject]@{
                Scope           = "Active Directory"
                AccountName     = $User.SamAccountName
                Enabled         = if($User.Enabled){"Active"}else{"Disabled"}
                LastLogon       = if($User.LastLogonDate){$User.LastLogonDate.ToString('yyyy-MM-dd')}else{"Never"}
                Findings        = ($Flags -join ". ") + "."
                GroupMembership = $Groups
            }
        }
    }
    Write-Host "[+] Active Directory scan completed." -ForegroundColor Green
} else {
    Write-Host "[i] Active Directory module not found. Skipping domain check." -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------------------
# 2. Local Machine Audit
# ---------------------------------------------------------------------------
Write-Host "[*] Checking local computer accounts on '$env:COMPUTERNAME'..." -ForegroundColor Yellow
$LocalUsers = Get-LocalUser
$AdminMembers = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name

foreach ($LUser in $LocalUsers) {
    $LFlags = @()

    if ($LUser.Enabled -and ($LUser.LastLogonDateTime -lt (Get-Date).AddDays(-$InactiveDaysThreshold)) -and $LUser.LastLogonDateTime) {
        $LFlags += "Inactive local user account"
    }
    if ($LUser.PasswordRequired -eq $false) {
        $LFlags += "Account has no password required"
    }
    if ($AdminMembers -contains "$env:COMPUTERNAME\$($LUser.Name)" -or $AdminMembers -contains $LUser.Name) {
        $LFlags += "Member of local Administrators group"
    }

    if ($LFlags.Count -gt 0) {
        $AuditResults += [PSCustomObject]@{
            Scope           = "Local Endpoint"
            AccountName     = $LUser.Name
            Enabled         = if($LUser.Enabled){"Active"}else{"Disabled"}
            LastLogon       = if($LUser.LastLogonDateTime){$LUser.LastLogonDateTime.ToString('yyyy-MM-dd')}else{"Never"}
            Findings        = ($LFlags -join ". ") + "."
            GroupMembership = if ($AdminMembers -contains $LUser.Name) { "Administrators" } else { "Standard Users" }
        }
    }
}
Write-Host "[+] Local endpoint scan completed." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Clean, Professional HTML Report Generation (No Emojis)
# ---------------------------------------------------------------------------
$TotalIssues = $AuditResults.Count

if ($TotalIssues -eq 0) {
    $HealthStatus = "<span style='color: #27ae60; font-weight: bold;'>COMPLIANT: No access anomalies detected.</span>"
} else {
    $HealthStatus = "<span style='color: #c0392b; font-weight: bold;'>ACTION REQUIRED: $TotalIssues account(s) require review to meet compliance standards.</span>"
}

$HTMLHeader = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Rights Security Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #f8f9fa; color: #2c3e50; margin: 30px; line-height: 1.6; }
        .container { max-width: 1000px; margin: auto; background: #ffffff; padding: 30px; border-radius: 8px; border: 1px solid #e1e8ed; box-shadow: 0 4px 10px rgba(0,0,0,0.03); }
        h2 { color: #0b192c; border-bottom: 2px solid #3498db; padding-bottom: 8px; margin-top: 0; text-transform: uppercase; font-size: 1.4rem; letter-spacing: 0.5px; }
        .summary-box { background: #f1f6fb; border-left: 4px solid #3498db; padding: 15px 20px; margin: 20px 0; border-radius: 2px; font-size: 0.95rem; }
        .summary-box td { padding: 4px 10px; border: none; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background-color: #0b192c; color: #ffffff; text-align: left; padding: 12px; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }
        td { padding: 12px; border-bottom: 1px solid #e1e8ed; font-size: 0.85rem; vertical-align: top; }
        tr:nth-child(even) { background-color: #fdfdfd; }
        tr:hover { background-color: #f4f6f9; }
        .footer { margin-top: 30px; font-size: 0.8rem; color: #7f8c8d; text-align: center; border-top: 1px solid #e1e8ed; padding-top: 15px; }
    </style>
</head>
<body>
<div class="container">
    <h2>Access Rights Security Audit Report</h2>
    <div class="summary-box">
        <strong>Executive Overview:</strong> $HealthStatus<br>
        <strong>Auditor:</strong> Yoseph Negussie Alula, MSc (BSI ISO/IEC 27001 Lead Auditor)<br>
        <strong>Target Environment:</strong> $env:COMPUTERNAME<br>
        <strong>Date Run:</strong> $(Get-Date -Format 'MMMM dd, yyyy - HH:mm')<br>
        <strong>Standard Alignment:</strong> ISO/IEC 27001:2022 (Controls A.5.15 & A.5.18)
    </div>
    <p>This report highlights user account configurations that deviate from enterprise baseline policies, such as long-term inactivity, missing password expiration requirements, or unmonitored administrative group memberships.</p>
"@

$HTMLBody = $AuditResults | ConvertTo-Html -Fragment

$HTMLFooter = @"
    <div class="footer">
        Generated automatically via Security Automation Scripts | OmniStackIT
    </div>
</div>
</body>
</html>
"@

# Merge components and force UTF-8 Encoding
$FinalHTML = $HTMLHeader + $HTMLBody + $HTMLFooter
$FinalHTML | Out-File -FilePath $ReportPath -Encoding utf8

Write-Host "========================================================" -ForegroundColor Green
Write-Host "   Audit complete! Executive report generated at:       " -ForegroundColor Green
Write-Host "   -> $ReportPath" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Green