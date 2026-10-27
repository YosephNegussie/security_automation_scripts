<#
.SYNOPSIS
    Windows Endpoint Security Baseline Hardening & Audit Script
.DESCRIPTION
    Audits and enforces core Windows security hardening controls (SMBv1 status, Firewall, UAC, RDP NLA)
    to satisfy ISO/IEC 27001 Configuration Management and System Security baselines.
.AUTHOR
    Yoseph Negussie Alula, MSc | BSI ISO/IEC 27001 Lead Auditor
#>

[CmdletBinding()]
param (
    [string]$ReportPath = ".\ISO27001_Hardening_Report.html",
    [switch]$Enforce = $false
)

# Ensure script is run with Administrator privileges
If (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Error: This script must be run as an Administrator to audit and modify system baselines." -ForegroundColor Red
    Exit
}

$HardeningResults = @()

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "   Starting Windows Endpoint Security Baseline Audit... " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Check SMBv1 Status (Legacy Protocol Vulnerability)
# ---------------------------------------------------------------------------
Write-Host "[*] Checking SMBv1 protocol status..." -ForegroundColor Yellow
try {
    $SMB1Status = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    $isSMB1Enabled = if ($SMB1Status) { $SMB1Status.State -eq "Enabled" } else { $false }
} catch {
    $isSMB1Enabled = $false
}

$smbFinding = if ($isSMB1Enabled) { "CRITICAL: Legacy SMBv1 is Enabled (Vulnerable to EternalBlue/WannaCry)." } else { "COMPLIANT: SMBv1 is disabled." }
$HardeningResults += [PSCustomObject]@{
    ControlArea = "File Sharing Protocol"
    Setting     = "SMBv1 Feature"
    Status      = if($isSMB1Enabled){"Non-Compliant"}else{"Compliant"}
    Details     = $smbFinding
}

# ---------------------------------------------------------------------------
# 2. Check Windows Firewall Profiles
# ---------------------------------------------------------------------------
Write-Host "[*] Checking Windows Firewall status across profiles..." -ForegroundColor Yellow
$FirewallProfiles = Get-NetFirewallProfile
foreach ($Profile in $FirewallProfiles) {
    $isFirewallEnabled = $Profile.Enabled
    $fwStatus = if ($isFirewallEnabled) { "COMPLIANT: $($Profile.Name) Firewall is Enabled." } else { "NON-COMPLIANT: $($Profile.Name) Firewall is Disabled." }
    
    $HardeningResults += [PSCustomObject]@{
        ControlArea = "Network Security"
        Setting     = "$($Profile.Name) Firewall Profile"
        Status      = if($isFirewallEnabled){"Compliant"}else{"Non-Compliant"}
        Details     = $fwStatus
    }
}

# ---------------------------------------------------------------------------
# 3. Check User Account Control (UAC) Status
# ---------------------------------------------------------------------------
Write-Host "[*] Checking User Account Control (UAC) configuration..." -ForegroundColor Yellow
$UACEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
$uacStatus = if ($UACEnabled -eq 1) { "COMPLIANT: UAC is enabled and enforcing restrictions." } else { "NON-COMPLIANT: UAC is disabled or restricted." }

$HardeningResults += [PSCustomObject]@{
    ControlArea = "Endpoint Access Control"
    Setting     = "User Account Control (EnableLUA)"
    Status      = if($UACEnabled -eq 1){"Compliant"}else{"Non-Compliant"}
    Details     = $uacStatus
}

# ---------------------------------------------------------------------------
# 4. Check Remote Desktop Network Level Authentication (NLA)
# ---------------------------------------------------------------------------
Write-Host "[*] Checking RDP Network Level Authentication (NLA)..." -ForegroundColor Yellow
$RDPNLA = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
$nlaStatus = if ($RDPNLA -eq 1) { "COMPLIANT: RDP NLA is required." } else { "NON-COMPLIANT: RDP NLA is not strictly enforced." }

$HardeningResults += [PSCustomObject]@{
    ControlArea = "Remote Access Security"
    Setting     = "RDP Network Level Authentication"
    Status      = if($RDPNLA -eq 1){"Compliant"}else{"Non-Compliant"}
    Details     = $nlaStatus
}

# ---------------------------------------------------------------------------
# 5. Generate Executive HTML Report
# ---------------------------------------------------------------------------
$NonCompliantCount = ($HardeningResults | Where-Object { $_.Status -eq "Non-Compliant" }).Count

if ($NonCompliantCount -eq 0) {
    $HealthStatus = "<span style='color: #27ae60; font-weight: bold;'>COMPLIANT: Endpoint meets all core baseline hardening standards.</span>"
} else {
    $HealthStatus = "<span style='color: #c0392b; font-weight: bold;'>ACTION REQUIRED: $NonCompliantCount hardening control(s) failed baseline evaluation.</span>"
}

$TableRows = ""
foreach ($Item in $HardeningResults) {
    $statusColor = if ($Item.Status -eq "Compliant") { "#27ae60" } else { "#c0392b" }
    $TableRows += "<tr><td><b>$($Item.ControlArea)</b></td><td>$($Item.Setting)</td><td style='color: $statusColor; font-weight: bold;'>$($Item.Status)</td><td>$($Item.Details)</td></tr>"
}

$HTMLContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Windows Endpoint Hardening Baseline Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #f8f9fa; color: #2c3e50; margin: 30px; line-height: 1.6; }
        .container { max-width: 1100px; margin: auto; background: #ffffff; padding: 30px; border-radius: 8px; border: 1px solid #e1e8ed; box-shadow: 0 4px 10px rgba(0,0,0,0.03); }
        h2 { color: #0b192c; border-bottom: 2px solid #3498db; padding-bottom: 8px; margin-top: 0; text-transform: uppercase; font-size: 1.4rem; letter-spacing: 0.5px; }
        .summary-box { background: #f1f6fb; border-left: 4px solid #3498db; padding: 15px 20px; margin: 20px 0; border-radius: 2px; font-size: 0.95rem; }
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
    <h2>Windows Endpoint Hardening Baseline Report</h2>
    <div class="summary-box">
        <strong>Executive Overview:</strong> $HealthStatus<br>
        <strong>Lead Auditor:</strong> Yoseph Negussie Alula, MSc (BSI ISO/IEC 27001 Lead Auditor)<br>
        <strong>Target Host:</strong> $env:COMPUTERNAME<br>
        <strong>Date Run:</strong> $(Get-Date -Format 'MMMM dd, yyyy - HH:mm')<br>
        <strong>Standard Alignment:</strong> ISO/IEC 27001:2022 (Control A.8.9 - Configuration Management)
    </div>

    <table>
        <tr><th>Control Area</th><th>Hardening Setting</th><th>Status</th><th>Assessment Details</th></tr>
        $TableRows
    </table>

    <div class="footer">
        Generated automatically via Security Automation Scripts | OmniStackIT
    </div>
</div>
</body>
</html>
"@

$HTMLContent | Out-File -FilePath $ReportPath -Encoding utf8

Write-Host "========================================================" -ForegroundColor Green
Write-Host "   Hardening audit complete! Report generated at:       " -ForegroundColor Green
Write-Host "   -> $ReportPath" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Green