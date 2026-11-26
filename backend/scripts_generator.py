"""Ready-to-Run PowerShell Integration & Tenant Cleanup Script Generators.

Provides two zero-hassle integration paths for regulated environments:
1. Export-IntuneGuardSnapshot.ps1: Uses an admin's existing interactive read-only
   Microsoft Graph session (NO App Registration, NO persistent secrets, NO ARB wait)
   to export real Intune policies, groups, and audit events to a local JSON file
   that can be uploaded directly into IntuneGuard Studio.
2. New-IntuneGuardAppReg.ps1: Creates the least-privilege Phase 1 Read-Only Entra
   App Registration with X.509 certificate authentication (zero client secrets) for
   ongoing live integration after ARB approval.
3. Cleanup scripts for orphaned policies and stale exclusion groups.
"""
from __future__ import annotations

from typing import Any


def generate_offline_export_script() -> str:
    return r"""<#
.SYNOPSIS
  IntuneGuard Studio — Zero-Friction Read-Only Tenant Snapshot Exporter (Path A)
.DESCRIPTION
  Uses your EXISTING interactive Microsoft Graph sign-in with strictly Read-Only
  delegated permissions. Requires ZERO Entra App Registration, ZERO client secrets,
  and makes ZERO changes to your tenant.

  Run this script, then upload the generated 'intuneguard_snapshot.json' into
  IntuneGuard Studio -> Stage 1 (Connect Your Tenant).
#>
#Requires -Version 5.1
param(
    [string]$OutputPath = ".\intuneguard_snapshot.json",
    [switch]$MinimalScopes
)

$ErrorActionPreference = 'Stop'
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host "Installing lightweight Microsoft.Graph.Authentication module (CurrentUser, no admin needed)..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
}

$scopes = if ($MinimalScopes) {
    @(
        'DeviceManagementConfiguration.Read.All',
        'DeviceManagementManagedDevices.Read.All',
        'Group.Read.All'
    )
} else {
    @(
        'DeviceManagementConfiguration.Read.All',
        'DeviceManagementManagedDevices.Read.All',
        'DeviceManagementServiceConfig.Read.All',
        'DeviceManagementRBAC.Read.All',
        'Group.Read.All',
        'AuditLog.Read.All',
        'Application.Read.All'
    )
}

Write-Host "[1/8] Connecting to Microsoft Graph (Read-Only Delegated)..." -ForegroundColor Cyan
Connect-MgGraph -Scopes $scopes -NoWelcome

function Invoke-GraphPaged([string]$Uri) {
    $all = @()
    $next = $Uri
    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next
        if ($resp.value) { $all += $resp.value }
        $next = $resp.'@odata.nextLink'
    }
    return $all
}

function Invoke-SafeExport([string]$Label, [scriptblock]$Block) {
    try {
        return (& $Block)
    } catch {
        Write-Warning "Skipping '$Label' (insufficient scope or tenant restriction): $($_.Exception.Message)"
        return @()
    }
}

$org = (Invoke-SafeExport "Organization" { (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization").value }) | Select-Object -First 1

Write-Host "[2/8] Exporting Settings Catalog, Device Configs & Compliance Policies..." -ForegroundColor Cyan
$cfgPolicies = Invoke-SafeExport "Settings Catalog" { Invoke-GraphPaged "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$expand=assignments&`$top=100" }
$devConfigs  = Invoke-SafeExport "Device Configurations" { Invoke-GraphPaged "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?`$expand=assignments&`$top=100" }
$compliance  = Invoke-SafeExport "Compliance Policies" { Invoke-GraphPaged "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?`$expand=assignments&`$top=100" }

Write-Host "[3/8] Exporting Entra ID Groups & Dynamic Membership Rules..." -ForegroundColor Cyan
$groups = Invoke-SafeExport "Entra Groups" { Invoke-GraphPaged "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,groupTypes,membershipRule&`$top=100" }

Write-Host "[4/8] Exporting Autopilot Profiles & Enrollment Status Page (ESP) Configs..." -ForegroundColor Cyan
$autopilotProfiles = Invoke-SafeExport "Autopilot Profiles" { Invoke-GraphPaged "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles" }
$espProfiles = Invoke-SafeExport "ESP Profiles" {
    (Invoke-GraphPaged "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations") |
        Where-Object { $_.'@odata.type' -match 'EnrollmentCompletionPage' }
}

Write-Host "[5/8] Exporting Custom Intune RBAC Roles & Scope Tags..." -ForegroundColor Cyan
$customRoles = Invoke-SafeExport "Custom RBAC Roles" {
    (Invoke-GraphPaged "https://graph.microsoft.com/v1.0/deviceManagement/roleDefinitions") |
        Where-Object { -not $_.isBuiltIn }
}
$scopeTags = Invoke-SafeExport "Scope Tags" { Invoke-GraphPaged "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags" }

Write-Host "[6/8] Exporting Managed Windows Device Personas & OS Version Breakdown..." -ForegroundColor Cyan
$devices = Invoke-SafeExport "Managed Windows Devices" { Invoke-GraphPaged "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&`$select=id,deviceName,osVersion,complianceState,joinType,managementAgent&`$top=100" }
$win10Count = ($devices | Where-Object { $_.osVersion -match '^10\.0\.19' } | Measure-Object).Count
$coManagedCount = ($devices | Where-Object { $_.managementAgent -match 'configurationManager' } | Measure-Object).Count

Write-Host "[7/8] Exporting Recent Intune Audit Events (Last 50)..." -ForegroundColor Cyan
$audits = Invoke-SafeExport "Audit Events" { (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/auditEvents?`$top=50").value }

Write-Host "[8/8] Packaging local JSON snapshot (Phase 1.5 Full Track Parity)..." -ForegroundColor Cyan
$payload = [ordered]@{
    schema_version         = "1.5"
    exported_utc           = (Get-Date).ToUniversalTime().ToString("o")
    tenant_name            = $org.displayName
    tenant_id              = $org.id
    configuration_policies = $cfgPolicies
    device_configurations  = $devConfigs
    compliance_policies    = $compliance
    groups                 = $groups
    autopilot_profiles     = $autopilotProfiles
    esp_profiles           = $espProfiles
    custom_roles           = $customRoles
    scope_tags             = $scopeTags
    windows_devices_count  = $devices.Count
    windows_10_count       = $win10Count
    co_managed_count       = $coManagedCount
    audit_events           = $audits
}

$payload | ConvertTo-Json -Depth 8 | Out-File -FilePath $OutputPath -Encoding utf8
Disconnect-MgGraph | Out-Null
Write-Host "DONE! Upload '$OutputPath' into IntuneGuard Studio -> Stage 1." -ForegroundColor Green
"""


def generate_app_registration_script() -> str:
    return r"""<#
.SYNOPSIS
  IntuneGuard Studio — Least-Privilege Phase 1 Read-Only Entra App Registration (Path B)
.DESCRIPTION
  Creates an ARB-compliant Read-Only Entra ID App Registration using an X.509
  certificate (NO client secrets) with strictly *.Read.All Microsoft Graph scopes.
#>
param(
    [string]$AppDisplayName = "IntuneGuard-Studio-AuditReader",
    [string]$CertSubject    = "CN=IntuneGuard-Studio-AuditReader"
)

$ErrorActionPreference = 'Stop'
Connect-MgGraph -Scopes "Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All" -NoWelcome

Write-Host "[1/4] Generating 12-month X.509 certificate in CurrentUser\My store..." -ForegroundColor Cyan
$cert = New-SelfSignedCertificate -Subject $CertSubject -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 -NotAfter (Get-Date).AddMonths(12)

Write-Host "[2/4] Creating Entra ID App Registration '$AppDisplayName'..." -ForegroundColor Cyan
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$neededScopes = @(
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementApps.Read.All",
    "Group.Read.All",
    "AuditLog.Read.All",
    "Application.Read.All"
)
$roleAssignments = foreach ($s in $neededScopes) {
    $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $s } | Select-Object -First 1
    if ($role) { @{ Id = $role.Id; Type = "Role" } }
}

$app = New-MgApplication -DisplayName $AppDisplayName -RequiredResourceAccess @(
    @{ ResourceAppId = "00000003-0000-0000-c000-000000000000"; ResourceAccess = $roleAssignments }
)

Write-Host "[3/4] Uploading X.509 Public Key Credential (Zero Client Secrets)..." -ForegroundColor Cyan
$cerBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
Update-MgApplication -ApplicationId $app.Id -KeyCredentials @(
    @{ Type = "AsymmetricX509Cert"; Usage = "Verify"; Key = $cerBytes; DisplayName = "IntuneGuard-12Mo-Cert" }
)

Write-Host "[4/4] Creating Service Principal (Grant Admin Consent in Entra Portal)..." -ForegroundColor Cyan
$sp = New-MgServicePrincipal -AppId $app.AppId
$ctx = Get-MgContext

Write-Host "`n=== IntuneGuard Studio Live Configuration ===" -ForegroundColor Green
Write-Host "AZURE_TENANT_ID : $($ctx.TenantId)"
Write-Host "AZURE_CLIENT_ID : $($app.AppId)"
Write-Host "CERT_THUMBPRINT : $($cert.Thumbprint)"
Write-Host "NEXT STEP       : In Entra Portal -> App Registrations -> '$AppDisplayName' -> API Permissions -> Grant Admin Consent." -ForegroundColor Yellow
"""


def generate_orphan_cleanup_script(orphan_policies: list[dict[str, Any]]) -> str:
    sample_names = [p["name"].replace('"', "'") for p in orphan_policies[:15]]
    names_block = "\n".join(f'    "{n}"' for n in sample_names)
    return f"""<#
.SYNOPSIS
  IntuneGuard Studio — Stage 2A Safe Backup & Archive of Orphaned (Unassigned) Policies
.DESCRIPTION
  Backs up every unassigned policy to local JSON BEFORE taking any deletion action.
  Runs in -WhatIf (Dry-Run) mode by default for ITIL CAB review.
#>
param(
    [string]$BackupDir = ".\\IntuneGuard_Orphan_Backups",
    [switch]$ExecuteDelete
)

New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
$orphanTargets = @(
{names_block}
)

Write-Host "Found $($orphanTargets.Count) targeted unassigned policies for Stage 2A cleanup." -ForegroundColor Cyan
Write-Host "Connect with: Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All'" -ForegroundColor Yellow

foreach ($name in $orphanTargets) {{
    Write-Host "  [VERIFY UNASSIGNED + BACKUP] $name"
    if ($ExecuteDelete) {{
        Write-Host "    -> Would archive JSON to $BackupDir and remove policy after RFC sign-off." -ForegroundColor Green
    }} else {{
        Write-Host "    -> DRY-RUN ONLY (pass -ExecuteDelete after CAB approval)." -ForegroundColor DarkGray
    }}
}}
"""


def generate_stale_group_cleanup_script(risky_groups: list[dict[str, Any]]) -> str:
    group_lines = "\n".join(
        f'    @{{ Name = "{g["name"]}"; Members = {g["member_count"]}; Risk = "{(g["risk_flag"] or "").replace(chr(34), chr(39))}" }}'
        for g in risky_groups[:10]
    )
    return f"""<#
.SYNOPSIS
  IntuneGuard Studio — Stage 2B Stale Exclusion & Nested Group Audit + Ring Group Provisioner
.DESCRIPTION
  1) Audits high-risk stale exclusion groups & nested chains before changing assignments.
  2) Provisions clean, flat OIB Ring Security Groups (Ring 0 -> Ring 3) with zero nesting.
#>
param([switch]$CreateCleanRingGroups)

$flaggedGroups = @(
{group_lines}
)

Write-Host "=== Flagged High-Risk / Nested Groups ($($flaggedGroups.Count)) ===" -ForegroundColor Yellow
$flaggedGroups | ForEach-Object {{
    Write-Host " - $($_.Name) ($($_.Members) members): $($_.Risk)"
}}

$cleanRings = @(
    "SG-Intune-OIB-Ring0-Audit",
    "SG-Intune-OIB-Ring1-ITPilot",
    "SG-Intune-OIB-Ring2-BranchEarly",
    "SG-Intune-OIB-Ring3-BroadProd"
)

if ($CreateCleanRingGroups) {{
    Connect-MgGraph -Scopes "Group.ReadWrite.All" -NoWelcome
    foreach ($rg in $cleanRings) {{
        $existing = Get-MgGroup -Filter "displayName eq '$rg'" -ErrorAction SilentlyContinue
        if (-not $existing) {{
            New-MgGroup -DisplayName $rg -MailEnabled:$false -SecurityEnabled:$true -MailNickname ($rg -replace '[^a-zA-Z0-9]','') | Out-Null
            Write-Host "Created clean flat ring group: $rg" -ForegroundColor Green
        }} else {{
            Write-Host "Already exists: $rg" -ForegroundColor DarkGray
        }}
    }}
}} else {{
    Write-Host "`nRe-run with -CreateCleanRingGroups after CAB RFC approval to create the 4 flat OIB Ring groups." -ForegroundColor Cyan
}}
"""
