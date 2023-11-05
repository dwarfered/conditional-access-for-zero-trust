#Requires -Modules @{ ModuleName="Microsoft.Graph.Authentication"; ModuleVersion="2.7.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Identity.SignIns"; ModuleVersion="2.7.0" }


$ErrorActionPreference = 'stop'

<#
    .SYNOPSIS
        CA Policy: CA901-WorkloadIdentities-BaseProtection-AllApps-AnyPlatform-BlockHighRisk

    .DESCRIPTION
        Workload Identities with a Service Principal Risk of High are blocked.

    .NOTES
        AUTHOR: https://github.com/dwarfered/ConditionalAccessforZeroTrust
        UPDATED: 05-11-2023

        Requires Workload Identity Premium License
#>

$requiredScopes = @('Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'Application.Read.All', 'Group.ReadWrite.All')

if ($null -eq $currentScopes) {
    Connect-MgGraph -Scopes $requiredScopes | Out-Null
}
elseif (($currentScopes -match ([string]::Join('|', $requiredScopes))).Count -ne $requiredScopes.Count) {
    Connect-MgGraph -Scopes $requiredScopes | Out-Null
}

$policyName = 'CA901-WorkloadIdentities-BaseProtection-AllApps-AnyPlatform-BlockHighRisk'

if (Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq  '$policyName'") {
    Write-Output "'$policyName' already exists, no changes have been made."
}
else {
    $policy = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphConditionalAccessPolicy]::new()
    $policy.DisplayName = $policyName
    $policy.State = 'disabled'

    $policy.Conditions.ClientApplications.IncludeServicePrincipals = 'ServicePrincipalsInMyTenant'
    $policy.Conditions.Applications.IncludeApplications = 'All'
    $policy.Conditions.ClientAppTypes = 'all'
    $policy.Conditions.Locations.IncludeLocations = 'All'
    $policy.Conditions.ServicePrincipalRiskLevels = 'high'
    
    $policy.GrantControls.Operator = 'OR'
    $policy.GrantControls.BuiltInControls = 'block'
    
    New-MgBetaIdentityConditionalAccessPolicy -BodyParameter $policy
}

