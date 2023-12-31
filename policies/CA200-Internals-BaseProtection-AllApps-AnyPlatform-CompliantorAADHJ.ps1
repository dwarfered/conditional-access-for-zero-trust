#Requires -Modules @{ ModuleName="Microsoft.Graph.Applications"; ModuleVersion="2.7.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Authentication"; ModuleVersion="2.7.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Identity.SignIns"; ModuleVersion="2.7.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Groups"; ModuleVersion="2.7.0" }

$ErrorActionPreference = 'stop'

<#
    .SYNOPSIS
        CA Policy: CA200-Internals-BaseProtection-AllApps-AnyPlatform-CompliantorAADHJ

    .DESCRIPTION
        A CA Policy mandating all Internals use a Compliant or AAD Hybrid Joined Device

    .NOTES
        AUTHOR: https://github.com/dwarfered/conditional-access-for-zero-trust
        UPDATED: 04-11-2023
#>

$requiredScopes = @('Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'Application.Read.All', 'Group.ReadWrite.All')

if ($null -eq $currentScopes) {
    Connect-MgGraph -Scopes $requiredScopes | Out-Null
}
elseif (($currentScopes -match ([string]::Join('|', $requiredScopes))).Count -ne $requiredScopes.Count) {
    Connect-MgGraph -Scopes $requiredScopes | Out-Null
}

function Initialize-RequiredPersonaGroups {
    # Checks they exist and create if missing.
    $prerequisiteGroups = @(
        'CA-Persona-Internals',
        'CA-BreakGlassAccounts',
        'CA-Persona-Internals-BaseProtection-Exclusions')

    $prerequisiteGroups | ForEach-Object {
        $personaGroup = (Get-MgGroup -Filter "displayName eq '$PSItem'")
        if ($null -eq $personaGroup) {
            $params = @{
                description     = "CA Persona Group"
                groupTypes      = @()
                displayName     = $PSItem
                mailEnabled     = $false
                securityEnabled = $true
                mailNickName    = $PSItem
            }
            $personaGroup = New-MgGroup -BodyParameter $params
            if ($PSItem -eq 'CA-BreakglassAccounts') {
                # Adds the user of this script as a member.
                $currentUpn = (Get-MgContext).Account
                $params = @{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/users/$currentUpn"
                }
                New-MgGroupMemberByRef -GroupId $personaGroup.Id -BodyParameter $params
            }
        }
        $personaGroups.Add($PSItem, $personaGroup.Id)
    }
}

$policyName = 'CA200-Internals-BaseProtection-AllApps-AnyPlatform-CompliantorAADHJ'

if (Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq  '$policyName'") {
    Write-Output "'$policyName' already exists, no changes have been made."
}
else {
    $personaGroups = @{}
    Initialize-RequiredPersonaGroups
    
    $microsoftIntuneEnrollment = 'd4ebce55-015a-49b5-a083-c84d1797ae8c'
    $intuneEnrollment = Get-MgServicePrincipal -Filter "appId eq '$microsoftIntuneEnrollment'"
    if ($null -eq $intuneEnrollment) {
        $requiredScopes += 'Application.ReadWrite.All'
        Connect-MgGraph -Scopes $requiredScopes | Out-Null
        New-MgServicePrincipal -AppId $microsoftIntuneEnrollment | Out-Null
    }
    
    $policy = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphConditionalAccessPolicy]::new()
    $policy.DisplayName = $policyName
    $policy.State = 'disabled'
    
    $policy.Conditions.Users.IncludeGroups = $personaGroups['CA-Persona-Internals']
    $policy.Conditions.Users.ExcludeGroups = @($personaGroups['CA-BreakGlassAccounts'], $personaGroups['CA-Persona-Internals-BaseProtection-Exclusions'])
    $policy.Conditions.Applications.IncludeApplications = 'All'
    $policy.Conditions.Applications.ExcludeApplications = $microsoftIntuneEnrollment
    $policy.Conditions.ClientAppTypes = 'all'
    
    $policy.GrantControls.Operator = 'OR'
    $policy.GrantControls.BuiltInControls = @('compliantDevice', 'domainJoinedDevice')
    
    New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
}

