#Requires -Modules @{ ModuleName="Microsoft.Graph.Authentication"; ModuleVersion="2.7.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Identity.SignIns"; ModuleVersion="2.7.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Groups"; ModuleVersion="2.7.0" }

$ErrorActionPreference = 'stop'

<#
    .SYNOPSIS
        CA Policy: CA206-Internals-DataandAppProtection-Office365-iOSorAndroid-ClientAppORAPP

    .DESCRIPTION
        A CA Policy requiring iOS and Android to use an approved app and app protection policy for Office 365.

    .NOTES
        AUTHOR: https://github.com/dwarfered/ConditionalAccessforZeroTrust
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

$policyName = 'CA206-Internals-DataandAppProtection-Office365-iOSorAndroid-ClientAppORAPP'

if (Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq  '$policyName'") {
    Write-Output "'$policyName' already exists, no changes have been made."
}
else {
    $personaGroups = @{}
    Initialize-RequiredPersonaGroups
    
    $policy = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphConditionalAccessPolicy]::new()
    $policy.DisplayName = $policyName
    $policy.State = 'disabled'

    $policy.Conditions.Users.IncludeGroups = $personaGroups['CA-Persona-Internals']
    $policy.Conditions.Users.ExcludeGroups = @($personaGroups['CA-BreakGlassAccounts'], $personaGroups['CA-Persona-Internals-BaseProtection-Exclusions'])
    $policy.Conditions.Applications.IncludeApplications = 'Office365'
    $policy.Conditions.ClientAppTypes = 'all'
    $policy.Conditions.Platforms.IncludePlatforms = @('android', 'iOS')
    
    $policy.GrantControls.Operator = 'OR'
    $policy.GrantControls.BuiltInControls = @('approvedApplication','compliantApplication')
    
    New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
}

