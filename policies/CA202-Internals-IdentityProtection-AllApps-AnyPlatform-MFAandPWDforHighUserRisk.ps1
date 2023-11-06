#Requires -Modules @{ ModuleName="Microsoft.Graph.Authentication"; ModuleVersion="2.7.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Identity.SignIns"; ModuleVersion="2.7.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Groups"; ModuleVersion="2.7.0" }

$ErrorActionPreference = 'stop'

<#
    .SYNOPSIS
        CA Policy: CA202-Internals-IdentityProtection-AllApps-AnyPlatform-MFAandPWDforHighUserRisk

    .DESCRIPTION
        A CA Policy requring MFA and a password change for High User Risk.

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
        'CA-Persona-Internals-IdentityProtection-Exclusions')

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

$policyName = 'CA202-Internals-IdentityProtection-AllApps-AnyPlatform-MFAandPWDforHighUserRisk'

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
    $policy.Conditions.Users.ExcludeGroups = @($personaGroups['CA-BreakGlassAccounts'], $personaGroups['CA-Persona-Internals-IdentityProtection-Exclusions'])
    $policy.Conditions.Applications.IncludeApplications = 'All'
    $policy.Conditions.ClientAppTypes = 'all'
    $policy.Conditions.UserRiskLevels = 'high'

    $policy.GrantControls.Operator = 'AND'
    $policy.GrantControls.BuiltInControls = @('mfa', 'passwordChange')

    $policy.SessionControls.SignInFrequency.AuthenticationType = 'primaryAndSecondaryAuthentication'
    $policy.SessionControls.SignInFrequency.FrequencyInterval = 'everyTime'
    $policy.SessionControls.SignInFrequency.IsEnabled = $true
    
    New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
}

