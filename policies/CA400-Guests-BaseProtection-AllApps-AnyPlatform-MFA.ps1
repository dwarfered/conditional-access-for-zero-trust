#Requires -Modules @{ ModuleName="Microsoft.Graph.Authentication"; ModuleVersion="2.7.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Identity.SignIns"; ModuleVersion="2.7.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Groups"; ModuleVersion="2.7.0" }

$ErrorActionPreference = 'stop'

<#
    .SYNOPSIS
        CA Policy: CA400-Guests-BaseProtection-AllApps-AnyPlatform-MFA

    .DESCRIPTION
        A CA Policy requiring MFA for Guests.

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
        'CA-BreakGlassAccounts',
        'CA-Persona-Guests-BaseProtection-Exclusions',
        'CA-Persona-GuestAdmins')

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

$policyName = 'CA400-Guests-BaseProtection-AllApps-AnyPlatform-MFA'

if (Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq  '$policyName'") {
    Write-Output "'$policyName' already exists, no changes have been made."
}
else {
    $personaGroups = @{}
    Initialize-RequiredPersonaGroups
    
    $policy = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphConditionalAccessPolicy]::new()
    $policy.DisplayName = $policyName
    $policy.State = 'disabled'

    $policy.Conditions.Users.IncludeGuestsOrExternalUsers.ExternalTenants.MembershipKind = 'all'
    $policy.Conditions.Users.IncludeGuestsOrExternalUsers.GuestOrExternalUserTypes = 'internalGuest,
    b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider'
    $policy.Conditions.Users.ExcludeGroups = @(
        $personaGroups['CA-BreakGlassAccounts'],
        $personaGroups['CA-Persona-Guests-BaseProtection-Exclusions'],
        $personaGroups['CA-Persona-GuestAdmins']
    )
    $policy.Conditions.Applications.IncludeApplications = 'All'
    $policy.Conditions.ClientAppTypes = 'all'
    
    $policy.GrantControls.Operator = 'OR'
    $policy.GrantControls.BuiltInControls = 'mfa'
    
    New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
}

