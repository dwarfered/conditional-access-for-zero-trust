#Requires -Modules @{ ModuleName="Microsoft.Graph.Authentication"; ModuleVersion="2.7.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Identity.SignIns"; ModuleVersion="2.7.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Groups"; ModuleVersion="2.7.0" }

$ErrorActionPreference = 'stop'

<#
    .SYNOPSIS
        CA Policy: CA406-Guests-DataProtection-AllApps-AnyPlatform-SignInSessionPolicy

    .DESCRIPTION
        Guests have a limited sign-in session.

    .NOTES
        AUTHOR: https://github.com/dwarfered/ConditionalAccessforZeroTrust
        UPDATED: 05-11-2023
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
        'CA-Persona-Guests-DataProtection-Exclusions')

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

$policyName = 'CA406-Guests-DataProtection-AllApps-AnyPlatform-SignInSessionPolicy'

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
        $personaGroups['CA-Persona-Guests-DataProtection-Exclusions']
    )
    $policy.Conditions.Applications.IncludeApplications = 'All'
    $policy.Conditions.ClientAppTypes = 'all'
    
    $policy.SessionControls.PersistentBrowser.IsEnabled = $true
    $policy.SessionControls.PersistentBrowser.Mode = 'never'
    $policy.SessionControls.SignInFrequency.AuthenticationType = 'primaryAndSecondaryAuthentication'
    $policy.SessionControls.SignInFrequency.FrequencyInterval = 'timeBased'
    $policy.SessionControls.SignInFrequency.IsEnabled = $true
    $policy.SessionControls.SignInFrequency.Type = 'hours'
    $policy.SessionControls.SignInFrequency.Value = 1
    
    New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
}

