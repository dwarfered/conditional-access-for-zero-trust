# Conditional Access for Zero Trust

Deployment of Zero Trust, persona-based Azure AD Conditional Access Policies via Microsoft Graph, utilizing PowerShell.

Based upon the excellent [Microsoft Learn: Conditional Access architecture and personas](https://learn.microsoft.com/en-us/azure/architecture/guide/security/conditional-access-architecture) and [Framework and policies](https://learn.microsoft.com/en-us/azure/architecture/guide/security/conditional-access-framework) pages authored by [Claus Jespersen](https://www.linkedin.com/in/claus-jespersen-25b0422/).

## Prerequisite
[PowerShell SDK for Microsoft Graph](https://github.com/microsoftgraph/msgraph-sdk-powershell)
```powershell
Install-Module Microsoft.Graph -AllowClobber -Force
```
Optionally, also install:
```powershell
Install-Module Microsoft.Graph.Beta -AllowClobber -Force
```

<img src="images/overview.PNG" width="800">

Conditional Access Policies as code deployed via the PowerShell SDK for Microsoft Graph.

## Policies

> Policies can be deployed in any order and will be 'Off' by default. 

> Persona groups will be created if they do not already exist.

<small>*This collection is a work in progress*.</small>

### Internals

#### CA200-Internals-BaseProtection-AllApps-AnyPlatform-CompliantorAADHJ
Internals require a Compliant or Domain-Joined Device.

#### CA201-Internals-IdentityProtection-AllApps-AnyPlatform-CombinedRegistration
Internals performing Security registration (ie. MFA enrollment) require a Compliant or Domain-Joined Device.

#### CA202-Internals-IdentityProtection-AllApps-AnyPlatform-MFAandPWDforHighUserRisk
Internals with High User Risk must perform MFA and change their password.

#### CA203-Internals-IdentityProtection-AllApps-AnyPlatform-MFAforHighSignInRisk
Internals with High Sign-In Risk must perform MFA.

#### CA204-Internals-IdentityProtection-AllApps-AnyPlatform-BlockLegacyAuth
Internals are blocked from Legacy Authentication methods.

#### CA205-Internals-AppProtection-MicrosoftIntuneEnrollment-AnyPlatform-MFA
Internals must perform MFA to enroll a device.

#### CA206-Internals-DataandAppProtection-Office365-iOSorAndroid-ClientAppORAPP
Internals accessing Office 365 from iOS or Android must use an Approved App or an App Protection Policy.

#### CA207-Internals-AttackSurfaceReduction-AllApps-AnyPlatform-BlockUnknownPlatforms
Internals on unknown platforms are blocked.

### Guests

#### CA400-Guests-BaseProtection-AllApps-AnyPlatform-MFA
Guests must perform MFA.

#### CA402-Guests-IdentityProtection-AllApps-AnyPlatform-MFAforMediumandHighUserandSignInRisk
Guests with Medium or High Risk must always perform MFA.

#### CA403-Guests-IdentityProtection-AllApps-AnyPlatform-BlockLegacyAuth
Guests are blocked from Legacy Authentication methods.

#### CA406-Guests-DataProtection-AllApps-AnyPlatform-SignInSessionPolicy
Guests have a limited Sign-In Session.

### Workload Identities

#### CA900-WorkloadIdentities-BaseProtection-AllApps-AnyPlatform-BlockUntrustedLocations
Workload Identities in untrusted locations are blocked.

#### CA901-WorkloadIdentities-BaseProtection-AllApps-AnyPlatform-BlockHighRisk
Workload Identities with High Risk are blocked.
