# MDE-KDFv1-Retirement

KQL Query to list devices which are still using the KDFv1 (Key Derivation Function) algorithm to store the Primary Refresh Token which was addressed in CVE-2021-33781. Unpatched devices using the KDFv1 algorithm will no longer be able to sign in to Entra ID. 

Based on Microsoft Entra news from June 2024, users of Windows devices that haven't been patched since July 2021 may experience login failures with their Entra ID user accounts on an Entra joined or hybrid joined Windows device because the KDFv1 algorithm will be retired. With the patch after July 2021, Windows clients will use the stronger KDFv2 algorithm.

## Microsoft Defender XDR

```kql
DeviceTvmSoftwareVulnerabilities 
| where CveId == "CVE-2021-33781"
| join kind = inner (DeviceInfo
        | summarize arg_max(Timestamp, *) by DeviceId
        )
    on $left.DeviceId == $right.DeviceId
| where SoftwareName in~("windows_10","windows_11") and JoinType in~("Hybrid Azure AD Join","AAD Joined")
| project DeviceId, 
    DeviceName,
    OSPlatform,
    OSVersion,
    OSVersionInfo,
    SoftwareVendor,
    SoftwareVersion,
    CveId,
    VulnerabilitySeverityLevel,
    RecommendedSecurityUpdate, 
    RecommendedSecurityUpdateId,
    JoinType,
    MachineGroup,
    LoggedOnUsers,
    OnboardingStatus
```
## References
- [Security update to Entra ID affecting clients which are running old, unpatched builds of Windows](https://techcommunity.microsoft.com/t5/microsoft-entra-blog/what-s-new-in-microsoft-entra-june-2024/ba-p/3796387)
