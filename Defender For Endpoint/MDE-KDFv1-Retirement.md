# MDE-KDFv1-Retirement

Query to find Windows 10 / 11 hybrid joined or joined devices without security updates after July 2021. 

Based on Microsoft Entra news from June 2024, users of Windows devices that haven't been patched since July 2021 may experience login failures with their Entra ID user accounts on an Entra joined or hybrid joined Windows device because the KDFv1 algorithms will be retired. With the patch after July 2021, Windows clients will use the stronger KDFv2 algorithm.

## Microsoft Defender XDR

```kql
DeviceTvmSoftwareVulnerabilities 
| where CveId == "CVE-2021-33781"
| join (DeviceInfo
        | summarize arg_max(Timestamp, *) by DeviceId
        )
    on $left.DeviceId == $right.DeviceId
| where SoftwareName in("windows_10","windows_11") and JoinType in("Hybrid Azure AD Join","AAD Joined")
| project DeviceId,DeviceName, OSPlatform, OSVersion, OSVersionInfo, SoftwareVendor, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, RecommendedSecurityUpdateId, JoinType, MachineGroup, LoggedOnUsers, OnboardingStatus
```
## References
- [Security update to Entra ID affecting clients which are running old, unpatched builds of Windows](https://techcommunity.microsoft.com/t5/microsoft-entra-blog/what-s-new-in-microsoft-entra-june-2024/ba-p/3796387)
