<h1>MDE-KDFv1-Retirement</h1>
Query to find Windows devices without security updates after July 2021 Based on the [Microsoft Announcement] (https://techcommunity.microsoft.com/t5/microsoft-entra-blog/what-s-new-in-microsoft-entra-june-2024/ba-p/3796387), users of Windows devices that haven't been updated with patches since July 2021 may experience login failures with their Entra ID user accounts on a entra joined or hybrid joined Windows device.

<h2>Microsoft Defender XDR</h2>

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

<h2> References </h2>
* [Security update to Entra ID affecting clients which are running old, unpatched builds of Windows] (https://techcommunity.microsoft.com/t5/microsoft-entra-blog/what-s-new-in-microsoft-entra-june-2024/ba-p/3796387)
