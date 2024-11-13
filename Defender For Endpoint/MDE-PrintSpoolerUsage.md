# MDE-PrintSpoolerUsage

The spooler accepts print jobs from computers and ensures that printer resources are available. To mitigate Print Spooler attacks, it is recommended that the Print Spooler service is disabled if the service is not required (e.g. Print Server). This KQL query lists each Windows server that is using the print spooler because an external client has accessed the print spooler service.

## Microsoft Defender XDR
```kql
let lookback = 30d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName == @"spoolsv.exe"
| where ActionType != @"ListeningConnectionCreated" and ActionType != @"ConnectionFailed" 
| join kind = inner
    (
    DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId
    )
    on $left.DeviceId == $right.DeviceId
| where OSPlatform startswith "WindowsServer"
| summarize PrintSpoolerUsageCount = count() by DeviceName
```

## Microsoft Sentinel
```kql
let lookback = 30d;
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where InitiatingProcessFileName == @"spoolsv.exe"
| where ActionType != @"ListeningConnectionCreated" and ActionType != @"ConnectionFailed" 
| join kind = inner
    (
    DeviceInfo
    | summarize arg_max(TimeGenerated, *) by DeviceId
    )
    on $left.DeviceId == $right.DeviceId
| where OSPlatform startswith "WindowsServer"
| summarize PrintSpoolerUsageCount = count() by DeviceName
```

## References
- [Print Spooler Service](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-prsod/7262f540-dd18-46a3-b645-8ea9b59753dc)
- [Defender for Identity Print Spooler Assessment](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-print-spooler)