# MDE-DefaultLocalAdmin-Logon
This KQL query identifies logon events for the default local administrator (.\Administrator) with SID starting with S-1-5 and ending with 500 (according well-know SIDs). As the default domain administrator also starts with S-1-5 and ends with -500, the query includes a table containing the default domain administrator's SID of the domain to exclude these logons.

The following logon types exists:


| Logon Type | Description |
| ----------| ---------- |
| Interactive | User physically interacts with the device using the local keyboard and screen. |
| Remote interactive (RDP) logons | User interacts with the device remotely using Remote Desktop, Terminal Services, Remote Assistance, or other RDP clients. |
| Network | Session initiated when the device is accessed using PsExec or when shared resources on the device, such as printers and shared folders, are accessed.
| Batch  |  Session initiated by scheduled tasks.
| Service |  Session initiated by services as they start.

## Microsoft Defender XDR

```kql
let DefauldDomainAdministrators = dynamic([
    "S-1-5-XXXXXXXXXX-XXXXXXXXX-XXXXXXXXXX-500", //Default Domain Administrator SID Domain X
    "S-1-5-XXXXXXXXXX-XXXXXXXXX-XXXXXXXXXX-500" // Default Domain Administrator SID Domain Y
    ]);
DeviceLogonEvents
| where AccountSid startswith "S-1-5-" and AccountSid endswith "-500"
| where IsLocalAdmin == true
| join kind = inner (
    DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId
    )
    on $left.DeviceId == $right.DeviceId
| where AccountSid !in~(DefauldDomainAdministrators) //Comment this line if you also want to see default domain administrator logins
| summarize count()
    by
    DeviceName,
    LogonType,
    AccountDomain,
    AccountName, 
    OSPlatform, 
    MachineGroup
```

## Microsoft Sentinel

```kql
let DefauldDomainAdministrators = dynamic([
    "S-1-5-XXXXXXXXXX-XXXXXXXXX-XXXXXXXXXX-500", //Default Domain Administrator SID Domain X
    "S-1-5-XXXXXXXXXX-XXXXXXXXX-XXXXXXXXXX-500" // Default Domain Administrator SID Domain Y
    ]);
DeviceLogonEvents
| where AccountSid startswith "S-1-5-" and AccountSid endswith "-500"
| where IsLocalAdmin == true
| join kind = inner (
    DeviceInfo
    | summarize arg_max(TimeGenerated, *) by DeviceId
    )
    on $left.DeviceId == $right.DeviceId
| where AccountSid !in~(DefauldDomainAdministrators) //Comment this line if you also want to see default domain administrator logins
| summarize count()
    by
    DeviceName,
    LogonType,
    AccountDomain,
    AccountName, 
    OSPlatform, 
    MachineGroup
```

## References
- [Active Directory Security identifiers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)
- [DeviceLogonEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table)