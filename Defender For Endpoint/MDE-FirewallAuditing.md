# MDE-Firewall Auditing
Windows Defender for Endpoint's firewall auditing feature enables administrators to gain insight into network traffic and evaluate the effectiveness of firewall rules and policies. All allowed connections on the device are monitored by Defender for Endpoint by default. However, blocked connections by the Windows Firewall are not audited by default. To audit these, an additional firewall auditing policy is required.

The following query lists all devices where inbound and outbound blocked firewall events are not audited.

## Microsoft Defender XDR

```kql
DeviceEvents
| where ActionType in ("FirewallOutboundConnectionBlocked", "FirewallInboundConnectionBlocked", "FirewallInboundConnectionToAppBlocked")
| join kind=inner (
    DeviceInfo 
    | summarize arg_max(Timestamp, *) by DeviceId
    | where OnboardingStatus == "Onboarded" 
    )
    on $left.DeviceId == $right.DeviceId
| join kind=rightanti (
    DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId
    | where OnboardingStatus == "Onboarded" 
    )
    on $left.DeviceId == $right.DeviceId
//|  summarize count() by MachineGroup
```
## References
- [Host firewall reporting in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/host-firewall-reporting?view=o365-worldwide)
