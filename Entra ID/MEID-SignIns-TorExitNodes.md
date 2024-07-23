# MEID-SignIns-TorExitNodes
This KQL query retrieves all Tor exit nodes from the official tor project website. Tor exit nodes are the gateways of the communication flow between the Tor client and the destination server (after leaving the Tor network). Any request coming from one of these IP addresses indicates that the request came from the Tor network.

This query can be used to check how many login attempts are coming from Tor exit nodes to the Entra ID tenant and whether further login attempts from Tor exit nodes should be blocked (e.g. conditional access) or not.

## Microsoft Sentinel
```kql
let TorExitNodes = externaldata (IPAddress: string) ['https://check.torproject.org/torbulkexitlist'] with (format=txt);
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(90d)
//| where ResultType == 0 //See all successfull Logons
| where IPAddress has_any (TorExitNodes)
| project
    TimeGenerated,
    Category,
    ResultType,
    ResultDescription,
    Identity,
    AppDisplayName,
    IPAddress,
    AuthenticationRequirement,
    RiskLevelDuringSignIn
```

## References
- [Offical Tor Exit List Service from the Tor Project](https://check.torproject.org/torbulkexitlist)