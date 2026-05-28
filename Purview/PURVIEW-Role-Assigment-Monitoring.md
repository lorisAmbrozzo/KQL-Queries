# PURVIEW-Role-Assigment-Monitoring
Permissions managed in the Microsoft Purview portal only grant users access to the compliance and governance features available within the portal itself. As some Purview roles have high permissions to read sensitive data, they are quite privileged. They are not managed via Entra role assignments, but instead are assigned directly within the Purview blade. This means that changes to Purview role assignments are not tracked by Entra ID audit logs. Therefore, Purview roles should also be monitored. The two queries below monitor all Purview role changes (add or remove role assignments).

There are two ways to modify role assignments for Purview roles:
- Directly via the Purview portal. 
    - Changes to role assignments in the Purview portal are made via the Purview APIs (purview.microsoft.com) in the background. These APIs reflect an internal Microsoft API that is not publicly accessible. 
- Via the Security & Compliance PowerShell module, which allows you to add them     programmatically.
    - The purview.microsoft.com API is not publicly accessible, so automated role assignment changes must be made via the Security & Compliance PowerShell module. 

This is why two types of query are required to detect role changes.

## Monitoring role assignments changes via GUI 
```kql
let lookbackAccounts = 30d;
let lookbackEvents = 2h;
let Accounts =
    materialize(
        IdentityAccountInfo
        | where Timestamp > ago(lookbackAccounts)
        | summarize arg_max(Timestamp, AccountUpn) by SourceProviderAccountId
        | project SourceProviderAccountId, AccountUpn
    );
CloudAppEvents
| where Timestamp > ago(lookbackEvents)
| where ActionType in ("GrantPermissionsAsync", "DeletePermissionAsync")
| extend Raw = todynamic(RawEventData)
| extend
    PreExecutionMessage = tostring(Raw.PreExecutionMessage),
    PostExecutionMessage = tostring(Raw.PostExecutionMessage),
    ActorId = tostring(Raw.ActingCallerId)
| extend Message = coalesce(PostExecutionMessage, PreExecutionMessage)
| extend PermissionJson = extract(@"(\{.*\})", 1, Message)
| where isnotempty(PermissionJson)
| extend p = todynamic(PermissionJson)
| extend
    Target = tostring(p.MemberDetail.MemberName),
    PurviewRoleGroupName = tostring(p.RoleGroupDetail.RoleGroupName)
| lookup kind=leftouter Accounts on $left.ActorId == $right.SourceProviderAccountId
| summarize arg_max(Timestamp, *) by ActionType, ActorId, Target, PurviewRoleGroupName
| project
    Timestamp,
    ActorId,
    Actor = coalesce(AccountUpn, ActorId),
    Target,
    ActionType,
    PurviewRoleGroupName
| order by Timestamp desc
```

## Monitoring role assigment changes via GUI (eDiscovery Adminsitrator Role)

```kql
CloudAppEvents
| where Timestamp > ago(2h)
| where ActionType == "CaseAdminUpdated"
| extend Raw = todynamic(RawEventData)
| extend Actor = tostring(Raw.UserId)
| extend EP = parse_json(tostring(Raw.ExtendedProperties))
| mv-apply Item = EP on (
    summarize Props = make_bag(pack(tostring(Item.Name), tostring(Item.Value)))
)
| extend
    CaseAdminsSmtp = tostring(Props.CaseAdminsSmtp),
    CaseAdminsGuid = tostring(Props.CaseAdminsGuid)
| project Timestamp, ActionType, Actor, CaseAdminsSmtp, CaseAdminsGuid
| order by Timestamp desc
```


## Monitoring role assignments via Microsoft Purview (Security & Compliance) PowerShell endpoint

```kql
let lookbackAccounts = 30d;
let lookbackEvents = 2h;
let Accounts =
    materialize(
    IdentityAccountInfo
    | where Timestamp > ago(lookbackAccounts)
    | where isnotempty(SourceProviderAccountId)
    | summarize arg_max(Timestamp, AccountUpn) by SourceProviderAccountId
    | project SourceProviderAccountId, AccountUpn
    );
CloudAppEvents
| where Timestamp > ago(lookbackEvents)
| where ActionType in ("Add-RoleGroupMember", "Remove-RoleGroupMember")
| extend AO = todynamic(ActivityObjects)
| mv-expand AO
| extend obj = todynamic(AO)
| summarize
    ParameterRaw = anyif(tostring(obj.Name), tostring(obj.Role) == "Parameter"),
    ActorId = anyif(tostring(obj.Id), tostring(obj.Role) == "Actor"),
    ActorName = anyif(tostring(obj.Name), tostring(obj.Role) == "Actor"),
    ApplicationId = anyif(tostring(obj.ApplicationId), tostring(obj.Role) == "Actor"),
    ApplicationInstance = anyif(tostring(obj.ApplicationInstance), tostring(obj.Role) == "Actor")
    by ReportId, Timestamp, ActionType
| extend MemberPart = tostring(split(ParameterRaw, " -Identity ")[0])
| extend Target = replace_regex(MemberPart, @"(?i)^-member\s+", "")
| extend Target = replace_regex(Target, @"(?i)\s+-confirm\s+.*$", "")
| extend Target = trim(@" """, Target)
| extend PurviewRole = extract(@"(?i)-identity\s+(\S+)", 1, ParameterRaw)
| where isnotempty(Target) and isnotempty(PurviewRole)
| lookup kind=leftouter Accounts on $left.ActorId == $right.SourceProviderAccountId
| extend Actor = coalesce(AccountUpn, ActorName, ActorId)
| extend Operation = iff(ActionType == "Add-RoleGroupMember", "Added", "Removed")
| project
    Timestamp,
    ActionType,
    Actor,
    Target,
    PurviewRole
| order by Timestamp desc
```` 

# References
- [Permissions in the Microsoft Purview portal](https://learn.microsoft.com/en-us/purview/purview-permissions)
- [Connect to Security & Compliance PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps#updates-for-version-300-the-exo-v3-module)
- [Add-RoleGroupMember](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/add-rolegroupmember?view=exchange-ps)
- [Remove-RoleGroupMember](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/remove-rolegroupmember?view=exchange-ps)
