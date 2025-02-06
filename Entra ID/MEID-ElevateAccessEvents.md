# MEID-ElevateAccessEvents
As a Global Administrator, it is possible to access all subscriptions and management groups within a tenant by elevating access. This feature is particularly useful when an Azure subscription becomes orphaned (lacks an owner). Elevated access is highly privileged access. It might be important to audit when access was elevated and who performed the action. Since Januar 2025 this Operation is logged within the Entra Audit Logs.

Elevated Access can be enabled within the Entra Portal :

![](https://raw.githubusercontent.com/lorisAmbrozzo/KQL-Queries/refs/heads/main/Media/MEID-ElevateAccessEvents.png?raw=true)


## Microsoft Sentinel
```kql
AuditLogs
| where Category == "AzureRBACRoleManagementElevateAccess"
//| where OperationName == "User has elevated their access to User Access Administrator for their Azure Resources" //Uncomment if you only want to detect Elevate Access activation
//| where OperationName == "The role assignment of User Access Administrator has been removed from the user" //Uncomment if you only want to detect Elevate Access deactivation
| extend InvolvedIPAddress = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend IPAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| project TimeGenerated, Category, OperationName, InvolvedUser, InvolvedIPAddress
```

## References
- [Elevate Access events are now exportable via Entra Audit Logs | Now in Public Preview](https://www.linkedin.com/pulse/elevate-access-events-now-exportable-via-entra-audit-logs-woaoe/)
- [Elevate access to manage all Azure subscriptions and management groups](https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin?tabs=azure-portal%2Centra-audit-logs)