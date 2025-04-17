# MEID-AttackDisruption-Actions
The Enterprise Application **Microsoft Defender for Identity (formerly known as Radius Aad Syncer)** with the App ID _60ca1954-583c-4d1f-86de-39d835f3e452_ is responsible for executing Microsoft Defender XDR Attack Disruption actions in Entra ID. The  KQL query lists each triggered Defender XDR Attack Disruption action in Entra ID performed by this service principal.

To use the query, insert the **Service Principal Object ID** from the Application with the App ID _60ca1954-583c-4d1f-86de-39d835f3e452_.

## Microsoft Sentinel
```kql
AuditLogs
| where TimeGenerated > ago(180d)
| mv-expand InitiatedBy, TargetResources
| mv-expand modifiedUserProperty = TargetResources.modifiedProperties
| extend InitiatedApp = InitiatedBy.app
| where InitiatedApp.servicePrincipalId == "INSERT OBJECT ID" // Filter for Microsoft Defender for Identity (formerly Radius Aad Syncer) Service Principal 
| extend
    ModifiedProperty = modifiedUserProperty.displayName,
    OldValue = modifiedUserProperty.oldValue,
    NewValue = modifiedUserProperty.newValue
| project
    TimeGenerated,
    InitiatedApp.displayName,
    OperationName,
    TargetResources.userPrincipalName,
    ModifiedProperty,
    OldValue,
    NewValue,
    Result
```

## References
- [First-Party Microsoft Enterprise Applications](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in)
- [Microsoft Defender XDR Attack disruption automated response actions](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption#automated-response-actions)