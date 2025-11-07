# MDA-User-Removed-From-PrivateTeamsChannel
In the event of an incident response case, one possibility is to disable a user account in Entra ID/Active Directory to stop an ongoing attack. Microsoft Defender XDR Attack Disruption also automatically disables user accounts in the event of an active attack. By design, disabling the user account automatically removes the account from all Microsoft Teams. However, even after the account is re-enabled, it is possible that the user will not see the teams they were previously a member of.

- **Standard Channels**: It can take up to 24–48 hours for the account memberships to be automatically restored for standard channels.
- **Private Channels**: For private channels, the user will not be automatically added to the private channel again. They must make new membership requests for each private channel that they want to rejoin.

This KQL query will list all the private channels from which the user was removed by querying the Cloud App Events table.


## Microsoft Defender XDR
```kql
let affectedUser = "INSERT UPN"; 
let actionFilter = "MemberRemoved"; 
let lookBackTime = 8h;
CloudAppEvents
| where Timestamp > ago(lookBackTime)
| where Application == "Microsoft Teams"
| where ActionType == actionFilter
| extend Workload = tostring(RawEventData.Workload)
| extend TeamsChannelName = tostring(RawEventData.ItemName)
| extend TeamsName = tostring(RawEventData.TeamName)
| mv-expand Members = RawEventData.Members
| extend TeamsMember = tostring(Members.UPN)
| extend ChannelType = RawEventData.ChannelType
| where TeamsMember == affectedUser
| where ChannelType == "Private"
| project
    Timestamp,
    Workload,
    Actor = AccountDisplayName,
    ActionType,
    TeamsName,
    TeamsChannelName,
    TeamsMember,
    ChannelType
| order by Timestamp desc
```

## References
- [You don't see team members after your account is re-enabled](https://learn.microsoft.com/en-us/troubleshoot/microsoftteams/channels/logon-reenabled-user-not-see-previous-joined-teams)
- [Private channels in Microsoft Teams](https://learn.microsoft.com/en-us/MicrosoftTeams/private-channels)
- [Automatic Attack Disruption - Response actions](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption#automated-response-actions)