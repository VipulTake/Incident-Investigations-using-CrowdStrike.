# Incident-Investigations-using-CrowdStrike.

A collection of sanitized CrowdStrike Falcon incident investigation case studies demonstrating endpoint security analysis, threat hunting and incident response.

-----

## Case 06 - Suspected Lateral Movement Investigation

-----

### Case Study Note

Customer names, hostnames, usernames, IP addresses, and other identifying information have been replaced with fictional values.

-----

### Objective

Investigate suspicious remote activity between two internal Windows endpoints and determine whether the activity represents:

- Legitimate administrative activity
- Unauthorized remote authentication
- Suspicious remote execution
- Account misuse
- Lateral movement

The investigation also aims to identify additional affected endpoints and contain the incident.

------
## Incident Summary

Detection Type  -  Suspicious Remote Activity

Severity  -  High

Operating System  -  Windows

Source Host  -  TEST-WIN-06

Destination Host  -  TEST-WIN-07

User Account  -  test.admin

Process  -  powershell.exe

Remote Activity  -  Remote Authentication and PowerShell Execution

Command  -  net localgroup administrators

Detection Engine  -  CrowdStrike Falcon

ATT&CK Technique  -  T1021 Remote Services

Related ATT&CK Technique  -  T1069.001 Local Groups

Final Classification  -  Confirmed Unauthorized Remote Activity / Lateral Movement

-----
### Detection Description

CrowdStrike Falcon generated an alert involving suspicious remote activity between two internal Windows endpoints.

The activity originated from `TEST-WIN-06` and was associated with the administrative account `test.admin`.

The account remotely authenticated to `TEST-WIN-07`, after which PowerShell executed the following command:

```text
net localgroup administrators
```

The activity was considered suspicious because `test.admin` normally performed administrative activities from an approved management workstation and was not expected to authenticate remotely from `TEST-WIN-06`.

Further investigation was performed to determine whether the activity was legitimate administrative activity or unauthorized lateral movement.

-----
## Initial Alert Information

The Falcon console reported:

```text
Source Host        : TEST-WIN-06
Destination Host   : TEST-WIN-07
User Account       : test.admin
Process            : powershell.exe
Activity           : Remote Authentication
Command            : net localgroup administrators
Severity           : High
```

Reason for Detection:

An administrative account performed unusual remote activity from a workstation that was not an approved administrative management system.

The remote activity was followed by PowerShell execution on the destination endpoint.

-----
# Investigation Methodology

## Step 1 – Reviewed Detection Details

The following information was reviewed:

- Detection description
- Source hostname
- Destination hostname
- User account
- Authentication activity
- Process information
- Command line
- Detection timestamp
- Detection severity
- Related detections

The combination of unusual remote authentication and subsequent PowerShell activity required further investigation.

-----
## Step 2 – Investigated the Source Host

The source endpoint `TEST-WIN-06` was investigated to determine whether it showed indicators of compromise.

The investigation reviewed:

- Recent Falcon detections
- Suspicious processes
- PowerShell activity
- Authentication activity
- Network connections
- Related alerts

The endpoint had previously generated suspicious activity, making the use of an administrative account from the system more concerning.

The analyst therefore treated `TEST-WIN-06` as a potentially compromised source host.

-----
## Step 3 – Reviewed Remote Authentication Activity

The authentication activity between the two endpoints was reviewed.

Observed activity:

```text
TEST-WIN-06
      ↓
test.admin
      ↓
Remote Authentication
      ↓
TEST-WIN-07
```

The investigation confirmed that `test.admin` remotely authenticated to `TEST-WIN-07`.

The authentication was considered unusual because the account normally performed administrative activities from an approved management workstation.

`TEST-WIN-06` was not identified as an approved source system for administrative access.

The unusual source host increased the suspicion that the account may have been misused.

-----
## Step 4 – Investigated the Destination Host

The destination endpoint `TEST-WIN-07` was investigated for suspicious activity occurring after the remote authentication.

Falcon telemetry showed PowerShell activity shortly after the remote session was established.

Observed activity:

```text
Remote Authentication
        ↓
TEST-WIN-07
        ↓
powershell.exe
        ↓
net localgroup administrators
```

The timing of the PowerShell execution was correlated with the remote authentication activity.

This established a connection between the source endpoint, administrative account, and destination endpoint.

-----
## Step 5 – Analyzed the PowerShell Activity

The PowerShell command observed on `TEST-WIN-07` was:

```text
net localgroup administrators
```

The command was used to list the members of the local Administrators group on the destination endpoint.

The activity could be legitimate when performed by an authorized administrator.

However, in this investigation, the command was considered suspicious because:

- The administrative account authenticated from an unusual source host.
- The source host showed suspicious activity.
- The command was executed shortly after remote authentication.
- The destination activity was not associated with an approved administrative task.

The command was therefore treated as potential account and privilege discovery activity following unauthorized remote access.

-----
## Step 6 – Correlated the Activity Between Both Hosts

The timeline of events was reviewed to determine whether the activity represented lateral movement.

Observed sequence:

```text
TEST-WIN-06
Potentially Compromised
        ↓
test.admin Account Used
        ↓
Unusual Remote Authentication
        ↓
TEST-WIN-07
        ↓
PowerShell Execution
        ↓
net localgroup administrators
```

The source host, user account, authentication activity and destination process execution were correlated.

The investigation found that the remote authentication and PowerShell activity occurred within the same suspicious activity timeline.

This provided evidence that the administrative account was used to access a second internal endpoint and perform discovery activity.

-----
## Step 7 – Validated Business Context

The activity was reviewed against the normal behavior of the account.

The investigation checked:

- Normal administrative workstation - NO
- Expected destination systems  - NO
- Approved maintenance activity  -  NO
- Scheduled administrative tasks  - NO
(All above points confirmed by Administrative team.)

The IT team confirmed that:

- `test.admin` normally performed administrative activities from an approved management workstation.
- `TEST-WIN-06` was not an approved administrative management system.
- No approved maintenance activity was scheduled for `TEST-WIN-07`.
- The remote activity could not be associated with a known administrative task.

This provided additional evidence that the activity was unauthorized.

-----
## Step 8 – Scoped the Environment

The environment was searched to determine whether the activity affected additional systems.

The investigation searched for:

- Authentication activity associated with `test.admin`
- Additional remote connections from `TEST-WIN-06`
- Similar PowerShell commands
- Related Falcon detections
- Additional destination hosts

Observed scope:

```text
TEST-WIN-06
        ↓
TEST-WIN-07
        ↓
No Additional Affected Hosts Identified
```

No additional suspicious remote activity associated with the incident was identified during the available investigation period.

-----
## Step 9 – Contained the Affected Endpoints

Because unauthorized remote activity was confirmed, both endpoints were treated as potentially affected.

The following containment actions were performed:

- `TEST-WIN-06` was placed into Network Containment.
- `TEST-WIN-07` was placed into Network Containment.
- Suspicious activity on both endpoints was investigated further.
- The `test.admin` account was secured according to the organization's incident-response procedure.

Network Containment was used to restrict normal network communication while the investigation continued.

-----
## Step 10 – Secured the User Account

Because the administrative account was involved in the suspicious activity, the account was treated as potentially compromised.

The incident-response process included:

- Reviewing recent authentication activity.
- Reviewing systems accessed by the account.
- Reviewing active sessions.
- Securing or resetting credentials according to organizational procedures.
- Requiring re-authentication after account security actions were completed.

The account activity was monitored for further unauthorized authentication attempts.

-----
## Step 11 – Performed Remediation

The affected endpoints were reviewed for additional malicious activity.

The remediation process included:

- Reviewing suspicious processes.
- Terminating confirmed malicious processes where applicable.
- Removing confirmed persistence mechanisms where identified.
- Quarantining confirmed malicious files where applicable.
- Reviewing related detections.
- Monitoring both endpoints for recurring suspicious activity.

The endpoints were not released from containment until the investigation and remediation activities were completed.

-----
# Risk Assessment

Likelihood:

High

Impact:

High

Reason:

The investigation identified unauthorized remote authentication from a potentially compromised workstation to another internal endpoint.

The administrative account was then used to perform discovery activity on the destination system.

The activity demonstrated that an internal endpoint had been used to access another system within the environment, increasing the risk of further compromise.

-----
# MITRE ATT&CK Mapping

### T1021 - Remote Services

Remote authentication was used to access another internal endpoint.

Remote services can be used by legitimate administrators but may also be abused by attackers to move between systems.

-----

### T1069.001 - Permission Groups Discovery: Local Groups

The following command was executed on the destination endpoint:

```text
net localgroup administrators
```

The command was used to identify members of the local Administrators group.

This type of discovery activity can help an attacker identify accounts with elevated privileges.

-----

# Lateral Movement Determination

The incident was classified as:

**Confirmed Unauthorized Remote Activity / Lateral Movement**

Evidence supporting the conclusion:

- The source host `TEST-WIN-06` showed suspicious activity.
- The administrative account `test.admin` authenticated from an unusual source endpoint.
- `TEST-WIN-06` was not an approved administrative management system.
- The account accessed a second internal endpoint, `TEST-WIN-07`.
- PowerShell activity occurred shortly after the remote authentication.
- The command enumerated members of the local Administrators group.
- The activity could not be associated with an approved administrative task.
- The source host, account activity and destination activity were correlated within the same investigation timeline.

-----
# Recommended Response

Recommended actions:

- Immediately investigate the source and destination endpoints.
- Contain affected endpoints when appropriate.
- Review the involved account for possible compromise.
- Secure or reset compromised credentials according to organizational procedures.
- Review active sessions and recent authentication activity.
- Search for additional systems accessed by the account.
- Investigate suspicious remote process execution.
- Review persistence mechanisms on affected endpoints.
- Monitor the environment for recurring activity.

-----

# Recovery

Before releasing the affected endpoints from Network Containment, the following checks were completed:

- No confirmed malicious processes remained active.
- No additional unauthorized remote activity was identified.
- The involved administrative account was secured.
- No new related Falcon detections were observed.
- No additional affected hosts were identified during environment scoping.
- Both endpoints were reviewed for persistence and additional suspicious activity.

After remediation and monitoring, the endpoints could be released from Network Containment according to the organization's incident-response procedures.

-----

# Analyst Conclusion

CrowdStrike Falcon identified suspicious remote activity involving `TEST-WIN-06`, `TEST-WIN-07`, and the administrative account `test.admin`.

The investigation showed that `test.admin` remotely authenticated from `TEST-WIN-06`, which was not an approved administrative management workstation.

Shortly after the remote authentication, PowerShell executed on `TEST-WIN-07`.

The following command was observed:

```text
net localgroup administrators
```

The command enumerated the members of the local Administrators group on the destination endpoint.

The activity was investigated to determine whether it represented legitimate administration or unauthorized remote access.

Business-context validation confirmed that the activity was not associated with an approved maintenance task and that `TEST-WIN-06` was not an expected source system for the administrative account.

The source host, authentication activity and destination process execution were correlated, confirming unauthorized remote activity between two internal endpoints.

Both systems were investigated and contained, the involved account was secured, and the environment was searched for additional affected hosts.

No additional affected endpoints were identified during the available investigation period.

Based on the available evidence, the incident was classified as **Confirmed Unauthorized Remote Activity / Lateral Movement**.

-----

# Lessons Learned

- Remote authentication should always be reviewed in context.
- Administrative accounts should normally be used from approved management systems.
- An unusual source host can be an important indicator of account misuse.
- Remote authentication alone does not automatically indicate lateral movement.
- Process activity on the destination host provides additional investigation context.
- Authentication events should be correlated with endpoint process activity.
- Discovery commands can provide insight into attacker objectives.
- Environment scoping is important when multiple internal systems are involved.
- Administrative accounts require additional investigation when suspicious activity is identified.
- Containment decisions should consider both the source and destination endpoints.
- SOC analysts should use multiple pieces of evidence before classifying activity as malicious.

-----

# Skills Demonstrated

- CrowdStrike Falcon
- SOC Alert Triage
- Lateral Movement Investigation
- Remote Authentication Analysis
- Multi-Host Investigation
- Source and Destination Host Analysis
- PowerShell Investigation
- Command-Line Analysis
- Account Activity Investigation
- Privilege Discovery Analysis
- Threat Hunting
- Environment Scoping
- Network Containment
- Incident Response
- Credential Security
- MITRE ATT&CK Mapping
- Security Monitoring
- Evidence-Based Incident Classification

-----
# Limitations

Customer names, hostnames, usernames, IP addresses, and other identifying information have been replaced with fictional values.

The case is intended to demonstrate a lateral-movement investigation and SOC incident-response workflow and does not contain production customer data.

-----
