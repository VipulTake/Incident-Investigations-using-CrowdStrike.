# Incident-Investigations-using-CrowdStrike.

A collection of sanitized CrowdStrike Falcon incident investigation case studies demonstrating endpoint security analysis, threat hunting and incident response.

-----

## Case 03 - Suspicious External Network Authentication Activity.
-----

### Case Study Note

This case study has been sanitized for educational purposes. Customer names, hostnames, usernames, IP addresses, and other identifying information have been replaced with fictional values.

The case demonstrates a complete SOC investigation workflow based on a CrowdStrike Falcon OverWatch authentication alert.

-----
### Objective

Investigate suspicious external authentication attempts against a Windows server and determine whether the activity represents:

- Automated credential guessing
- Password spraying
- Unauthorized account access
- Compromised credentials
- Lateral movement
- Legitimate remote administration

The investigation also aims to determine whether the attacker successfully authenticated and identify appropriate containment and remediation actions.

------
## Incident Summary

Detection Type  -  Suspicious Authentication Activity

Severity  -  High

Operating System  -  Windows

Affected Host  -  TEST-SRV-01

Local IP  -  10.10.20.15

Remote IP  - 203.0.113.50

Target Account  - svc_backup

Client Hostname  - TEST-CLIENT-01

Logon Type  - 3 (Network Logon)

Detection Source  - CrowdStrike Falcon OverWatch

ATT&CK Tactic  - Credential Access / Initial Access

-----
### Detection Description

CrowdStrike Falcon OverWatch identified multiple failed network authentication attempts against a Windows server.

The authentication attempts originated from an external source and targeted the `svc_backup` account.

The attempts occurred within very short intervals, indicating automated authentication activity rather than normal interactive user activity.

During the investigation, an additional successful authentication event was identified following multiple failed attempts.

This increased the severity of the investigation because it indicated that the targeted credentials may have been compromised.

-----
## Initial Alert Information

The Falcon OverWatch notification reported:

Process/Activity  :  Network Authentication

Affected Host     :  TEST-SRV-01

Local IP          :  10.10.20.15

Remote IP         : 203.0.113.50

Username          :  svc_backup

Client Hostname   :  TEST-CLIENT-01

Logon Type        :  3 - Network Logon

Event             :  UserLogonFailed2

Detection Source  :  Falcon OverWatch

Multiple authentication attempts were observed within seconds of one another.

Example timeline:

21:31:14 - Failed authentication.

21:31:16 - Failed authentication.

21:31:17 - Failed authentication.

21:31:19 - Failed authentication.

21:31:20 - Failed authentication.

21:31:22 - Failed authentication.

21:31:25 - Failed authentication.

21:31:38 - Failed authentication.

21:31:40 - Failed authentication.

21:31:56 - Failed authentication.


The short intervals between attempts indicated that the activity was likely automated.

-----
# Investigation Methodology

## Step 1 – Reviewed OverWatch Detection

The initial OverWatch notification was reviewed to determine:

- Affected host
- Source IP
- Target account
- Authentication type
- Number of attempts
- Timestamp
- Source hostname
- Whether the source was internal or external

The source system and account were not recognized as authorized internal resources.

The activity was therefore treated as suspicious.

-----
## Step 2 – Analyzed Authentication Events

Falcon telemetry was reviewed for authentication events involving:

TEST-SRV-01

svc_backup

203.0.113.50

TEST-CLIENT-01

The investigation initially identified multiple:

UserLogonFailed2

events.

The repeated failures occurred within very short intervals, which is inconsistent with normal manual authentication.

### Analyst Assessment

The activity was consistent with an automated authentication attempt.

Possible attacker objectives included:

- Password guessing
- Password spraying
- Testing previously obtained credentials
- Attempting unauthorized access to a network resource

-----
## Step 3 – Investigated Logon Type

The authentication events showed:

Logon Type: 3

Logon Type 3 represents a Network Logon.

This indicates that the authentication was performed over the network rather than through a normal local interactive logon.

This increased the relevance of investigating:

- SMB access
- Network resource access
- Remote service authentication
- Credential reuse
- Lateral movement

-----

## Step 4 – Investigated Successful Authentication

Further telemetry review identified a successful authentication involving the same account following the failed attempts.

Timeline:

Multiple failed authentication attempts
              ↓
      Successful authentication
              ↓
       svc_backup account
              ↓
       TEST-SRV-01

The successful authentication indicated that the credentials may have been successfully obtained or guessed.

The account was therefore treated as potentially compromised.

-----
## Step 5 – Reviewed Process Activity

Following the successful authentication, Falcon telemetry was reviewed for suspicious process execution.

The investigation identified PowerShell activity occurring shortly after the successful authentication.

Observed activity:

powershell.exe
        ↓
System information discovery
        ↓
Network configuration discovery
        ↓
User/account enumeration

The commands were reviewed to determine whether they represented legitimate administrative activity.

No approved maintenance activity was associated with the account during the investigation timeframe.

The PowerShell activity was therefore considered suspicious.
-----

## Step 6 – Investigated Potential Lateral Movement

Because the compromised account was a service account, additional systems were searched for activity involving:

svc_backup

203.0.113.50

TEST-CLIENT-01

The investigation focused on:

- Authentication attempts against other systems
- Network logons
- SMB connections
- Remote service activity
- PowerShell execution
- Remote administration activity

No additional confirmed compromised systems were identified during the investigation.

-----
## Step 7 – Investigated Persistence

The affected endpoint was reviewed for common persistence mechanisms.

The investigation included:

- Scheduled Tasks
- Windows Services
- Startup locations
- Registry Run keys
- PowerShell profiles
- Suspicious executables
- Recently created files

No confirmed malicious persistence mechanism was identified.

-----

## Step 8 – Determine Attack Objective

Based on the observed sequence:

External Source
        ↓  
Multiple Failed Logons
       ↓
Successful Authentication
        ↓
Network Logon
      ↓
PowerShell Execution
      ↓
System Discovery
      ↓
Account Investigation

The most likely objective was unauthorized access followed by reconnaissance of the compromised system.

The activity was consistent with an account compromise scenario.

-----
# Step 9 – Business Context Validation

The following questions were validated with the infrastructure/security team:

- Was `svc_backup` expected to authenticate from an external source? - NO
- Was remote administration scheduled? NO
- Was the source IP authorized? NO
- Was any maintenance activity taking place? NO
- Was PowerShell execution expected Internally? NO 
- Was the service account supposed to access the affected server remotely? NO

The activity could not be associated with an approved administrative activity.

-----
# Risk Assessment

Likelihood:

High

Impact:

High

Reason:

The combination of repeated external authentication attempts, a subsequent successful authentication, and suspicious PowerShell execution indicates a potential compromised account and unauthorized access.

-----
# MITRE ATT&CK Mapping

### T1110 - Brute Force

Repeated authentication attempts may indicate credential guessing or password spraying activity.

### T1078 - Valid Accounts

The successful authentication using the service account may indicate the use of valid or compromised credentials.

### T1021 - Remote Services

Network-based authentication can be associated with remote access and lateral movement techniques.

### T1059.001 - PowerShell

PowerShell was observed following the successful authentication and was used for system discovery activity.

### T1087 - Account Discovery

Account enumeration activity was observed during the post-authentication investigation.

### T1082 - System Information Discovery

The activity included discovery of information about the affected system.

-----
# Recommended Response

Immediate actions taken:

- Network-contained `TEST-SRV-01` using CrowdStrike Falcon.
- Blocked the malicious source IP `203.0.113.50` at the perimeter firewall.
- Disabled the potentially compromised `svc_backup` account.
- Reset the account credentials.
- Reviewed recent authentication activity involving the account.
- Searched for additional activity involving the compromised account.
- Reviewed PowerShell execution on the affected endpoint.
- Performed a full endpoint security scan.
- Rebooted the system after remediation.
- Continued monitoring the endpoint for recurring suspicious activity.

-----
# Threat Hunting Performed

Environment-wide searches were performed for:

203.0.113.50

svc_backup

TEST-CLIENT-01

The investigation searched for:

- Failed authentication attempts
- Successful authentication
- PowerShell execution
- Remote service activity
- Suspicious process execution
- Additional targeted hosts
- Network connections
- Persistence indicators

No additional confirmed compromised endpoints were identified.

-----
# Recovery

After remediation:

- The compromised account credentials were rotated.
- Unauthorized access was removed.
- The affected endpoint was validated.
- Security controls were confirmed to be operational.
- Falcon sensor health was verified.
- The endpoint was monitored for recurring detections.
- Network connectivity was restored after security validation.

-----
# Preventive Measures

To reduce the likelihood of similar incidents:

- Restrict external access to internal Windows servers.
- Disable unnecessary externally exposed authentication services.
- Implement account lockout and authentication protection policies.
- Use strong and unique service-account credentials.
- Prefer managed service accounts where applicable.
- Restrict service accounts from interactive logon.
- Apply least-privilege access.
- Monitor privileged and service-account authentication.
- Implement network segmentation.
- Monitor abnormal authentication patterns.
- Review externally exposed services regularly.
- Enable centralized authentication logging and monitoring.

-----
# Lessons Learned

- Multiple failed authentication attempts within a short period can indicate automated attack activity.
- A successful authentication following repeated failures significantly increases the risk of account compromise.
- Logon Type 3 should be investigated in the context of network-based authentication.
- Service accounts require additional protection because their credentials may provide access to multiple systems.
- Successful authentication does not automatically mean compromise; post-authentication activity must also be investigated.
- PowerShell activity after suspicious authentication should be reviewed carefully.
- Threat hunting across the environment is important to determine whether the attacker targeted additional systems.
- Containment should be combined with credential remediation and IOC hunting.
- Authentication monitoring can provide early indicators of attempted account compromise.

-----

# Analyst Conclusion

CrowdStrike Falcon OverWatch identified multiple external network authentication attempts against `TEST-SRV-01` targeting the `svc_backup` account.

The attempts occurred within short intervals and were inconsistent with normal user activity.

Further investigation identified a successful authentication following the failed attempts, followed by suspicious PowerShell-based discovery activity.

The account was therefore treated as potentially compromised.

The affected endpoint was contained, the source IP was blocked, the account credentials were reset, and environment-wide threat hunting was performed to identify additional activity.

No additional confirmed compromised systems were identified during the investigation.

The incident demonstrates the importance of correlating authentication activity with endpoint telemetry rather than treating individual failed-login events in isolation.

-----
# Skills Demonstrated

- CrowdStrike Falcon
- Falcon OverWatch Investigation
- Falcon LogScale
- EDR Investigation
- Security Operations
- Authentication Analysis
- Windows Logon Analysis
- Logon Type Analysis
- Threat Hunting
- Incident Response
- Account Compromise Investigation
- PowerShell Analysis
- IOC Investigation
- Lateral Movement Analysis
- Network Containment
- Firewall Remediation
- Credential Remediation
- MITRE ATT&CK Mapping
- Root Cause Analysis
- Endpoint Security
- Security Monitoring

-----

# Limitations

This case study has been sanitized for educational purposes.

Customer names, hostnames, usernames, IP addresses, and other identifying information have been replaced with fictional values.

The case is intended to demonstrate an end-to-end SOC investigation workflow and does not contain production customer data.

-----
