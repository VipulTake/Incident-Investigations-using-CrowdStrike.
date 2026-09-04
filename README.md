# Incident-Investigations-using-CrowdStrike.

A collection of sanitized CrowdStrike Falcon incident investigation case studies demonstrating endpoint security analysis, threat hunting and incident response.

-----

## Case 07 - Suspicious Scheduled Task Persistence Investigation

-----

### Case Study Note

Customer names, hostnames, usernames, IP addresses, and other identifying information have been replaced with fictional values.

-----

### Objective

Investigate a CrowdStrike Falcon detection involving a suspicious executable and determine whether the activity represents:

- Legitimate scheduled task activity
- Unauthorized task creation
- Malware persistence
- Suspicious file execution
- Recurring malicious activity

The investigation also aims to identify whether the persistence mechanism exists on other endpoints and ensure that the malicious activity is fully remediated.

------
## Incident Summary

Detection Type  -  Suspicious Scheduled Task Persistence

Severity  -  High

Operating System  -  Windows

Affected Host  -  TEST-WIN-08

User  -  test.user

Suspicious File  -  update.exe

File Path  -  C:\Users\test.user\AppData\Roaming\WindowsUpdate\update.exe

Scheduled Task  -  WindowsUpdateCheck

Task Trigger  -  At User Logon

Process  -  schtasks.exe

Detection Engine  -  CrowdStrike Falcon

ATT&CK Technique  -  T1053.005 Scheduled Task/Job: Scheduled Task

Final Classification  -  Confirmed Malicious Persistence

-----
### Detection Description

CrowdStrike Falcon generated a detection involving suspicious activity associated with a scheduled task on `TEST-WIN-08`.

The investigation identified a suspicious executable named `update.exe` located within the user's AppData directory.

Further analysis showed that a scheduled task named `WindowsUpdateCheck` had been created to execute the same file whenever the user logged in.

The task name appeared to imitate a legitimate Windows update-related activity.

Further investigation was performed to determine whether the scheduled task was legitimate or had been created to maintain persistence.

-----
## Initial Alert Information

The Falcon console reported:

```text
Host             : TEST-WIN-08
User             : test.user
Process          : schtasks.exe
Scheduled Task   : WindowsUpdateCheck
Suspicious File  : update.exe
File Path        : C:\Users\test.user\AppData\Roaming\WindowsUpdate\update.exe
Task Trigger     : At User Logon
Severity         : High
```

Reason for Detection:

A suspicious executable located within a user-writable directory was associated with the creation of a scheduled task designed to execute automatically at user logon.

-----
# Investigation Methodology

## Step 1 – Reviewed Detection Details

The following information was reviewed:

- Detection description
- Hostname
- Username
- Process information
- Parent process
- Child process
- Scheduled task name
- Task trigger
- File path
- File hash
- Detection timestamp
- Detection severity
- Related detections

The combination of a suspicious executable and automatic scheduled execution required further investigation.

-----
## Step 2 – Reviewed Process Activity

The process activity was reviewed to determine how the scheduled task was created.

Observed process relationship:

```text
explorer.exe
      ↓
suspicious.exe
      ↓
schtasks.exe
      ↓
WindowsUpdateCheck Created
```

The investigation showed that the suspicious executable was associated with the creation of the scheduled task.

This relationship increased the likelihood that the task had been created to maintain persistence.

-----

## Step 3 – Investigated the Suspicious File

The executable associated with the scheduled task was investigated.

Observed file:

```text
File Name : update.exe

File Path : C:\Users\test.user\AppData\Roaming\WindowsUpdate\update.exe
```

The file location was considered suspicious because:

- The executable was located in a user-writable AppData directory.
- The directory name attempted to appear related to Windows updates.
- Legitimate Windows update executables are not normally executed from this location.
- The file was associated with an unauthorized scheduled task.

The file hash and reputation were reviewed in CrowdStrike Falcon.

The investigation determined that the file was malicious.

-----

## Step 4 – Investigated the Scheduled Task

The scheduled task configuration was reviewed.

Observed task:

```text
Task Name    : WindowsUpdateCheck
Task Trigger : At User Logon
Action       : C:\Users\test.user\AppData\Roaming\WindowsUpdate\update.exe
```

The task was configured to automatically execute the suspicious file whenever `test.user` logged in.

This behavior indicated that the task was being used as a persistence mechanism.

The task name was also reviewed.

Although the name suggested legitimate Windows update activity, the task was not associated with an approved Microsoft Windows component.

-----

## Step 5 – Analyzed the Persistence Mechanism

The scheduled task was designed to ensure that the malicious executable could run again after the user logged in.

Observed persistence flow:

```text
User Logon
      ↓
WindowsUpdateCheck
      ↓
update.exe
      ↓
Malicious Activity
```

The scheduled task allowed the malicious file to maintain access to the endpoint without requiring the user to manually execute the file again.

The persistence mechanism was therefore classified as malicious.

-----

## Step 6 – Reviewed Related Process Activity

The endpoint was reviewed for additional activity associated with `update.exe`.

The investigation checked for:

- Suspicious child processes
- PowerShell execution
- Network connections
- File creation
- Additional scheduled tasks
- Registry modifications
- Related Falcon detections

The activity associated with the file was reviewed to determine whether the malware had created additional persistence mechanisms or performed other malicious actions.

No additional persistence mechanisms were identified during the available investigation period.

-----

## Step 7 – Validated Business Context

The scheduled task was reviewed to determine whether it was part of an approved administrative or software-management process.

The investigation checked:

- Approved scheduled tasks
- Endpoint-management activities
- Software deployment records
- Change records
- Windows update processes

The IT team confirmed that:

- `WindowsUpdateCheck` was not an approved scheduled task.
- `update.exe` was not part of an approved software deployment.
- The file path was not associated with a legitimate Windows update component.
- No approved maintenance activity explained the task creation.

This confirmed that the activity was unauthorized.

-----
## Step 8 – Scoped the Environment

The environment was searched for similar indicators.

The investigation searched for:

- The file hash of `update.exe`
- The file name `update.exe`
- The file path
- The scheduled task name `WindowsUpdateCheck`
- Similar scheduled tasks
- Related Falcon detections

Observed scope:

```text
TEST-WIN-08
      ↓
Malicious Scheduled Task Identified
      ↓
No Additional Affected Hosts Identified
```

No additional endpoints containing the same malicious file or scheduled task were identified during the available investigation period.

-----

## Step 9 – Contained the Endpoint

Because malicious persistence was confirmed, `TEST-WIN-08` was treated as a compromised endpoint.

The following containment action was performed:

- `TEST-WIN-08` was placed into Network Containment.

Network Containment was used to restrict normal network communication while remediation and further investigation were performed.

-----

## Step 10 – Performed Remediation

The malicious persistence mechanism and associated file were removed.

The remediation process included:

- Removing the malicious scheduled task.
- Terminating the malicious process if active.
- Quarantining the malicious executable.
- Reviewing the endpoint for additional persistence.
- Reviewing related Falcon detections.
- Monitoring the endpoint for recurring activity.

The scheduled task was removed to prevent `update.exe` from automatically executing at future user logons.

-----

## Step 11 – Verified Remediation

After remediation, the endpoint was reviewed to confirm that the persistence mechanism had been removed.

The following checks were performed:

- Confirmed that `WindowsUpdateCheck` no longer existed.
- Confirmed that `update.exe` was no longer executing.
- Confirmed that the malicious file was quarantined.
- Checked for additional scheduled tasks.
- Checked for recurring detections.
- Monitored the endpoint for repeated suspicious activity.

No recurring execution of the malicious file was identified after remediation.

-----

# Risk Assessment

Likelihood:

High

Impact:

High

Reason:

The investigation confirmed that a malicious executable had created an unauthorized scheduled task to automatically execute whenever the user logged in.

The persistence mechanism allowed the malware to regain execution after user logon and increased the risk of continued compromise.

The file was also located within a user-writable directory and attempted to appear associated with Windows update activity.

-----
# MITRE ATT&CK Mapping

### T1053.005 - Scheduled Task/Job: Scheduled Task

The malicious activity created a scheduled task named:

```text
WindowsUpdateCheck
```

The task was configured to automatically execute:

```text
C:\Users\test.user\AppData\Roaming\WindowsUpdate\update.exe
```

at user logon.

Scheduled tasks can be used by legitimate software and administrators, but attackers may abuse them to maintain persistence and repeatedly execute malicious programs.

-----

# Persistence Determination

The activity was classified as:

**Confirmed Malicious Persistence**

Evidence supporting the conclusion:

- A suspicious executable was located in a user-writable AppData directory.
- The executable was associated with the creation of a scheduled task.
- The scheduled task was configured to execute automatically at user logon.
- The task name attempted to imitate legitimate Windows update activity.
- The task was not associated with an approved Windows component.
- The activity was not associated with an approved administrative task.
- The malicious file reputation was identified as malicious.
- The scheduled task provided a mechanism for recurring execution.

-----
# Recommended Response

Recommended actions:

- Investigate the scheduled task configuration.
- Identify the executable associated with the task.
- Review the file hash and reputation.
- Determine the process responsible for creating the task.
- Check the task trigger and execution conditions.
- Validate whether the task is approved.
- Search the environment for the same task and file hash.
- Contain the endpoint when malicious activity is confirmed.
- Remove the malicious persistence mechanism.
- Quarantine the malicious file.
- Monitor for recurring activity.

-----

# Recovery

Before releasing the endpoint from Network Containment, the following checks were completed:

- The malicious scheduled task was removed.
- The malicious process was no longer running.
- The malicious file was quarantined.
- No additional persistence mechanisms were identified.
- No new related Falcon detections were observed.
- No additional affected endpoints were identified during environment scoping.

After remediation and monitoring, the endpoint could be released from Network Containment according to the organization's incident-response procedures.

-----

# Analyst Conclusion

CrowdStrike Falcon identified suspicious activity involving the creation of a scheduled task on `TEST-WIN-08`.

The investigation identified a suspicious executable named `update.exe` located at:

```text
C:\Users\test.user\AppData\Roaming\WindowsUpdate\update.exe
```

The file was associated with the creation of a scheduled task named:

```text
WindowsUpdateCheck
```

The task was configured to execute the suspicious file whenever the user logged in.

Process analysis showed that the suspicious executable was associated with the scheduled task creation.

The file location, task configuration and business-context validation indicated that the activity was not part of a legitimate Windows update or approved administrative process.

The scheduled task provided a mechanism for the malicious executable to automatically regain execution after user logon.

The environment was searched for the same file hash, file name and scheduled task.

No additional affected endpoints were identified during the available investigation period.

The endpoint was contained, the malicious scheduled task was removed, the malicious file was quarantined and the endpoint was monitored for recurring activity.

Based on the available evidence, the activity was classified as **Confirmed Malicious Persistence**.

-----

# Lessons Learned

- Persistence mechanisms allow attackers to maintain access after the initial compromise.
- Scheduled tasks should be reviewed when suspicious executables are detected.
- Task names can be misleading and should not be trusted without investigating the associated action.
- User-writable directories can be abused to store malicious executables.
- File paths should be reviewed together with file reputation and process activity.
- Scheduled task triggers provide important context during persistence investigations.
- Process-tree analysis can help identify how a persistence mechanism was created.
- Business-context validation is important before removing scheduled tasks.
- Environment scoping helps determine whether persistence exists on additional endpoints.
- Removing the malicious file alone may not be sufficient if the persistence mechanism remains.
- SOC analysts should verify that both the malicious file and persistence mechanism have been removed.

-----

# Skills Demonstrated

- CrowdStrike Falcon
- SOC Alert Triage
- Persistence Investigation
- Scheduled Task Analysis
- EDR Investigation
- Process Tree Analysis
- File Path Analysis
- File Hash Investigation
- Malware Investigation
- Threat Hunting
- Environment Scoping
- Network Containment
- Incident Response
- Remediation Verification
- MITRE ATT&CK Mapping
- Security Monitoring
- Evidence-Based Incident Classification

-----

