# Incident-Investigations-using-CrowdStrike.

A collection of sanitized CrowdStrike Falcon incident investigation case studies demonstrating endpoint security analysis, threat hunting and incident response.

-----

## Case 04 - Suspicious PowerShell Execution - False Positive

-----

### Case Study Note

Customer names, hostnames, usernames, IP addresses, and other identifying information have been replaced with fictional values.

-----

### Objective

Investigate a CrowdStrike Falcon detection involving suspicious PowerShell execution and determine whether the activity represents:

- Malicious PowerShell execution
- Defense evasion
- Unauthorized script execution
- Legitimate administrative activity
- False positive

The investigation also aims to determine whether the detection requires remediation or detection tuning.

------
## Incident Summary

Detection Type  -  Suspicious PowerShell Execution

Severity  -  Medium

Operating System  -  Windows

Affected Host  -  TEST-WIN-04

User  -  test.user

Process  -  powershell.exe

Parent Process  -  Task Scheduler

Script  -  WindowsHealthCheck.ps1

Detection Engine  -  CrowdStrike Falcon

ATT&CK Technique  -  T1059.001 PowerShell

Final Classification  -  False Positive / Legitimate Administrative Activity

-----
### Detection Description

CrowdStrike Falcon generated a detection after identifying PowerShell executing with an Execution Policy Bypass.

The activity initially appeared suspicious because attackers commonly use PowerShell and Execution Policy Bypass techniques to execute scripts that may otherwise be restricted.

Further investigation was performed to determine whether the activity was malicious or part of an approved administrative process.

-----
## Initial Alert Information

The Falcon console reported:

```text
Host            : TEST-WIN-04
User            : test.user
Process         : powershell.exe
Parent Process  : Task Scheduler
Script          : C:\ProgramData\Company\WindowsHealthCheck.ps1
Command         : powershell.exe -ExecutionPolicy Bypass -File "C:\ProgramData\Company\WindowsHealthCheck.ps1"
```

Reason for Detection:

PowerShell was executed using `-ExecutionPolicy Bypass`.

-----
# Investigation Methodology

## Step 1 – Reviewed Detection Details

The following information was reviewed:

- Detection description
- Hostname
- Username
- Process
- Parent process
- Command line
- Script path
- Detection timestamp
- Detection severity

The use of PowerShell with Execution Policy Bypass was considered suspicious and required further investigation.

-----
## Step 2 – Reviewed Process Tree

The process tree was reviewed to determine how PowerShell was launched.

Observed process relationship:

```text
Task Scheduler
      ↓
powershell.exe
      ↓
WindowsHealthCheck.ps1
```

The PowerShell process was launched through a scheduled task.

Although scheduled tasks can be abused for persistence, the process relationship alone was not enough to determine that the activity was malicious.

-----

## Step 3 – Analyzed PowerShell Command

Observed command:

```text
powershell.exe -ExecutionPolicy Bypass -File "C:\ProgramData\Company\WindowsHealthCheck.ps1"
```

The use of:

```text
-ExecutionPolicy Bypass
```

was considered suspicious because attackers commonly use it to bypass PowerShell execution restrictions.

The script itself was therefore reviewed to determine its purpose.

-----
## Step 4 – Reviewed Script Activity

The script was found to perform basic Windows health checks.

The script performed activities such as:

- Checking Windows version
- Checking available disk space
- Checking running services
- Checking antivirus status

No malicious payload execution was identified.

The script did not:

- Download suspicious files
- Execute encoded commands
- Attempt credential theft
- Modify security controls
- Create suspicious persistence
- Upload sensitive data

Based on the observed behavior, the script appeared to perform legitimate system-health checks.

-----

## Step 5 – Investigated the Script File

The script file was reviewed for additional indicators.

Checked:

- File path
- File hash
- File creation time
- File modification time
- File ownership
- Presence on other endpoints

The same script and hash were identified on multiple corporate endpoints.

This indicated that the script was part of a standardized endpoint-management activity rather than an isolated malicious file.

-----

## Step 6 – Validated Business Context

The activity was validated with the IT/endpoint-management team.

The team confirmed that:

```text
WindowsHealthCheck.ps1
```

was an approved Windows health-check script deployed through the organization's endpoint-management system.

The scheduled task was also confirmed as part of the approved deployment.

This provided important business context for the detection.

-----
## Step 7 – Reviewed Network Activity

Network activity associated with the script was reviewed.

The investigation looked for:

- External connections
- Suspicious domains
- File downloads
- Data uploads
- Command-and-control communication

No suspicious external communication was identified.

The script only performed the expected health-check activity.

-----

## Step 8 – Checked for Additional Malicious Activity

The endpoint was reviewed for related suspicious activity.

The investigation checked for:

- Suspicious child processes
- Malware detections
- Unauthorized scheduled tasks
- Persistence mechanisms
- Credential access
- Suspicious PowerShell commands
- Data exfiltration

No additional malicious activity was identified.

-----

# Risk Assessment

Likelihood:

Low

Impact:

Low

Reason:

Although the initial behavior contained indicators commonly associated with malicious PowerShell execution, investigation confirmed that the activity was generated by an approved Windows health-check script deployed through the organization's endpoint-management infrastructure.

-----
# MITRE ATT&CK Mapping

### T1059.001 - PowerShell

PowerShell was used to execute the Windows health-check script.

The technique itself is legitimate and can be used by both administrators and attackers.

-----

# False Positive Determination

The detection was classified as:

**False Positive / Legitimate Administrative Activity**

Evidence supporting the conclusion:

- PowerShell execution was associated with an approved scheduled task.
- The script was stored in an expected management directory.
- The script performed legitimate system-health checks.
- The same script was present on multiple managed endpoints.
- The script hash was consistent across endpoints.
- IT confirmed the script was approved.
- No suspicious network communication was identified.
- No malicious child processes were observed.
- No additional malicious activity was identified.

-----
# Recommended Response

Because the activity was confirmed as legitimate, the script was not removed or blocked.

Recommended actions:

- Document the legitimate activity.
- Record the business justification for the script.
- Confirm the script owner and deployment source.
- Monitor the script for unauthorized modifications.
- Tune the detection if repeated alerts are generated.
- If an exclusion is required, create a narrow and specific exception.
- Avoid creating broad exclusions for PowerShell.

-----

# Detection Tuning

The detection should not be disabled globally because PowerShell Execution Policy Bypass can still be a valuable indicator of malicious activity.

If repeated alerts are generated by this approved script, a narrowly scoped exception can be considered using appropriate conditions such as:

- Specific script path
- Known file hash
- Approved parent process
- Approved management system
- Specific endpoint group

The exception should be documented and periodically reviewed.

-----

# Analyst Conclusion

CrowdStrike Falcon detected PowerShell execution using the `-ExecutionPolicy Bypass` parameter on `TEST-WIN-04`.

The activity initially appeared suspicious because Execution Policy Bypass is commonly associated with PowerShell-based attacks.

The investigation showed that PowerShell was launched by an approved scheduled task and executed `WindowsHealthCheck.ps1`.

The script performed legitimate Windows health checks and was deployed consistently across multiple managed endpoints.

The activity was also validated with the IT/endpoint-management team, and no suspicious network communication, malicious child processes, persistence, credential access, or data exfiltration were identified.

Based on the available evidence, the detection was classified as a **False Positive / Legitimate Administrative Activity**.

No endpoint containment or malware remediation was required.

The appropriate response was documentation and, if necessary, narrowly scoped detection tuning rather than blocking the legitimate PowerShell activity.

-----

# Lessons Learned

- A suspicious command does not automatically mean malicious activity.
- PowerShell is widely used by both attackers and administrators.
- `ExecutionPolicy Bypass` should always be investigated rather than automatically classified as malware.
- Process-tree analysis provides important context.
- File hashes can help determine whether a script is consistently deployed across the environment.
- Business-context validation is important when investigating potential false positives.
- Detection tuning should be narrow and specific.
- Broad exclusions can create security gaps.
- SOC analysts should make alert decisions based on multiple pieces of evidence rather than a single indicator.

-----

# Skills Demonstrated

- CrowdStrike Falcon
- SOC Alert Triage
- False Positive Investigation
- EDR Investigation
- PowerShell Analysis
- Process Tree Analysis
- Command-Line Analysis
- File Hash Investigation
- Scheduled Task Investigation
- Threat Hunting
- Business Context Validation
- Detection Tuning
- Exception Management
- MITRE ATT&CK Mapping
- Incident Investigation
- Security Monitoring
- Evidence-Based Alert Classification

-----
# Limitations

Customer names, hostnames, usernames, IP addresses, and other identifying information have been replaced with fictional values.

The case is intended to demonstrate a false-positive investigation and SOC alert-triage workflow and does not contain production customer data.

-----
