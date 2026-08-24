# Incident-Investigations-using-CrowdStrike.
A collection of sanitized CrowdStrike Falcon incident investigation case studies demonstrating endpoint security analysis, threat hunting and incident response

-----

## Case 05 - Endpoint Compromise and Incident Response

-----

### Case Study Note

Customer names, hostnames, usernames, IP addresses, file names, hashes, domains, and other identifying information have been replaced with fictional values.

-----

### Objective

Investigate a CrowdStrike Falcon detection involving a suspicious executable and PowerShell activity and determine whether the activity represents:

- Malicious file execution
- PowerShell execution
- External file download
- Persistence
- Endpoint compromise
- Confirmed malware

The investigation also aims to determine the appropriate containment, remediation, threat hunting and recovery actions.

------
## Incident Summary

Detection Type  -  Suspicious Executable / PowerShell Activity

Severity  -  High

Operating System  -  Windows

Affected Host  -  TEST-WIN-05

User  -  test.user

Process  -  Activator.exe

Parent Process  -  explorer.exe

Child Process  -  powershell.exe

Detection Engine  -  CrowdStrike Falcon

Containment  -  Network Containment

Persistence  -  Registry Run Entry

ATT&CK Techniques  -  T1059.001 PowerShell / T1547.001 Registry Run Keys / T1105 Ingress Tool Transfer

Final Classification  -  Confirmed Malware / Endpoint Compromise

Final Status  -  Resolved

-----
### Detection Description

CrowdStrike Falcon generated multiple detections after a suspicious executable was launched on a Windows endpoint.

The suspicious executable launched PowerShell, which attempted to download another file from an external location.

The combination of malicious file execution, PowerShell activity, external file download and persistence indicated potential endpoint compromise and required further investigation.

-----
## Initial Alert Information

The Falcon console reported:

```text
Host            : TEST-WIN-05
User            : test.user
Process         : Activator.exe
Parent Process  : explorer.exe
Child Process   : powershell.exe
File            : C:\Users\test.user\AppData\Local\Temp\Activator.exe
Activity        : Attempted external file download
Severity        : High
```

Reason for Detection:

A suspicious executable launched PowerShell and attempted to download another file from an external location.

-----
# Investigation Methodology

## Step 1 – Reviewed Detection Details

The following information was reviewed:

- Detection description
- Hostname
- Username
- Process
- Parent process
- Child process
- File path
- File hash
- Detection timestamp
- Detection severity
- Related detections

The combination of the suspicious executable and PowerShell activity indicated that the endpoint required further investigation.

-----

## Step 2 – Reviewed Process Tree

The process tree was reviewed to determine how the suspicious activity started.

Observed process relationship:

```text
explorer.exe
      ↓
Activator.exe
      ↓
powershell.exe
```

The suspicious executable launched PowerShell.

The process relationship and subsequent download attempt increased the likelihood of active malicious activity.

-----

## Step 3 – Analyzed PowerShell Activity

PowerShell was reviewed because it was launched by the suspicious executable.

Observed activity:

```text
Activator.exe
      ↓
powershell.exe
      ↓
External File Download
```

PowerShell itself is a legitimate Windows component.

The activity was considered suspicious because:

- PowerShell was launched by a malicious executable.
- It attempted to retrieve another file.
- The activity occurred shortly after the suspicious executable was launched.

Based on the observed behavior, the activity was treated as potentially malicious.

-----
## Step 4 – Investigated the Malicious File

The suspicious executable was reviewed for additional indicators.

Checked:

- File path
- File hash
- File reputation
- Related detections
- File activity
- Detection history

Example:

```text
File Name    : Activator.exe
SHA256       : f41f69d72e9ccf6f564129a003cff12371be207fabc68b1643a163ccbaa87947
Reputation   : Malicious
```

The file was identified as malicious based on the available CrowdStrike detection and reputation information.

-----
## Step 5 – Contained the Endpoint

Because the endpoint showed signs of potentially active malicious activity, Network Containment was performed using CrowdStrike Falcon.

The purpose of containment was to prevent the endpoint from communicating normally with the network while the investigation continued.

In simple terms:

> "The endpoint was isolated from the network so the suspected malware could not continue communicating externally or potentially affect other systems while the investigation was performed."

-----
## Step 6 – Investigated Persistence

After containment, the endpoint was checked for mechanisms that could allow the malware to execute again after user logon or system restart.

A suspicious Windows Registry Run entry was identified.

Observed persistence:

```text
Registry Run Entry
        ↓
Activator.exe
        ↓
Execution at User Logon
```

The Registry Run entry was associated with the malicious executable.

This indicated that the malware had attempted to establish persistence.

-----
## Step 7 – Scoped the Environment

I searched CrowdStrike Falcon for the same indicators to determine whether other endpoints were affected.

The following indicators were searched:

- File hash
- File name
- Related detection indicators

Example:

```text
SHA256 : f41f69d72e9ccf6f564129a003cff12371be207fabc68b1643a163ccbaa87947
File   : Activator.exe
```

No additional affected endpoints were identified during the investigation.

This indicated that the incident appeared to be isolated to the investigated endpoint.

-----

## Step 8 – Remediated the Endpoint

The following remediation actions were performed:

- Terminated the malicious process.
- Quarantined the malicious executable.
- Removed the malicious Registry Run entry.
- Reviewed the endpoint for additional suspicious activity.

Remediation flow:

```text
Terminate Process
       ↓
Quarantine File
       ↓
Remove Persistence
       ↓
Review Endpoint
```

-----

## Step 9 – Verified Recovery

After remediation, the endpoint was monitored for recurring malicious activity.

The analyst verified:

- Malicious process was no longer running.
- Malicious file was quarantined.
- Registry persistence was removed.
- No additional suspicious processes were identified.
- No new related detections were observed.
- No additional affected endpoints were identified.

After successful validation, the endpoint was released from Network Containment.

-----

# Risk Assessment

Likelihood:

High

Impact:

High

Reason:

The endpoint demonstrated multiple indicators of compromise, including malicious executable execution, PowerShell activity, an attempted external file download and a persistence mechanism.

The endpoint was therefore treated as a confirmed compromise and contained until remediation was completed.

-----
# MITRE ATT&CK Mapping

### T1059.001 - PowerShell

PowerShell was used during the malicious execution chain.

The technique can be used by both administrators and attackers, but its use in this process chain was considered malicious.

-----

### T1547.001 - Registry Run Keys / Startup Folder

A Registry Run entry was identified as a persistence mechanism for the malicious executable.

-----

### T1105 - Ingress Tool Transfer

PowerShell attempted to download another file from an external location.

-----

# Incident Response Actions

The incident followed the following response process:

```text
Detection
    ↓
Investigation
    ↓
Containment
    ↓
Persistence Investigation
    ↓
Environment Scoping
    ↓
Remediation
    ↓
Monitoring
    ↓
Recovery
```

-----

# Final Classification

The detection was classified as:

**Confirmed Malware / Endpoint Compromise**

Evidence supporting the conclusion:

- The suspicious executable was identified as malicious.
- The executable launched PowerShell.
- PowerShell attempted an external file download.
- A Registry Run persistence mechanism was identified.
- The endpoint required Network Containment.
- The malicious process was terminated.
- The malicious file was quarantined.
- Persistence was removed.
- No additional affected endpoints were identified.

-----
# Recommended Response

Because the activity was confirmed as malicious, the endpoint was contained and remediation was performed.

Recommended actions:

- Isolate the affected endpoint.
- Investigate the malicious executable.
- Review the process tree.
- Investigate PowerShell activity.
- Check for persistence mechanisms.
- Search the environment for the same indicators.
- Terminate the malicious process.
- Quarantine the malicious file.
- Remove persistence.
- Monitor the endpoint for recurring activity.
- Release containment only after successful remediation.

-----

# Analyst Conclusion

CrowdStrike Falcon detected suspicious activity on `TEST-WIN-05` involving a malicious executable that launched PowerShell and attempted to download another file from an external location.

The activity initially appeared suspicious because the executable launched PowerShell and attempted external file download activity.

The process-tree investigation showed:

```text
explorer.exe
      ↓
suspicious.exe
      ↓
powershell.exe
```

The suspicious executable was confirmed as malicious.

Because the activity indicated potential active compromise, the endpoint was placed into Network Containment.

Further investigation identified a Registry Run entry associated with the malicious executable, indicating an attempt to establish persistence.

The analyst terminated the malicious process, quarantined the executable and removed the persistence mechanism.

The same file hash, file name and related indicators were searched across the environment. No additional affected endpoints were identified.

After remediation and monitoring confirmed that no further suspicious activity was occurring, the endpoint was released from Network Containment.

Based on the available evidence, the incident was classified as a **Confirmed Malware / Endpoint Compromise** and successfully resolved.

-----

# Lessons Learned

- Suspicious files should be investigated in the context of their behavior.
- PowerShell is a legitimate Windows tool but can be abused by malware.
- Process-tree analysis provides important context during endpoint investigations.
- Active threats should be contained before continuing with remediation.
- Persistence mechanisms should be checked during malware investigations.
- Environment-wide IOC searches help determine whether an incident has spread.
- Malware remediation should include both the malicious file and persistence mechanism.
- Endpoints should be monitored after remediation before being returned to normal operation.
- Recovery decisions should be based on multiple pieces of evidence.

-----

# Skills Demonstrated

- CrowdStrike Falcon
- SOC Alert Triage
- Endpoint Compromise Investigation
- Malware Investigation
- EDR Investigation
- PowerShell Analysis
- Process Tree Analysis
- Command-Line Analysis
- File Hash Investigation
- IOC Investigation
- Network Containment
- Endpoint Remediation
- Persistence Investigation
- Registry Run Key Analysis
- Threat Hunting
- Environment Scoping
- Incident Response
- MITRE ATT&CK Mapping
- Security Monitoring
- Incident Recovery

-----
# Limitations

Customer names, hostnames, usernames, IP addresses, file names, hashes, domains, and other identifying information have been replaced with fictional values.

The case is intended to demonstrate an endpoint compromise investigation and incident-response workflow and does not contain production customer data.

-----
