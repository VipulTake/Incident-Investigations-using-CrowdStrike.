# Incident-Investigations-using-CrowdStrike.
A collection of sanitized CrowdStrike Falcon incident investigation case studies demonstrating endpoint security analysis, threat hunting and incident response
-----
## Case 01 - Suspicious PowerShell Attempt to Modify Microsoft Defender
-----
### Objective
Investigate a CrowdStrike Falcon detection where PowerShell attempted to modify Microsoft Defender Antivirus exclusions using the Add-MpPreference cmdlet.

Also determine whether the PowerShell execution represents:

- Legitimate administrative activity
- Security testing
- Unauthorized modification of antivirus settings
- Malware attempting to evade endpoint protection
------

### Incident Summary

Detection Type  -  Defense Evasion

Severity  -  High

Operating System  -  Windows

Process  -  powershell.exe

Technique  -  Attempt to modify Microsoft Defender exclusions

Detection Engine  -  CrowdStrike Falcon

ATT&CK Tactic  -  Defense Evasion

--------
### Detection Description
CrowdStrike Falcon generated a detection after identifying a PowerShell command attempting to modify Microsoft Defender Antivirus preferences by adding a Windows system directory to the antivirus exclusion list.

This behavior is frequently observed during malware execution, as attackers attempt to prevent antivirus software from scanning malicious files.

-----

### Initial Alert Information

The Falcon console reported:

Process  :  powershell.exe

Observed Command  :   powershell.exe -Command "Add-MpPreference -ExclusionPath 'C:\Windows\System32'"

Reason for Detection  :   Attempt to modify Microsoft Defender Antivirus exclusions.

------

### Investigation Methodology

#### Step 1 – Reviewed Detection Details

Verified:

- Detection description
- Detection severity
- Timestamp
- Endpoint operating system

----

#### Step 2 – Reviewed Process Tree

Objective:

Determine which application launched PowerShell.

Questions asked while analyzing:

-What was the parent process? -  svchost.exe  - svchost.exe directly spawned powershell.exe.

- Was PowerShell launched by explorer.exe? - Unknown - he CrowdStrike detection does not include the process tree. This should be verified in the Falcon Process Tree.

- Was the PowerShell command suspicious? - Yes - The command attempted to add C:\Windows\System32 to Microsoft Defender's exclusion list, which is a known defense evasion technique.

- Was there evidence of Microsoft Defender configuration modification?  -  Yes  -The command explicitly attempted to modify Defender preferences using Add-MpPreference.

- Was additional malicious activity observed from the provided detection?  -No evidence available - The alert contains only the Defender modification attempt. Further investigation is required to identify persistence, payload execution, or lateral movement.

- Is this incident considered suspicious? - Yes - Modifying antivirus exclusions, especially for the System32 directory, is high-risk behavior and warrants investigation unless it is part of an approved administrative task.

---------
#### Step 3 – Analyze Command Line

Observed command:

powershell.exe -Command "Add-MpPreference -ExclusionPath 'C:\Windows\System32'"

Analysis:

The Add-MpPreference cmdlet modifies Microsoft Defender configuration.

Adding exclusions to Windows system directories is uncommon for normal users and is frequently abused by malware to avoid antivirus scanning.

Risk Level:

High


#### Step 4 – Assess Defense Evasion Activity

PowerShell attempted to execute:

Add-MpPreference

Purpose:

Modify Defender Antivirus configuration.

Potential attacker objective:

Prevent Defender from scanning malicious files stored within excluded directories.


------------

## Step 5 – Determine Business Context

Questions asked:

- Was this command executed by an administrator?
- Was security software being configured?
- Was this part of an approved maintenance activity?
- Was penetration testing scheduled?

If none of the above apply, the detection should be treated as suspicious.


------------

#### Risk Assessment

Likelihood:
High

Impact:
High

Reason:

Attempting to disable or weaken antivirus protection significantly increases the likelihood of successful malware execution.

--------
#### MITRE ATT&CK

T1562.001

Impair Defenses:
Disable or Modify Security Tools

-------

#### Recommended Response

Immediate actions:

- Validate whether the activity was authorized.
- Review the process tree.
- Investigate the parent process.
- Review recent endpoint detections.
- Search for related PowerShell executions.
- Check for persistence mechanisms.
- Isolate the endpoint if malicious activity is confirmed.

---

#### Lessons Learned

PowerShell is a legitimate administration tool but is frequently abused by attackers.

Modification of Microsoft Defender exclusions should always be investigated.

Parent-child process relationships provide valuable context during incident investigations.

Business context is essential before determining whether activity is malicious.

---

#### Analyst Conclusion

The PowerShell command attempted to modify Microsoft Defender exclusions using Add-MpPreference.

This behavior is consistent with Defense Evasion techniques commonly used by malware.

No additional evidence was available within this case study to confirm malicious execution.

Based on the available information, the activity should be treated as suspicious until validated against approved administrative activity.

--------
#### Skills Demonstrated

- CrowdStrike Falcon Investigation
- Endpoint Detection and Response (EDR)
- Incident Investigation
- Threat Hunting
- PowerShell Analysis
- MITRE ATT&CK Mapping
- Defense Evasion Detection
- Security Operations

- ---------

#### Limitations

This case study is based on a sanitized scenario.

No production logs or customer data are included.

Some investigative steps require additional endpoint telemetry that is intentionally omitted.
