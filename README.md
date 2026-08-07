# Incident-Investigations-using-CrowdStrike.
A collection of sanitized CrowdStrike Falcon incident investigation case studies demonstrating endpoint security analysis, threat hunting and incident response.

-----

# Case 02 - Suspicious AppleScript Execution Leading to Potential Data Exfiltration

-----
## Objective

Investigate a CrowdStrike Falcon detection involving a suspicious AppleScript application executed from a temporary directory that subsequently launched AppleScript, shell commands, created a ZIP archive, and attempted to upload data to an external domain.

Also determine whether the observed activity represents:

- Legitimate software installation or automation
- Authorized AppleScript execution
- Malware abusing macOS native utilities
- Attempted data collection and exfiltration

------
## Incident Summary

Detection Type  -  Potential Data Exfiltration / Suspicious Process Execution

Severity  -  High

Operating System  -  macOS

Initial Process  -  applet

Technique  -  Execution of AppleScript followed by archive creation and outbound upload

Detection Engine  -  CrowdStrike Falcon

ATT&CK Tactics  -  Execution, Collection, Exfiltration

Total Detections  -  864

------
## Detection Description

CrowdStrike Falcon detected the execution of an AppleScript application (`applet`) from a temporary directory instead of a trusted macOS application location.

The application subsequently launched `osascript`, executed shell commands, created a ZIP archive inside the `/tmp` directory, and attempted to upload the archive to an external Punycode (.ru) domain using the legitimate macOS utility `curl`.

Although the individual utilities are legitimate macOS components, the complete sequence closely resembles malware behavior associated with data staging and exfiltration.

------

## Initial Alert Information

The Falcon console reported:

Host  :  XYZ

Process  :  applet

Process Path  :

```
/private/tmp/f.app/Contents/MacOS/applet
```

Child Processes:

```
applet
    ↓
osascript
    ↓
sh
    ↓
zip archive creation
    ↓
curl
```

Uploaded File:

```
/tmp/12736.zip
```

Destination URL:

```
https://xn--80aaaagbbb3tbcd.xn--p1ai/u
```

Reason for Detection:

Potential malware execution chain resulting in possible data exfiltration.

------
## Investigation Methodology

### Step 1 – Review Detection Details

Verified:

- Detection description
- Detection severity
- Timestamp
- Endpoint operating system
- Detection count
- Executed process path

Observation:

The application executed from:

```
/private/tmp/f.app/
```

instead of the standard macOS application directories.

This execution path is uncommon for legitimate applications and frequently associated with malware.

-----
### Step 2 – Review Process Tree

Observed execution chain:

```
applet
      │
      ▼
osascript
      │
      ▼
sh
      │
      ▼
ZIP Archive Creation
      │
      ▼
curl
```

Questions asked during analysis:

- Was the application launched by the user? - Unknown - need to confirm with user whether it was executed manually or not -  User denied executing it manually.
- Which process launched `applet`? -- initial process observed was 'applet'.
- Was it executed from a trusted location? -- No – The application executed from: ``` /private/tmp/f.app/Contents/MacOS/applet  --  This is a temporary directory and not a standard location for trusted macOS applications, making the execution suspicious.
- Did additional child processes execute? -- Yes – The detection shows that `applet` spawned `osascript`, which subsequently launched `sh`, followed by ZIP archive creation and execution of `curl` to upload the archive.
- Was network communication established?  --  Yes – The `curl` utility attempted to communicate with an external domain:--  https://xn--80aaaagbbb3tbcd.xn--p1ai/u --   indicating outbound network activity.
- Was any archive created? -- Yes – The investigation identified the creation of a ZIP archive:```/tmp/12736.zip ```  This archive appears to have been prepared before the outbound upload attempt.
- Was data uploaded externally? -- Attempted – CrowdStrike detected an attempt to upload `/tmp/12736.zip` to an external Punycode (.ru) domain using `curl`. The available evidence confirms the upload attempt; however, Crowd strike terminated this process successfully.

Observation:

The execution chain demonstrated multiple native macOS utilities executing sequentially, which significantly increased the overall risk.

-----

### Step 3 – Analyze Initial Process

Observed Process:

```
applet
```

Observed Path:

```
/private/tmp/f.app/Contents/MacOS/applet
```

Analysis:

`applet` is the standard executable used by AppleScript applications.

However, legitimate applications are typically installed under:

```
/Applications
/System/Applications
```

Execution from `/private/tmp` is unusual and should be investigated.

Risk Level:

Medium to High

-----

### Step 4 – Analyze AppleScript Execution

Observed Process:

```
osascript
```

Analysis:

`osascript` is a legitimate Apple utility used to execute AppleScript.

CrowdStrike detected execution of an obfuscated AppleScript originating from the temporary directory.

Attackers frequently abuse AppleScript to execute commands while blending into normal macOS activity.

Risk Level:

High

------

### Step 5 – Analyze Shell Execution

Observed Command:

```
sh -c echo $((RANDOM % 3 + 2))
```

Analysis:

The command simply generates a random value between 2 and 4.

Although harmless by itself, malware commonly introduces random delays before executing subsequent actions to evade automated analysis.

Risk Level:

Medium

------

### Step 6 – Review Archive Creation

Observed File:

```
/tmp/12736.zip
```

Analysis:

The creation of temporary ZIP archives is a common technique used by malware to collect and stage files before transmission.

Potential attacker objectives include:

- Compress sensitive documents
- Archive browser data
- Package collected information
- Prepare data for exfiltration

Risk Level:

High

------

### Step 7 – Review Outbound Network Activity

Observed Process:

```
curl
```

Observed Upload:

```
/tmp/12736.zip
```

Destination:

```
https://xn--80aaaagbbb3tbcd.xn--p1ai/u
```

Analysis:

`curl` is a legitimate command-line utility.

However, using `curl` to upload a ZIP archive to an external Punycode (.ru) domain strongly resembles known malware exfiltration techniques.

Risk Level:

Critical

------

## Step 8 – Determine Business Context

Questions asked:

- Did the user intentionally execute the AppleScript application?  - No - User Denied.
- Was any software installation in progress? - No- User did not installed any process at that point of time.
- Was the application downloaded from a trusted source? NO.
- Was data intentionally transferred outside the organization? NO, as User and IT Team  confirmed they were not the one to transfer th data.

If none of the above apply, the activity should be treated as suspicious.

------

## Risk Assessment

Likelihood:

High

Impact:

Critical

Reason:

The observed attack chain demonstrates execution, scripting, archive creation, and outbound file transfer to an external domain.

These behaviors collectively indicate a potential attempt to collect and exfiltrate sensitive information.

------

## MITRE ATT&CK

T1059.002

Command and Scripting Interpreter:
AppleScript

T1059.004

Command and Scripting Interpreter:
Unix Shell

T1560

Archive Collected Data

T1567

Exfiltration Over Web Service

T1105

Ingress Tool Transfer / File Transfer

------

## Recommended Response

Immediate actions to be taken:

- Determine whether the AppleScript execution was authorized. 
- Review the complete process tree in CrowdStrike Falcon. 
- Validate the parent process.
- Inspect the AppleScript content if available.
- Review the ZIP archive contents.
- Investigate outbound network connections.
- Verify whether the upload completed successfully.
- Search for persistence mechanisms.
- Isolate the endpoint if malicious activity is confirmed.
- Remove malicious files.
- Reset affected user credentials if sensitive information may have been exposed.

------

## Lessons Learned

Legitimate macOS utilities such as `applet`, `osascript`, `sh`, and `curl` can be abused by attackers.

Execution from temporary directories should always be validated.

Data staging through ZIP archive creation is a common precursor to data exfiltration.

Reviewing the complete process chain provides significantly more context than analyzing individual detections.

Business context is essential before determining whether activity is malicious.

------

## Analyst Conclusion

CrowdStrike detected a suspicious execution chain beginning with an AppleScript application executed from a temporary directory.

The application subsequently launched AppleScript, executed shell commands, created a ZIP archive, and attempted to upload the archive to an external Punycode domain using `curl`.

Although the individual processes are legitimate macOS components, the complete sequence closely aligns with techniques commonly used for malware execution and data exfiltration.

Based on the available evidence, the activity should be treated as suspicious.

------

## Skills Demonstrated

- CrowdStrike Falcon Investigation
- macOS Threat Analysis
- Endpoint Detection and Response (EDR)
- Incident Investigation
- Threat Hunting
- AppleScript Analysis
- Process Tree Analysis
- Data Exfiltration Investigation
- MITRE ATT&CK Mapping
- Security Operations

- ------

## Limitations

This case study is based on a sanitized investigation.

No production customer data has been included.

The complete process tree, network packet captures, and endpoint forensic artifacts were not available.

Additional investigation would be required to conclusively determine whether data exfiltration was successful or prevented.
