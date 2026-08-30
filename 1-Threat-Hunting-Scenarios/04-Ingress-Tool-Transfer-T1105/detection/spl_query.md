# Splunk Detection Queries

## MITRE ATT&CK Mapping

- **Tactic:** Command and Control
- **Technique:** T1105 – Ingress Tool Transfer
- **Technique Description:** Adversaries may transfer tools or other files from an external system into a compromised environment.

---

## 1. Primary Detection Query

The following SPL query searches for PowerShell activity associated with downloading or transferring a file:

```spl
index=main
(
    "Invoke-WebRequest"
    OR "tool.exe"
)
| table _time host EventCode Image CommandLine ParentImage User
| sort - _time
```

### Detection Purpose

This query provides an initial view of events related to the simulated file-transfer activity and helps the analyst identify:

- PowerShell execution
- Download-related commands
- Downloaded file names
- Executing user
- Source host
- Parent process
- Event timestamp

## 2. PowerShell Process Creation Detection

```spl
index=main
EventCode=1
Image="*\\powershell.exe"
(
    CommandLine="*Invoke-WebRequest*"
    OR CommandLine="*tool.exe*"
)
| table _time host User Image CommandLine ParentImage ParentProcessId ProcessId
| sort - _time
```

### Detection Purpose

This query focuses specifically on Sysmon Process Creation events and identifies PowerShell processes whose command line contains indicators associated with the simulated transfer.

## 3. Downloaded File Creation Detection

```spl
index=main
EventCode=11
(
    TargetFilename="*tool.exe"
    OR TargetFilename="*\\Users\\Public\\*"
)
| table _time host User Image TargetFilename
| sort - _time
```

### Detection Purpose

This query searches for Sysmon File Creation events that may indicate the downloaded file was successfully written to the endpoint.

## 4. Investigation Fields

During investigation, the analyst should review the following fields:

| Field | Purpose |
| :--- | :--- |
| `_time` | Event timestamp |
| `host` | Affected endpoint |
| `User` | Account responsible for the activity |
| `Image` | Executed process |
| `CommandLine` | Full process command line |
| `ParentImage` | Parent process |
| `ParentProcessId` | Parent process identifier |
| `ProcessId` | Process identifier |
| `TargetFilename` | Created file path |
| `EventCode` | Windows/Sysmon event identifier |

## 5. Expected Detection Evidence

A successful investigation should provide evidence of:

- `powershell.exe` execution.
- Use of `Invoke-WebRequest`.
- A remote file-transfer operation.
- Creation of the transferred file on the endpoint.
- The user account responsible for execution.
- The affected Windows host.
- The exact timestamp of the activity.

## 6. Analyst Correlation

The analyst should correlate the following telemetry:

```text
Process Creation
       ↓
PowerShell Command
       ↓
Network Connection
       ↓
File Creation
```

This correlation provides stronger evidence that the observed PowerShell activity represents an ingress tool transfer rather than an isolated legitimate PowerShell command.

## 7. Detection Outcome

The detection is considered successful when Splunk provides sufficient telemetry to establish the relationship between:

- The executing PowerShell process
- The download command
- The remote resource
- The destination file
- The affected host
- The responsible user
- The associated timestamps
