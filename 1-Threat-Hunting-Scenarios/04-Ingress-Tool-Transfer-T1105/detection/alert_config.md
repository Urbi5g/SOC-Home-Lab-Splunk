# Splunk Alert Configuration

## Alert Overview

### Alert Name
Suspicious PowerShell Ingress Tool Transfer

### MITRE ATT&CK Mapping
- **Tactic:** Command and Control
- **Technique:** T1105 – Ingress Tool Transfer

### Severity
High

---

## Alert Objective

The purpose of this alert is to identify suspicious PowerShell activity associated with downloading a remote file into the Windows environment.

The detection focuses on PowerShell commands containing `Invoke-WebRequest`, which was used in the controlled Atomic Red Team simulation.

---

## Detection SPL

```spl
index=main
EventCode=1
Image="*\\powershell.exe"
CommandLine="*Invoke-WebRequest*"
| eval severity="high"
| eval technique="T1105 - Ingress Tool Transfer"
| eval alert_reason="PowerShell downloaded a remote file"
| table _time host User Image CommandLine ParentImage severity technique alert_reason
```

## Trigger Configuration

| Setting | Configuration |
| :--- | :--- |
| Trigger Type | Number of Results |
| Trigger Condition | Greater than 0 |
| Severity | High |
| Tactic | Command and Control |
| Technique | T1105 |
| Detection Source | Windows / Sysmon |
| Detection Method | SPL |

## Alert Metadata

| Field | Value |
| :--- | :--- |
| Alert Name | Suspicious PowerShell Ingress Tool Transfer |
| Severity | High |
| MITRE Tactic | Command and Control |
| MITRE Technique | T1105 |
| Technique Name | Ingress Tool Transfer |
| Platform | Windows |
| Data Source | Sysmon / Windows Event Logs |
| Detection Type | Behavioral |

## Analyst Investigation Procedure

When this alert is triggered, the SOC analyst should perform the following steps:

1. **Review the PowerShell Command**
   Examine the complete `CommandLine` field and determine what command was executed.
2. **Identify the Remote Resource**
   Determine the URL or external resource involved in the transfer.
3. **Identify the Destination File**
   Determine where the downloaded file was written on the endpoint.
4. **Identify the User**
   Review the `User` field and determine which account executed the activity.
5. **Review the Parent Process**
   Examine `ParentImage` to determine how PowerShell was launched.
6. **Correlate Related Events**
   Search for related:
   - Sysmon Event ID 1 — Process Creation
   - Sysmon Event ID 3 — Network Connection
   - Sysmon Event ID 11 — File Creation
   - Windows Security Event ID 4688 — Process Creation
7. **Determine Legitimacy**
   Determine whether the activity was authorized administrative activity or potentially malicious behavior.
8. **Document the Investigation**
   Record the relevant evidence, timestamps, affected host, user, commands, and indicators of compromise.

## False Positive Considerations

PowerShell is a legitimate Windows administration tool and may be used by administrators or applications to download files. Therefore, the alert should not automatically be considered malicious.

The analyst should validate:
- User account
- PowerShell command
- Download URL
- Destination path
- Parent process
- File name
- Whether the activity was authorized

## Recommended SOC Response

If the activity is confirmed to be malicious:
- Isolate the affected endpoint according to the approved lab response procedure.
- Preserve relevant logs and forensic evidence.
- Record identified indicators of compromise.
- Correlate the activity with other security events.
- Escalate the incident for further investigation.
- Document the final findings in the incident report.

## Detection Success Criteria

The alert is considered successful when Splunk detects the simulated PowerShell transfer and provides enough evidence for the analyst to determine:
- Who executed the activity.
- Which host was affected.
- What process executed.
- What command was executed.
- Where the file was downloaded.
- When the activity occurred.
- Whether the activity was authorized or suspicious.

## SOC Workflow

```text
Splunk Alert
     ↓
Review PowerShell Command
     ↓
Identify User & Host
     ↓
Identify Download URL
     ↓
Identify Destination File
     ↓
Correlate Sysmon Events
     ↓
Validate Activity
     ↓
True Positive / False Positive
     ↓
Document & Escalate
```

## Final Classification

- **Detection:** Suspicious PowerShell Ingress Tool Transfer
- **MITRE ATT&CK:** T1105
- **Tactic:** Command and Control
- **Severity:** High
- **Status:** Lab Detection Rule
