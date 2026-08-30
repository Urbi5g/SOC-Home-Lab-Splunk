# Incident Report — Ingress Tool Transfer (T1105)

## 1. Incident Information

| Field | Details |
|---|---|
| **Case ID** | SOC-2026-004 |
| **Incident Type** | Ingress Tool Transfer |
| **MITRE ATT&CK** | T1105 — Ingress Tool Transfer |
| **Environment** | SOC Home Lab |
| **SIEM** | Splunk Enterprise |
| **Endpoint Telemetry** | Sysmon |
| **Affected Host** | `DESKTOP-HCNDFJJ` |
| **User** | `DESKTOP-HCNDFJJ\حذيفه أبو الرجال` |
| **Primary Process** | `powershell.exe` |
| **Destination Port** | TCP/443 |
| **Detection Status** | Successfully Detected |
| **Alert** | `SOC - Suspicious PowerShell File Download T1105` |
| **Severity** | Medium |
| **Impact** | Controlled lab activity; no production impact |

---

## 2. Executive Summary

A controlled **Ingress Tool Transfer (T1105)** activity was simulated on the Windows endpoint `DESKTOP-HCNDFJJ` using Atomic Red Team.

The test executed a PowerShell command that used `.NET WebClient` and `DownloadString()` to retrieve content from a GitHub-hosted raw resource. The activity generated multiple Sysmon events that were ingested into Splunk and correlated during the investigation.

The observed sequence included:

1. PowerShell process creation.
2. DNS resolution for `raw.githubusercontent.com`.
3. HTTPS communication over TCP port `443`.
4. Creation of a local `LICENSE.txt` file.
5. Splunk detection and alert generation.
6. Dashboard-based investigation and validation.

The activity was successfully detected and investigated in the controlled SOC environment. No production system or external organization was targeted.

---

# 3. Objective

The purpose of this exercise was to validate an end-to-end SOC detection workflow for **T1105 — Ingress Tool Transfer**.

The exercise was designed to answer four practical questions:

- Can endpoint telemetry capture the PowerShell activity?
- Can Splunk correlate the related process, DNS, network, and file events?
- Can the activity be converted into an automated alert?
- Can the analyst document the complete evidence chain?

The exercise therefore focused not only on generating an event, but on demonstrating the complete path from **attack simulation to detection and investigation**.

---

# 4. Lab Environment

| Component | Configuration |
|---|---|
| **SIEM** | Splunk Enterprise |
| **Endpoint** | Windows 10 |
| **Endpoint Hostname** | `DESKTOP-HCNDFJJ` |
| **Telemetry** | Sysmon |
| **Splunk Index** | `main` |
| **Sourcetype** | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| **Attack Framework** | Atomic Red Team |
| **Technique Tested** | T1105 |
| **Primary Process** | `powershell.exe` |

The endpoint was monitored by Sysmon, with the resulting Windows event telemetry forwarded into Splunk for analysis.

---

# 5. Attack Simulation

The activity was generated using Atomic Red Team for the T1105 technique.

The test executed PowerShell with the following behavior:

```powershell
(New-Object Net.WebClient).DownloadString(
'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/4042cb3433bce024e304500dcfe3c5590571573a/LICENSE.txt'
) | Out-File LICENSE.txt; Invoke-Item LICENSE.txt
```

The command retrieved content from a GitHub raw-content endpoint, wrote the result to `LICENSE.txt`, and then opened the file.

The test completed successfully with an exit code of `0`.

### Attack Evidence

![PowerShell Attack Execution](./evidence/screenshots/powershell_attack.png)

**Figure 1 — Atomic Red Team T1105 execution**

The screenshot provides evidence of the controlled test execution and confirms that the Atomic Red Team test completed successfully.

---

# 6. Initial Process Creation

The first significant endpoint event was **Sysmon Event ID 1 — Process Create**.

The event recorded:

| Field | Observed Value |
|---|---|
| **Event ID** | `1` |
| **Image** | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| **Parent Image** | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| **Process ID** | `16244` |
| **Parent Process ID** | `13468` |
| **Process GUID** | `{9f3b70de-5faa-6a93-99bd-000000006b01}` |
| **User** | `DESKTOP-HCNDFJJ\حذيفه أبو الرجال` |

The most important field for the investigation was the **CommandLine**. It showed the use of `Net.WebClient` and `DownloadString()` to retrieve the external resource.

This established the relationship between the PowerShell process and the later network and file-system events.

---

# 7. DNS Resolution

The same PowerShell process generated **Sysmon Event ID 22 — DNS Query**.

Observed values included:

| Field | Value |
|---|---|
| **Event ID** | `22` |
| **Process** | `powershell.exe` |
| **Process ID** | `16244` |
| **Process GUID** | `{9f3b70de-5faa-6a93-99bd-000000006b01}` |
| **Query Name** | `raw.githubusercontent.com` |
| **Query Status** | `0` |

The DNS event is important because it provides endpoint evidence that the PowerShell process resolved the domain used in the download operation.

The recorded results included:

```text
185.199.110.133
185.199.111.133
185.199.108.133
185.199.109.133
```

### Detection Evidence

![Detection Events](./evidence/screenshots/detection_events.png)

**Figure 2 — Correlated Sysmon detection events**

---

# 8. Network Connection

Following the DNS resolution, **Sysmon Event ID 3 — Network Connection** recorded an outbound TCP connection from the same PowerShell process.

Observed values:

| Field | Value |
|---|---|
| **Event ID** | `3` |
| **Image** | `powershell.exe` |
| **Process ID** | `16244` |
| **Process GUID** | `{9f3b70de-5faa-6a93-99bd-000000006b01}` |
| **Destination IP** | `185.199.110.133` |
| **Destination Port** | `443` |
| **Source IP** | `192.168.1.138` |
| **Protocol** | `TCP` |

The matching **Process GUID** is particularly useful because it ties the network connection back to the PowerShell process observed in Event ID 1.

The resulting relationship was:

```text
PowerShell Process
      │
      ├── DNS Query
      │     └── raw.githubusercontent.com
      │
      └── Network Connection
            └── 185.199.110.133:443
```

This correlation provides stronger evidence than looking at the network event in isolation.

---

# 9. File Creation

The next relevant event was **Sysmon Event ID 11 — FileCreate**.

During the investigation, the resulting file was identified as:

```text
C:\Users\حذيفه أبو الرجال\Downloads\LICENSE.txt
```

The event showed that the downloaded content resulted in a local file-system change.

### File Evidence

![File Saved](./evidence/screenshots/file_saved.png)

**Figure 3 — File creation evidence**

The file creation event completed the main endpoint evidence chain:

```text
External Resource
      ↓
PowerShell Download
      ↓
Local File Creation
```

---

# 10. Additional Process Activity

After the file was created, related process activity was observed.

The investigation identified `notepad.exe` opening:

```text
C:\Users\حذيفه أبو الرجال\Downloads\LICENSE.txt
```

This was visible through a subsequent process creation event.

This activity was not treated as the primary malicious behavior. Instead, it was useful as supporting evidence showing what happened to the file after it was created.

The distinction is important: **file creation demonstrated the transfer result, while opening the file was subsequent user/application activity.**

---

# 11. Detection Logic

The detection was implemented in Splunk using Sysmon telemetry.

The detection focused on suspicious PowerShell download behavior and associated HTTPS network activity.

The investigation used fields including:

- `EventCode`
- `Image`
- `ParentImage`
- `CommandLine`
- `ProcessGuid`
- `ProcessId`
- `TargetFilename`
- `DestinationIp`
- `DestinationPort`
- `QueryName`
- `User`

The detection logic was designed to provide a practical SOC signal rather than rely on a single event.

### Detection Query

📄 **[SPL Detection Query](./detection/spl_query.md)**

---

# 12. Alert Configuration

A scheduled Splunk alert was created using the detection logic.

**Alert Name:**

```text
SOC - Suspicious PowerShell File Download T1105
```

**Severity:**

```text
Medium
```

The alert successfully triggered during the controlled test.

![Splunk Alert](./evidence/screenshots/splunk_alert.png)

**Figure 4 — Triggered Splunk alert**

This confirms that the detection was operationalized as an alert and did not remain only as a manual investigation query.

### Alert Configuration

📄 **[Alert Configuration](./detection/alert_config.md)**

---

# 13. Dashboard Investigation

A dedicated Splunk dashboard was created to give the analyst a centralized view of the activity.

The dashboard included visibility into:

- Attack timeline
- PowerShell download activity
- User
- Host
- Process ID
- Process GUID
- Command line
- Parent process
- Destination IP
- Destination port
- Related events

![PowerShell Dashboard](./evidence/screenshots/powershell_dashboard.png)

**Figure 5 — PowerShell Download & Execution Detection Dashboard**

A second dashboard view was also captured:

![PowerShell Dashboard — View 2](./evidence/screenshots/powershell_dashboard2.png)

**Figure 6 — Additional dashboard investigation view**

The dashboard was used to move from the alert to the underlying events and validate the process relationships.

---

# 14. Investigation Timeline

The key events occurred within a short time window.

| Time | Event | Significance |
|---|---|---|
| **01:39:38.646** | Sysmon Event ID 1 | PowerShell process created with `DownloadString()` command |
| **01:39:39.966** | Sysmon Event ID 11 | PowerShell-related temporary script file created |
| **01:39:42.253** | Sysmon Event ID 22 | DNS query for `raw.githubusercontent.com` |
| **01:39:42.450** | Sysmon Event ID 3 | PowerShell connected to `185.199.110.133:443` |
| **01:39:43.408** | Sysmon Event ID 1 | `notepad.exe` opened the resulting `LICENSE.txt` |
| **01:39:43.409** | Windows/Sysmon-related process telemetry | Supporting process creation evidence |

The timeline shows that the process, DNS, network, and resulting file activity were closely related in time and shared the same PowerShell process context.

---

# 15. Evidence Correlation

The investigation did not rely on a single event.

Instead, the evidence was correlated using **ProcessGuid**, **ProcessId**, timestamps, and the observed values.

```text
Event ID 1
PowerShell Process Creation
        │
        │ ProcessGuid:
        │ {9f3b70de-5faa-6a93-99bd-000000006b01}
        ↓
Event ID 22
DNS Query
raw.githubusercontent.com
        │
        ↓
Event ID 3
Network Connection
185.199.110.133:443
        │
        ↓
FileCreate Evidence
LICENSE.txt
        │
        ↓
Splunk Alert
SOC - Suspicious PowerShell File Download T1105
```

This is the core evidence chain for the case.

---

# 16. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Command and Control | Ingress Tool Transfer | **T1105** | PowerShell retrieved external content and wrote it locally |

### Why T1105 Applies

The simulated activity involved obtaining content from an external resource and transferring that content to the endpoint.

The strongest supporting evidence was the combination of:

- PowerShell `DownloadString()`
- External GitHub raw-content resource
- DNS resolution
- HTTPS connection
- Local file creation

The mapping is therefore based on the complete behavior chain rather than on the presence of PowerShell alone.

---

# 17. Indicators and Observables

## Host

```text
DESKTOP-HCNDFJJ
```

## User

```text
DESKTOP-HCNDFJJ\حذيفه أبو الرجال
```

## Process

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

## Process ID

```text
16244
```

## Process GUID

```text
{9f3b70de-5faa-6a93-99bd-000000006b01}
```

## Domain

```text
raw.githubusercontent.com
```

## Destination IP

```text
185.199.110.133
```

Additional DNS results observed:

```text
185.199.111.133
185.199.108.133
185.199.109.133
```

## Destination Port

```text
443/TCP
```

## Created File

```text
C:\Users\حذيفه أبو الرجال\Downloads\LICENSE.txt
```

---

# 18. Analyst Assessment

The observed activity is **consistent with the controlled T1105 test that was intentionally executed in the lab**.

The following evidence supports that conclusion:

1. Atomic Red Team executed the test successfully.
2. Sysmon recorded the PowerShell process.
3. The PowerShell command line contained the external download operation.
4. Sysmon recorded DNS resolution for the requested domain.
5. Sysmon recorded an HTTPS connection from the same PowerShell process.
6. A local `LICENSE.txt` file was created.
7. Splunk correlated the telemetry and generated the configured alert.
8. The dashboard provided an additional investigation view.

Because the activity was intentionally generated as part of the lab, it should not be interpreted as evidence of an actual compromise.

---

# 19. Detection Strengths

The exercise demonstrated several useful detection capabilities:

### Process Visibility

Sysmon Event ID 1 exposed the PowerShell command line and process relationship.

### DNS Visibility

Event ID 22 provided visibility into the domain requested by the process.

### Network Visibility

Event ID 3 provided the destination IP and TCP port.

### File-System Visibility

Event ID 11 provided evidence that a file was created locally.

### Correlation

The Process GUID allowed multiple events to be associated with the same PowerShell process.

### Alerting

The Splunk scheduled alert converted the detection logic into an operational SOC notification.

### Visualization

The dashboard provided analysts with a faster way to review the activity.

---

# 20. Limitations

This detection should not be considered proof that every PowerShell download is malicious.

Legitimate administrators and applications may also use PowerShell to retrieve files.

Potential improvements for a production environment would include:

- Allowlisting approved administrative scripts and destinations.
- Adding reputation or threat-intelligence context.
- Correlating the parent process and user context.
- Monitoring unusual download locations.
- Detecting encoded or obfuscated PowerShell commands.
- Adding additional behavioral conditions to reduce false positives.

These improvements were outside the scope of this controlled lab exercise.

---

# 21. Response Actions

Because this was a controlled lab simulation, no containment or eradication action was required.

For a real production alert, an analyst could consider:

1. Validate whether the PowerShell execution was authorized.
2. Identify the initiating user and host.
3. Review the complete PowerShell command line.
4. Inspect the destination domain and IP.
5. Verify the created file and its hash.
6. Search for related processes and persistence.
7. Review additional network and endpoint activity.
8. Escalate if the activity is unauthorized or malicious.

---

# 22. Lessons Learned

This exercise demonstrated an important SOC principle:

> **A stronger detection is built from related evidence rather than a single suspicious event.**

PowerShell by itself is common in Windows environments. The confidence of this investigation increased because several telemetry sources aligned:

```text
PowerShell Execution
        +
DNS Resolution
        +
HTTPS Connection
        +
File Creation
        =
High-Confidence Context for Investigation
```

The exercise also demonstrated the value of Process GUID correlation for connecting endpoint events belonging to the same process.

---

# 23. Final Incident Conclusion

The controlled T1105 simulation was successfully executed, detected, investigated, and documented.

The evidence established a coherent activity chain:

**Atomic Red Team → PowerShell → DNS Query → HTTPS Connection → Local File Creation → Splunk Detection → Alert → Dashboard Investigation**

The SOC lab successfully demonstrated the ability to move from raw Sysmon telemetry to a correlated detection and documented investigation.

**Final Classification:** Controlled Security Test  
**Primary Technique:** T1105 — Ingress Tool Transfer  
**Detection:** Successful  
**Alert:** Triggered  
**Production Impact:** None  
**Case Status:** Closed
