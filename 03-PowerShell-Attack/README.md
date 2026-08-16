# PowerShell Attack Detection using Splunk

> **SOC Home Lab | Detection Engineering | Atomic Red Team | Splunk Enterprise | Sysmon**

---

## Case Overview

This case study demonstrates the complete simulation, detection, alerting, investigation, and documentation of a PowerShell-based attack using **Atomic Red Team** and **Splunk Enterprise**.

The activity was mapped primarily to:

**MITRE ATT&CK T1059.001 – Command and Scripting Interpreter: PowerShell**

The objective was to simulate realistic PowerShell execution behavior and validate whether the SOC monitoring environment could:

- Generate realistic attack telemetry.
- Collect Windows Sysmon events.
- Detect suspicious PowerShell execution.
- Identify encoded PowerShell commands.
- Trigger a Splunk alert.
- Visualize the activity through a dashboard.
- Investigate the underlying event.
- Map the behavior to MITRE ATT&CK.
- Document the complete incident.

> **Environment:** Controlled SOC Home Lab  
> **Production Impact:** None  
> **Incident Status:** Closed  
> **Detection Status:** Successfully Detected

---

# Quick Navigation

| Section | Description |
|--------|-------------|
| [Case Overview](#case-overview) | Case summary and objectives |
| [Lab Environment](#lab-environment) | Infrastructure and telemetry |
| [Attack Simulation](#attack-simulation) | Atomic Red Team simulation |
| [Attack Evidence](#attack-evidence) | Attack execution evidence |
| [Detection Engineering](#detection-engineering) | SPL detection methodology |
| [Encoded PowerShell Detection](#encoded-powershell-detection) | Encoded command detection |
| [Alerting](#alerting) | Splunk alert workflow |
| [Detection Dashboard](#detection-dashboard) | Dashboard investigation |
| [Investigation Workflow](#investigation-workflow) | SOC L1 investigation process |
| [Evidence Review](#evidence-review) | Raw event analysis |
| [MITRE ATT&CK Mapping](#mitre-attck-mapping) | ATT&CK classification |
| [Lessons Learned](#lessons-learned) | Detection insights |
| [Incident Report](#incident-report) | Complete incident documentation |
| [Repository Structure](#repository-structure) | Project organization |

---

# Case Summary

| Field | Value |
|------|-------|
| **Case ID** | SOC-2026-003 |
| **Attack Type** | PowerShell Attack Simulation |
| **Primary Technique** | T1059.001 |
| **Attack Framework** | Atomic Red Team |
| **SIEM** | Splunk Enterprise |
| **Telemetry** | Sysmon |
| **Operating System** | Windows 10 |
| **Detection Method** | SPL |
| **Alerting** | Splunk Alert |
| **Dashboard** | PowerShell Detection Dashboard |
| **Severity** | High |
| **Priority** | P2 |
| **Status** | Closed |
| **Environment** | SOC Home Lab |

---

# Lab Environment

| Component | Description |
|------------|-------------|
| SIEM | Splunk Enterprise |
| Attack Framework | Atomic Red Team |
| Monitored Host | Windows 10 |
| Telemetry Source | Sysmon |
| Log Type | Windows Sysmon Operational |
| Splunk Index | `main` |
| Sourcetype | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Primary Event | Sysmon Process Creation |
| Primary Technique | T1059.001 |

The lab environment was intentionally configured to generate security telemetry that could be collected and analyzed by Splunk.

---

# Attack Simulation

The attack simulation was performed using **Atomic Red Team**.

Atomic Red Team provides controlled security tests mapped to MITRE ATT&CK techniques.

The selected test family was:

**T1059.001 – Command and Scripting Interpreter: PowerShell**

The available Atomic Red Team tests included several PowerShell execution behaviors, including:

- PowerShell command execution
- Encoded PowerShell
- PowerShell download cradles
- Fileless PowerShell execution
- PowerShell command-line variations
- PowerShell obfuscation
- PowerShell-based discovery
- PowerShell privilege escalation simulations

The purpose of the simulation was to generate realistic endpoint telemetry rather than compromise a production system.

### Attack Documentation

The Atomic Red Team test information and execution documentation are available here:

📄 **[Atomic Red Team Attack Documentation](./attack/atomic_red_team_commands.txt)**

---

# Attack Evidence

The attack execution generated Sysmon process creation events containing:

- Hostname
- Username
- Process image
- Parent process
- Process ID
- Command line
- PowerShell parameters
- Timestamp

### Attack Execution

![PowerShell Attack Execution](./screenshots/01_powershell_attack.png)

**Figure 1 — Atomic Red Team PowerShell Attack Execution**

This evidence demonstrates the controlled PowerShell attack simulation performed inside the SOC Home Lab.

---

# Detection Engineering

After generating the attack telemetry, a custom Splunk detection was developed to identify suspicious PowerShell execution.

The detection focused on the parent-child process relationship:

```text
cmd.exe
   ↓
powershell.exe

This relationship is useful for identifying PowerShell execution initiated through a Windows command shell.

Detection Documentation

The complete SPL query is available here:

📄 Open SPL Detection Query

Primary Detection
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
Image="*powershell.exe*"
ParentImage="*cmd.exe*"
| table _time host User Image ParentImage CommandLine
| sort -_time

The query extracts the following investigation fields:

_time
host
User
Image
ParentImage
CommandLine

This provides the SOC analyst with immediate process execution context.

Encoded PowerShell Detection

During the investigation, an encoded PowerShell command was identified.

The observed command contained:

powershell.exe -e

A second detection query was developed to identify common encoded PowerShell parameters:

index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
Image="*powershell.exe*"
(CommandLine="*-e *" OR CommandLine="*-enc *" OR CommandLine="*-EncodedCommand*")
| table _time host User Image ParentImage CommandLine ProcessId
| sort -_time

The detection identifies:

-e
-enc
-EncodedCommand

These parameters are commonly associated with encoded PowerShell command execution.

Important: The presence of an encoded PowerShell command alone does not prove malicious activity. Detection confidence increases when it is correlated with process ancestry, user context, endpoint behavior, and other telemetry.

Detection Result

The SPL search successfully identified the simulated PowerShell activity.

The observed event contained:

Field	Value
Host	DESKTOP-HCNDFJJ
User	DESKTOP-HCNDFJJ\حذيفه أبو الرجال
Image	C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Parent Image	C:\Windows\System32\cmd.exe
Process ID	13776
Encoded Parameter	-e
Sourcetype	XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
SPL Search Evidence

Figure 2 — Splunk SPL Detection Result

The event confirmed that PowerShell was launched by cmd.exe and that an encoded command was supplied through the PowerShell command line.

Alerting

After validating the detection logic, a Splunk alert was configured to notify the SOC when suspicious PowerShell activity was detected.

The detection workflow was:

Atomic Red Team
      ↓
PowerShell Execution
      ↓
Sysmon Event
      ↓
Splunk Ingestion
      ↓
SPL Detection
      ↓
Alert Trigger
      ↓
SOC Notification
      ↓
Investigation
Alert Evidence

Figure 3 — Splunk PowerShell Detection Alert

The alert confirms that the detection logic successfully generated a security alert from the simulated activity.

Detection Dashboard

A dedicated PowerShell Detection Dashboard was created to provide analysts with centralized visibility into suspicious PowerShell activity.

The dashboard provides visibility into:

PowerShell execution timeline
Executing hosts
Executing users
Parent processes
PowerShell processes
Command-line activity
Encoded PowerShell activity
Process IDs
Investigation events
Dashboard Preview

Figure 4 — PowerShell Detection Dashboard

The dashboard allows the analyst to move from high-level detection information into detailed event investigation.

Investigation Workflow

The investigation followed a standard SOC L1 workflow.

Detection
   ↓
Alert Review
   ↓
Identify Host
   ↓
Identify User
   ↓
Review Parent Process
   ↓
Analyze Command Line
   ↓
Identify Encoded PowerShell
   ↓
Validate Sysmon Event
   ↓
MITRE ATT&CK Mapping
   ↓
Incident Documentation

The analyst investigated:

Which host executed PowerShell?
Which user executed the process?
Which process launched PowerShell?
What command was executed?
Was an encoded command used?
Was the activity expected?
Which MITRE ATT&CK technique applied?
Evidence Review

The investigation was supported by four primary evidence artifacts.

Evidence	File	Purpose
Attack Execution	01_powershell_attack.png	Demonstrates attack simulation
Splunk Alert	02_detection_alert.png	Demonstrates alert generation
Dashboard	03_detection_dashboard.png	Demonstrates visualization
SPL Result	04_spl_query_result.png	Demonstrates event-level detection

The evidence chain demonstrates:

Attack
  ↓
Telemetry
  ↓
Detection
  ↓
Alert
  ↓
Dashboard
  ↓
Investigation
MITRE ATT&CK Mapping
Tactic	Technique	ID	Relevance
Execution	Command and Scripting Interpreter: PowerShell	T1059.001	Primary technique
Execution	Command and Scripting Interpreter	T1059	Parent technique
Defense Evasion	Obfuscated/Compressed Files and Information	T1027	Supporting indicator for encoded content
Primary Technique
T1059.001 — Command and Scripting Interpreter: PowerShell

PowerShell was used as the execution mechanism during the simulated attack.

This is the primary MITRE ATT&CK mapping for the case.

Supporting Indicator

The use of -EncodedCommand / -e was treated as an additional suspicious behavior.

The encoded command was investigated in conjunction with:

Parent process
User
Host
Process ID
Command line
Atomic Red Team execution context
Incident Classification
Attribute	Classification
Incident Type	PowerShell Attack Simulation
Severity	High
Priority	P2
Status	Closed
Environment	SOC Home Lab
Detection	Successful
Alert	Triggered
Investigation	Completed
Production Impact	None
SOC Investigation Findings

The investigation confirmed:

PowerShell was executed on the monitored Windows endpoint.
cmd.exe was identified as the parent process.
Sysmon successfully recorded the process creation event.
Splunk successfully ingested the telemetry.
The SPL detection successfully identified the activity.
An encoded PowerShell command was observed.
The Splunk alert was successfully triggered.
The activity appeared in the detection dashboard.
The underlying event was available for analyst investigation.
Atomic Red Team was responsible for generating the controlled test activity.
Lessons Learned

This case demonstrated why PowerShell should receive high-priority monitoring within a Windows SOC environment.

Process creation telemetry provides important context beyond simply searching for:

powershell.exe

The most valuable investigation fields were:

Process Image
Parent Image
User
CommandLine
Process ID
Host
Timestamp

The exercise also demonstrated the value of monitoring encoded PowerShell parameters.

Detection Improvements

Future detection iterations can improve visibility by adding:

PowerShell Script Block Logging
PowerShell Module Logging
PowerShell Operational Logs
Sysmon Event ID 1 correlation
Network connections generated by PowerShell
External download activity
Suspicious URLs
Encoded command analysis
Parent-child process anomaly detection
User and host baselining

A stronger correlation model could be:

Encoded PowerShell
        +
Suspicious Parent Process
        +
External Network Connection
        +
Script Execution
        =
Higher Confidence Detection
Incident Report

The complete incident investigation is documented in the incident report.

📄 Open Incident Report

The report contains:

Executive Summary
Incident Overview
Attack Timeline
Detection & Alerting
MITRE ATT&CK Mapping
Affected Assets
Indicators
Investigation Steps
Evidence
Root Cause Analysis
PICERL
Recommendations
Lessons Learned
Appendices
Conclusion
Detection Query

The complete detection query is maintained separately to keep detection engineering artifacts reusable.

📄 Open SPL Detection Query

Attack Documentation

Atomic Red Team test information and attack execution details are documented separately.

📄 Open Atomic Red Team Documentation

Evidence Gallery
Attack Execution

Splunk Alert

Detection Dashboard

SPL Detection Result

Repository Structure
03-PowerShell-Attack/
│
├── README.md
│
├── incident_report.md
│
├── attack/
│   └── atomic_red_team_commands.txt
│
├── detection/
│   └── spl_query.txt
│
└── screenshots/
    ├── 01_powershell_attack.png
    ├── 02_detection_alert.png
    ├── 03_detection_dashboard.png
    └── 04_spl_query_result.png
Complete SOC Workflow

The complete workflow demonstrated in this case was:

┌─────────────────────────┐
│     Atomic Red Team     │
│    Attack Simulation    │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│   PowerShell Execution  │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│      Sysmon Event       │
│   Process Creation      │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│    Splunk Log Ingest    │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│      SPL Detection      │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│     Splunk Alert        │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│   Detection Dashboard   │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│   Analyst Investigation │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│   MITRE ATT&CK Mapping  │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│    Incident Report      │
└─────────────────────────┘
Skills Demonstrated

This case demonstrates practical SOC L1 capabilities including:

Splunk Enterprise
SPL Query Development
Detection Engineering
Atomic Red Team
MITRE ATT&CK
Sysmon Analysis
Windows Event Analysis
PowerShell Threat Detection
Process Tree Analysis
Command-Line Analysis
Encoded PowerShell Detection
Alert Engineering
Dashboard Development
SOC Investigation
Threat Hunting
Security Event Correlation
Incident Documentation
Conclusion

The PowerShell attack simulation was successfully executed using Atomic Red Team and detected by Splunk Enterprise through Sysmon process creation telemetry.

The exercise validated the complete SOC workflow:

Attack Simulation → Telemetry → Detection → Alert → Dashboard → Investigation → MITRE Mapping → Incident Documentation

The case demonstrates that endpoint process telemetry combined with command-line analysis can provide effective visibility into suspicious PowerShell execution.

The lab is now positioned for future detection improvements involving:

PowerShell Script Block Logging
Encoded command analysis
Suspicious download cradles
Network correlation
Process-tree analytics
Post-exploitation behavior
Automated response

Case Status: Successfully Detected and Investigated
Primary MITRE Technique: T1059.001
Environment: Controlled SOC Home Lab
Production Impact: None