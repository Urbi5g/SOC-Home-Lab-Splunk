# Incident Report: PowerShell Attack — Encoded PowerShell Execution

| Field            | Value                                      |
|------------------|--------------------------------------------|
| **Report ID**    | SOC-2026-003                               |
| **Date**         | 2026-08-17                                 |
| **Time (UTC)**   | 00:06                                      |
| **Author**       | حذيفة أبو الرجال — SOC Analyst L1 (Lab)   |
| **Reviewer**     | N/A — Personal SOC Home Lab                |
| **Classification** | Internal                                 |
| **Severity**     | High                                       |
| **Priority**     | P2                                         |
| **Status**       | Closed                                     |
| **Related Alerts** | PowerShell Encoded Command Detection     |

---

## 1. Executive Summary

A controlled PowerShell attack simulation was conducted inside the SOC Home Lab using Atomic Red Team to emulate adversarial PowerShell execution.

The simulation targeted MITRE ATT&CK technique **T1059.001 — Command and Scripting Interpreter: PowerShell**. Multiple Atomic Red Team tests were reviewed, including PowerShell download cradles, fileless execution, NTFS Alternate Data Streams, PowerShell sessions, encoded command execution, and other PowerShell-based attack behaviors.

During the validation phase, an encoded PowerShell command was executed using the `-e` parameter:

```text
powershell.exe -e <Base64 encoded command>

Windows Sysmon recorded the resulting process creation activity. The event was ingested into Splunk Enterprise using the Sysmon sourcetype:

XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

A custom Splunk detection identified PowerShell execution originating from cmd.exe, and a more focused detection identified PowerShell commands using -e, -enc, or -EncodedCommand.

The detection successfully identified the simulated malicious PowerShell behavior and exposed important investigation fields including:

Timestamp
Host
User
PowerShell executable
Parent process
Command Line
Process ID

The incident was confirmed as a controlled Red Team simulation performed for SOC detection engineering and analyst investigation training.

No production systems or real user accounts were affected.

2. Incident Overview
Attack Type: PowerShell Command Execution / Encoded PowerShell
MITRE ATT&CK Technique: T1059.001 — Command and Scripting Interpreter: PowerShell
Attack Platform: Atomic Red Team
Primary Atomic Test: T1059.001-17 — PowerShell Command Execution
Observed PowerShell Technique: Encoded PowerShell execution using -e
Attacker Host: DESKTOP-HCNDFJJ
Target Host: DESKTOP-HCNDFJJ
User Context: DESKTOP-HCNDFJJ\حذيفه أبو الرجال
PowerShell Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Parent Process:
C:\Windows\System32\cmd.exe
Log Source: Windows Sysmon
Splunk Index: main
Splunk Sourcetype:
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
Business Impact: No production impact. The activity was generated intentionally within the SOC Home Lab.
Initial Vector: Local command execution through cmd.exe, spawning PowerShell with an encoded command.
Attack Objective

The objective of the simulation was to validate the complete SOC detection workflow for suspicious PowerShell execution:

Prepare Atomic Red Team.
Review available PowerShell Atomic tests.
Validate test prerequisites.
Execute a controlled PowerShell attack simulation.
Generate Windows Sysmon telemetry.
Ingest the telemetry into Splunk.
Detect suspicious PowerShell execution.
Detect encoded PowerShell command-line activity.
Investigate the generated event.
Visualize the activity using a Splunk Dashboard.
Map the activity to MITRE ATT&CK.
Document the detection and investigation process.
3. Attack Methodology

The attack simulation was performed using Atomic Red Team.

The Atomic Red Team framework was used to identify and execute tests associated with:

T1059.001
Command and Scripting Interpreter: PowerShell

The available Atomic tests included multiple PowerShell behaviors.

Examples reviewed during the exercise included:

Mimikatz execution
BloodHound / SharpHound execution
PowerShell download cradle
In-memory PowerShell execution
AppPath UAC bypass
MSXML download cradle
XML-based PowerShell execution
mshta.exe download execution
Fileless PowerShell execution
NTFS Alternate Data Stream execution
PowerShell session creation
Encoded PowerShell command execution
PowerShell command-line parameter variations
PowerShell known malicious cmdlet simulation
PowerUp privilege escalation checks
DNS-based PowerShell execution
SOAPHound operations

The prerequisite validation showed that not every Atomic test was immediately executable because some required:

Elevated privileges
SharpHound payloads
PowerShell Remoting
AtomicTestHarnesses module
Additional dependencies

For this reason, the attack simulation was focused on tests whose prerequisites were satisfied and whose behavior could be safely observed through Sysmon.

4. Attack Execution
4.1 Atomic Red Team Validation

The following command was used to review the PowerShell Atomic tests:

Invoke-AtomicTest T1059.001 -ShowDetails

This returned the available Atomic Red Team tests associated with:

T1059.001 — Command and Scripting Interpreter: PowerShell

Prerequisites were then checked using:

Invoke-AtomicTest T1059.001 -CheckPrereqs

The results demonstrated that some tests were ready for execution while others required additional privileges or dependencies.

For example:

T1059.001-17 PowerShell Command Execution
Prerequisites met

The test specifically simulated obfuscated PowerShell execution using an encoded command.

4.2 Observed Attack Behavior

The observed PowerShell process was:

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

The parent process was:

C:\Windows\System32\cmd.exe

The observed command line contained:

powershell.exe -e <Base64 encoded command>

The use of -e represents the PowerShell -EncodedCommand parameter.

The encoded command observed during the investigation was:

JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIiACsAIgBvAG0AIAUAA...

The full encoded value was preserved in the Sysmon event and was available for investigation through Splunk.

5. Attack Timeline
Time (UTC)	Event	Source	Artifact / Log Evidence	Analyst Note
00:00	Atomic Red Team PowerShell tests reviewed	Atomic Red Team	Invoke-AtomicTest T1059.001 -ShowDetails	Available PowerShell attack simulations reviewed
00:01	Atomic prerequisites checked	Atomic Red Team	Invoke-AtomicTest T1059.001 -CheckPrereqs	Several tests were available while others required dependencies
00:06:50	Encoded PowerShell command executed	Windows	PowerShell process creation	Suspicious -e parameter observed
00:06:50	PowerShell spawned by cmd.exe	Sysmon	Image + ParentImage	Parent-child process relationship recorded
00:06:50	Sysmon event ingested into Splunk	Splunk	Sysmon sourcetype	Telemetry became available for detection
00:06:50	Detection identified encoded PowerShell	Splunk	Encoded PowerShell SPL	Detection condition matched
00:07	Dashboard investigation performed	Splunk	PowerShell Detection Dashboard	Activity visualized and reviewed
00:10	Raw event investigated	SOC Analyst	CommandLine / User / ProcessId	Attack behavior confirmed
00:15	Incident documented	SOC Analyst	incident_report.md	Findings recorded
6. Detection & Alerting
6.1 Detection Source

The activity was detected through Windows Sysmon process creation telemetry ingested into Splunk Enterprise.

The primary data source was:

index=main
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"

The detection focused on PowerShell execution and its relationship with the parent process.

6.2 Initial PowerShell Detection

The initial detection query used during the investigation was:

index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
Image="*powershell.exe*"
ParentImage="*cmd.exe*"
| table _time host User Image ParentImage CommandLine
| sort -_time

This detection identifies PowerShell processes launched by cmd.exe.

The query provided the following investigation fields:

_time
host
User
Image
ParentImage
CommandLine

The query successfully returned the observed attack event.

6.3 Encoded PowerShell Detection

A more focused detection was then created to identify common PowerShell encoded-command parameters:

index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
Image="*powershell.exe*"
(CommandLine="*-e *" OR CommandLine="*-enc *" OR CommandLine="*-EncodedCommand*")
| table _time host User Image ParentImage CommandLine ProcessId
| sort -_time
Detection Logic

The detection searches for:

PowerShell process execution.
PowerShell command-line parameters associated with encoded commands.
-e
-enc
-EncodedCommand

The detection also extracts the process ID and parent process for investigation.

The logic is intended to identify potentially suspicious PowerShell obfuscation or encoded execution.

Encoded PowerShell is not automatically malicious because legitimate administrators may use encoded commands. Therefore, the detection should be investigated using additional context such as:

Parent process
User
Host
Command line
Process ID
Network activity
File creation
Child processes
Authentication activity
6.4 Detection Result

The detection successfully identified the simulated attack.

Observed event:

Time:
2026-08-17 00:06:50.911


Host:
DESKTOP-HCNDFJJ


User:
DESKTOP-HCNDFJJ\حذيفه أبو الرجال


Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe


ParentImage:
C:\Windows\System32\cmd.exe


ProcessId:
13776

The command line contained:

powershell.exe -e <Base64 encoded command>

This confirmed that the detection successfully identified the encoded PowerShell execution generated during the Atomic Red Team simulation.

6.5 Alert Configuration
Alert Name: PowerShell Encoded Command Detection
Data Source: Sysmon
Index: main
Sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
Detection Type: Scheduled / SPL-based detection
Detection Logic: PowerShell execution containing encoded-command parameters
Primary Parameters: -e, -enc, -EncodedCommand
Status: Successfully tested
Investigation: Performed through Splunk Search and Dashboard
7. MITRE ATT&CK Mapping
Tactic	Technique	Sub-Technique	ID	Description	Evidence
Execution	Command and Scripting Interpreter	PowerShell	T1059.001	Adversaries may abuse PowerShell to execute commands and scripts	PowerShell process execution
Defense Evasion	Obfuscated/Compressed Files and Information	N/A	T1027	Adversaries may obfuscate commands or payloads to make detection more difficult	Base64-encoded PowerShell command
Technique Rationale

The primary technique is:

T1059.001 — Command and Scripting Interpreter: PowerShell

The simulated attack explicitly executed PowerShell.

The use of:

powershell.exe -e

also demonstrated an encoded command-line execution pattern.

This provides additional defensive-evasion context because encoding can make command-line content less immediately readable during investigation.

The MITRE mapping is based on the observed behavior and not simply on the name of the Atomic Red Team test.

8. Affected Assets & Impact
Asset / Hostname	IP Address	OS / Service	Criticality	Impact Description
DESKTOP-HCNDFJJ	Lab Host	Windows / PowerShell	Medium	Executed the controlled PowerShell simulation
Splunk Enterprise	Local SOC Infrastructure	SIEM	High	Collected and analyzed Sysmon telemetry
Monitoring Infrastructure

Splunk Enterprise was used to collect, search, detect, visualize, and investigate the generated Sysmon telemetry.

Splunk was not the target of the attack.

Impact Assessment

This was a controlled security exercise performed inside the SOC Home Lab.

No production infrastructure was affected.

No real credentials were targeted.

No production data was accessed.

The simulation was designed to validate SOC visibility into suspicious PowerShell execution.

If similar behavior occurred on a production endpoint, potential consequences could include:

Malicious script execution.
Credential theft.
Privilege escalation.
Persistence.
Defense evasion.
Download and execution of additional payloads.
Lateral movement.
Data collection or exfiltration.
9. Indicators of Compromise (IOCs)
Type	Value	Context	Source
Host	DESKTOP-HCNDFJJ	Host where simulation was executed	Sysmon
User	DESKTOP-HCNDFJJ\حذيفه أبو الرجال	User context of PowerShell process	Sysmon
Process	powershell.exe	PowerShell execution	Sysmon
Parent Process	cmd.exe	Parent process that launched PowerShell	Sysmon
Parameter	-e	Encoded PowerShell execution	Sysmon
Process ID	13776	Observed PowerShell process	Sysmon
Command Line	powershell.exe -e <Base64>	Encoded command execution	Sysmon
Technique	T1059.001	PowerShell execution	Atomic Red Team / MITRE ATT&CK

These indicators represent the controlled laboratory simulation and should not automatically be treated as production IOCs.

10. Investigation Steps
Step	Action Taken	Findings / Results
1	Reviewed Atomic Red Team PowerShell tests	Multiple T1059.001 tests were available
2	Checked test prerequisites	Some tests were ready while others required elevation or dependencies
3	Executed controlled PowerShell simulation	PowerShell process activity was generated
4	Reviewed Sysmon telemetry	PowerShell process creation was recorded
5	Investigated parent process	cmd.exe was identified as the parent
6	Reviewed CommandLine	Encoded PowerShell parameter -e was observed
7	Created initial SPL detection	PowerShell spawned by cmd.exe was detected
8	Created focused encoded-command detection	-e, -enc, and -EncodedCommand were searched
9	Reviewed Process ID	PID 13776 identified the observed PowerShell process
10	Reviewed user context	Event executed under the lab user account
11	Built Dashboard panels	PowerShell execution activity was visualized
12	Performed raw-event investigation	Full command line and process relationship were validated
13	Mapped activity to MITRE ATT&CK	T1059.001 identified as the primary technique
14	Classified the incident	Controlled PowerShell attack simulation
15	Documented findings	Incident report and detection workflow documented
11. Evidence

The following evidence was collected during the investigation.

11.1 Atomic Red Team Test Enumeration

The following command was used:

Invoke-AtomicTest T1059.001 -ShowDetails

The output demonstrated the available PowerShell Atomic Red Team simulations.

Evidence included tests involving:

Mimikatz
BloodHound
Download Cradles
Fileless execution
NTFS Alternate Data Streams
PowerShell sessions
Encoded PowerShell commands
PowerUp
SOAPHound
11.2 Atomic Prerequisite Validation

The following command was used:

Invoke-AtomicTest T1059.001 -CheckPrereqs

The result showed that several tests were immediately available while others required additional prerequisites.

This validation was important to ensure that the selected simulation could be executed reliably inside the lab.

11.3 Sysmon Process Evidence

The observed Sysmon event contained:

Host:
DESKTOP-HCNDFJJ


User:
DESKTOP-HCNDFJJ\حذيفه أبو الرجال


Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe


ParentImage:
C:\Windows\System32\cmd.exe


ProcessId:
13776

The command line contained an encoded PowerShell command:

powershell.exe -e <Base64 encoded command>
11.4 Splunk Detection Evidence

The initial detection:

index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
Image="*powershell.exe*"
ParentImage="*cmd.exe*"
| table _time host User Image ParentImage CommandLine
| sort -_time

successfully returned the simulated PowerShell event.

The focused detection:

index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
Image="*powershell.exe*"
(CommandLine="*-e *" OR CommandLine="*-enc *" OR CommandLine="*-EncodedCommand*")
| table _time host User Image ParentImage CommandLine ProcessId
| sort -_time

also successfully identified the encoded PowerShell execution.

11.5 Dashboard Evidence

A dedicated Splunk Dashboard was created to visualize the PowerShell attack activity.

The dashboard was used to support:

Detection visibility.
PowerShell event investigation.
Parent-child process analysis.
Encoded command detection.
Event timeline analysis.
Analyst drilldown.

Recommended screenshot:

screenshots/splunk_powershell_dashboard.png
12. Root Cause Analysis
5 Whys / Cause & Effect

Why was suspicious PowerShell activity generated?

Because a controlled Atomic Red Team PowerShell simulation was executed on the lab endpoint.

Why was PowerShell involved?

The Atomic Red Team test targeted MITRE ATT&CK T1059.001, which represents Command and Scripting Interpreter: PowerShell.

Why was the command line encoded?

The selected Atomic test simulated encoded PowerShell execution using the -e / -EncodedCommand mechanism.

Why was this behavior detectable?

Sysmon recorded the PowerShell process creation event, including the executable, parent process, user, command line, and process ID.

Root Cause:

The observed suspicious PowerShell activity was intentionally generated by the SOC Home Lab Red Team simulation to validate detection engineering and SOC investigation capabilities.

Note: This root cause applies only to the controlled laboratory exercise and does not represent a compromise of a production system.

13. Containment, Eradication & Recovery (PICERL)
Stage	Action Taken	Responsible	Status
Containment	Attack simulation stopped after detection validation	SOC Analyst	Completed
Eradication	No production compromise or persistence identified	SOC Analyst	Not Required
Recovery	Lab endpoint remained operational	Lab Administrator	Completed
Post-Incident	Detection and dashboard workflow reviewed	SOC Analyst	Completed
Improvement	Encoded PowerShell detection logic documented	SOC Analyst	Completed

Because this was a controlled simulation, no production endpoint required containment or remediation.

14. Recommendations & Remediation
Immediate (0–24 hours)
Continue monitoring PowerShell process creation through Sysmon.
Investigate encoded PowerShell commands rather than treating every encoded command as automatically malicious.
Review the parent process responsible for launching PowerShell.
Review the executing user and host context.
Correlate suspicious PowerShell activity with network connections and child processes.
Short-Term (1 week)

Improve the Splunk detection by adding contextual correlations such as:

PowerShell + encoded command.
PowerShell + unusual parent process.
PowerShell + network connection.
PowerShell + suspicious child process.
PowerShell + script download activity.
PowerShell + privilege escalation behavior.

Create additional detection coverage for:

IEX
Invoke-Expression
DownloadString
DownloadFile
-EncodedCommand
-e
-enc
FromBase64String
WebClient
Invoke-WebRequest

These indicators should be used as supporting evidence rather than standalone proof of malicious activity.

Long-Term (1 month)
Enable and centralize PowerShell Script Block Logging.
Enable PowerShell Module Logging where appropriate.
Enable PowerShell Transcription where appropriate.
Continue Sysmon process monitoring.
Correlate PowerShell events with network telemetry.
Develop risk-based PowerShell detections.
Integrate MITRE ATT&CK mapping into the detection engineering process.
Regularly validate detections using Atomic Red Team.
Build a broader endpoint execution dashboard.
15. Lessons Learned

This incident demonstrated several important SOC L1 capabilities:

Atomic Red Team can be used to generate repeatable adversary behavior.
MITRE ATT&CK provides a useful framework for organizing attack simulations.
Sysmon provides valuable process creation telemetry.
Parent-child process relationships are important during endpoint investigations.
PowerShell command-line arguments can provide strong detection context.
Encoded PowerShell is an important behavior to monitor.
Splunk can convert endpoint telemetry into actionable detections.
Dashboards improve investigation speed and visibility.
Detection engineering should be validated using controlled attack simulations.
Not every Atomic Red Team test will be immediately executable because of prerequisites and privilege requirements.
Detection logic should focus on behavior and context rather than relying on a single suspicious string.
Detection Improvement

The next iteration should correlate:

Encoded PowerShell
        ↓
PowerShell Process Creation
        ↓
Network Connection / Download
        ↓
File Creation
        ↓
Child Process
        ↓
Credential Access / Persistence / Lateral Movement

This correlation would provide significantly stronger evidence of malicious activity than detecting encoded PowerShell alone.

16. Detection Engineering Summary
Detection 1 — PowerShell Spawned by CMD
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
Image="*powershell.exe*"
ParentImage="*cmd.exe*"
| table _time host User Image ParentImage CommandLine
| sort -_time

Purpose:

Identify PowerShell processes launched by cmd.exe.

Detection 2 — Encoded PowerShell
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
Image="*powershell.exe*"
(CommandLine="*-e *" OR CommandLine="*-enc *" OR CommandLine="*-EncodedCommand*")
| table _time host User Image ParentImage CommandLine ProcessId
| sort -_time

Purpose:

Identify PowerShell processes using common encoded-command parameters.

Detection Engineering Consideration

The second detection is intentionally broad.

It should be treated as a suspicious behavior detection, not definitive proof of compromise.

The analyst should investigate:

User
Host
Parent Process
CommandLine
ProcessId
Network Activity
Child Processes
File Activity
Authentication Activity

before escalating the alert.

17. References
MITRE ATT&CK — T1059.001: Command and Scripting Interpreter: PowerShell
MITRE ATT&CK — T1027: Obfuscated/Compressed Files and Information
Atomic Red Team — T1059.001 PowerShell
Splunk Enterprise — Internal SOC Home Lab Documentation
Microsoft Sysmon — Process Creation Telemetry
Windows PowerShell Logging and Monitoring Documentation
18. Appendices
Appendix A — Atomic Red Team Commands

Test enumeration:

Invoke-AtomicTest T1059.001 -ShowDetails

Prerequisite validation:

Invoke-AtomicTest T1059.001 -CheckPrereqs

The commands were used to review and validate the available PowerShell Atomic Red Team simulations.

Appendix B — Observed Process Relationship
cmd.exe
   │
   └── powershell.exe
          │
          └── -e <Base64 Encoded Command>

This parent-child relationship was recorded by Sysmon and used during the Splunk investigation.

Appendix C — Observed Event
Time:
2026-08-17 00:06:50.911


Host:
DESKTOP-HCNDFJJ


User:
DESKTOP-HCNDFJJ\حذيفه أبو الرجال


Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe


ParentImage:
C:\Windows\System32\cmd.exe


ProcessId:
13776
Appendix D — Investigation Workflow

The complete SOC investigation workflow was:

Atomic Red Team
       ↓
Attack Simulation
       ↓
PowerShell Execution
       ↓
Sysmon Event
       ↓
Splunk Ingestion
       ↓
SPL Detection
       ↓
Alert
       ↓
Dashboard
       ↓
Raw Event Investigation
       ↓
MITRE ATT&CK Mapping
       ↓
Incident Documentation