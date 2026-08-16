============================================================
SOC HOME LAB — ATOMIC RED TEAM ATTACK COMMANDS
============================================================

Incident:
03-PowerShell-Attack

MITRE ATT&CK:
T1059.001 — Command and Scripting Interpreter: PowerShell

Attack Framework:
Atomic Red Team

Attack Objective:
Simulate suspicious PowerShell execution techniques and generate
Windows Sysmon telemetry for Splunk detection and investigation.

Environment:
Windows 10 SOC Home Lab

Telemetry:
Sysmon — Microsoft-Windows-Sysmon/Operational

Splunk Index:
main

Sourcetype:
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational


============================================================
1. ATOMIC RED TEAM VALIDATION
============================================================

Purpose:
Verify that Atomic Red Team is installed and accessible.

Command:

Invoke-AtomicTest T1059.001 -ShowDetails


Expected Result:

Atomic Red Team displays the available Atomic Tests for:

T1059.001 — Command and Scripting Interpreter: PowerShell


============================================================
2. PREREQUISITE CHECK
============================================================

Purpose:
Check which PowerShell Atomic Tests can be executed in the
current lab environment.

Command:

Invoke-AtomicTest T1059.001 -CheckPrereqs


Expected Result:

Atomic Red Team reports the prerequisite status for each test.

Some tests may require:

- Administrator privileges.
- PowerShell Remoting.
- SharpHound.ps1.
- AtomicTestHarnesses module.
- Additional payloads.

Only tests whose prerequisites are satisfied should be executed.


============================================================
3. SELECTED ATTACK TEST
============================================================

Atomic Test:

T1059.001-17

Name:

PowerShell Command Execution

GUID:

a538de64-1c74-46ed-aa60-b995ed302598

Purpose:

Simulate obfuscated PowerShell command execution using the
EncodedCommand (-e) parameter.

This test was selected because it directly generates the type
of telemetry required for the Splunk detection developed for
this incident.


============================================================
4. ATTACK EXECUTION
============================================================

Command:

Invoke-AtomicTest T1059.001 -TestNumbers 17


Attack Behavior:

The Atomic Red Team test launches PowerShell using an encoded
command.

The execution uses the following PowerShell syntax:

powershell.exe -e <Base64-encoded-command>


Expected Telemetry:

Sysmon Process Creation Event

The resulting event should contain fields such as:

Image
ParentImage
CommandLine
User
host
ProcessId


============================================================
5. OBSERVED ATTACK CHAIN
============================================================

Observed Parent Process:

C:\Windows\System32\cmd.exe

        |
        v

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

        |
        v

Encoded PowerShell Command


Observed execution pattern:

cmd.exe
    |
    +---- powershell.exe -e <encoded command>


This process relationship was successfully observed in Splunk.


============================================================
6. OBSERVED ATTACK EVIDENCE
============================================================

Host:

DESKTOP-HCNDFJJ

User:

DESKTOP-HCNDFJJ\حذيفه أبو الرجال

PowerShell Image:

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Parent Image:

C:\Windows\System32\cmd.exe

Process ID:

13776

Command Pattern:

powershell.exe -e <Base64-encoded command>


Observed timestamp:

2026-08-17 00:06:50.911


============================================================
7. SPLUNK DETECTION VALIDATION
============================================================

After executing the Atomic Red Team test, Splunk was queried
to identify the generated Sysmon process creation event.

Detection Query:

index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
Image="*powershell.exe*"
ParentImage="*cmd.exe*"
| table _time host User Image ParentImage CommandLine ProcessId
| sort -_time


Expected Result:

A PowerShell process launched by cmd.exe should appear in the
results.


============================================================
8. ENCODED POWERSHELL DETECTION
============================================================

The following query was used to specifically identify encoded
PowerShell execution:

index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
Image="*powershell.exe*"
(CommandLine="*-e *"
 OR CommandLine="*-enc *"
 OR CommandLine="*-EncodedCommand*")
| table _time host User Image ParentImage CommandLine ProcessId
| sort -_time


Detection Indicators:

-e
-enc
-EncodedCommand


============================================================
9. HIGH-CONFIDENCE DETECTION
============================================================

The following query combines the process relationship and
encoded-command indicators:

index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
Image="*powershell.exe*"
ParentImage="*cmd.exe*"
(CommandLine="*-e *"
 OR CommandLine="*-enc *"
 OR CommandLine="*-EncodedCommand*")
| table _time host User Image ParentImage CommandLine ProcessId
| sort -_time


Detection Logic:

PowerShell
    +
cmd.exe Parent
    +
Encoded Command
    =
High-Confidence Suspicious PowerShell Activity


============================================================
10. ATOMIC TESTS REVIEWED
============================================================

The following T1059.001 Atomic Red Team tests were reviewed
during attack preparation:

T1059.001-1
Mimikatz

T1059.001-2
Run BloodHound from local disk

T1059.001-3
Run BloodHound from Memory using Download Cradle

T1059.001-4
Mimikatz - Cradlecraft PsSendKeys

T1059.001-5
Invoke-AppPathBypass

T1059.001-6
Powershell MsXml COM object

T1059.001-7
Powershell XML requests

T1059.001-8
Powershell invoke mshta.exe download

T1059.001-10
PowerShell Fileless Script Execution

T1059.001-11
NTFS Alternate Data Stream Access

T1059.001-12
PowerShell Session Creation and Use

T1059.001-13
PowerShell CommandLine Parameter variations

T1059.001-14
PowerShell CommandLine Parameter variations with
encoded arguments

T1059.001-15
PowerShell EncodedCommand parameter variations

T1059.001-16
PowerShell EncodedCommand parameter variations with
encoded arguments

T1059.001-17
PowerShell Command Execution

T1059.001-18
PowerShell Invoke Known Malicious Cmdlets

T1059.001-19
PowerUp Invoke-AllChecks

T1059.001-20
Abuse Nslookup with DNS Records

T1059.001-21
SOAPHound - Dump BloodHound Data

T1059.001-22
SOAPHound - Build Cache


============================================================
11. PREREQUISITE STATUS
============================================================

Prerequisites were checked before execution.

The following tests reported satisfied prerequisites:

T1059.001-3
T1059.001-5
T1059.001-6
T1059.001-7
T1059.001-8
T1059.001-10
T1059.001-11
T1059.001-17
T1059.001-19
T1059.001-20
T1059.001-21
T1059.001-22

Other tests required additional prerequisites such as:

- Administrator privileges.
- SharpHound.ps1.
- PowerShell Remoting.
- AtomicTestHarnesses module.

Prerequisite failures were not treated as attack failures;
they indicate that the individual Atomic Test requires
additional configuration before execution.


============================================================
12. ATTACK EXECUTION RESULT
============================================================

Attack Status:

SUCCESSFUL


Evidence:

The Atomic Red Team PowerShell Command Execution test generated
a Sysmon process creation event that was successfully ingested
into Splunk.

The event showed:

Image:
powershell.exe

ParentImage:
cmd.exe

CommandLine:
powershell.exe -e <Base64-encoded command>

The Splunk detection successfully identified the activity.


============================================================
13. DETECTION WORKFLOW
============================================================

Atomic Red Team
      |
      v
PowerShell Encoded Execution
      |
      v
Sysmon Process Creation
      |
      v
Splunk Index: main
      |
      v
Sourcetype:
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
      |
      v
SPL Detection
      |
      v
Alert
      |
      v
SOC Dashboard
      |
      v
Investigation
      |
      v
Incident Report


============================================================
14. CLEANUP
============================================================

The selected Atomic Test was a controlled command-execution
simulation.

No persistence mechanism or production compromise was introduced.

Temporary artifacts generated by individual Atomic Tests should
be removed using their documented Cleanup Commands when those
tests are executed.


============================================================
15. SAFETY / LAB SCOPE
============================================================

All commands in this file were intended for execution inside
the controlled SOC Home Lab.

The activity was performed for defensive detection engineering,
SOC investigation, and Splunk validation.

No production systems, real user accounts, or unauthorized
external systems were targeted.


============================================================
16. MITRE ATT&CK MAPPING
============================================================

Tactic:

Execution

Technique:

T1059 — Command and Scripting Interpreter

Sub-Technique:

T1059.001 — PowerShell


============================================================
17. FINAL ATTACK SUMMARY
============================================================

Attack:

PowerShell Command Execution

Framework:

Atomic Red Team

Technique:

T1059.001

Primary Test:

T1059.001-17

Key Indicator:

powershell.exe -e <Base64-encoded command>

Parent Process:

cmd.exe

Telemetry:

Sysmon Process Creation

SIEM:

Splunk Enterprise

Detection:

PowerShell spawned by cmd.exe with an encoded command

Result:

Successfully detected and investigated.


============================================================
END OF ATTACK COMMANDS
============================================================