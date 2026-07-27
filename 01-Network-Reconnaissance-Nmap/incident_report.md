# Incident Report: Network Reconnaissance Activity Detected

## Incident Overview

| Field | Details |
|---|---|
| Incident Type | Network Reconnaissance / Port Scanning |
| Severity | Medium |
| Detection Platform | Splunk Enterprise SIEM |
| Affected Host | Windows Endpoint |
| Attacker Source | Kali Linux |
| Detection Status | Confirmed |
| Investigation Status | Completed |


---

# 1. Executive Summary

A network reconnaissance activity was detected against a Windows endpoint in the SOC home lab environment.

The activity involved a Kali Linux attacker machine performing TCP port scanning using Nmap to identify exposed services and available ports on the target system.

Windows Security Event Logs were collected into Splunk and analyzed using SPL detection queries. The investigation confirmed abnormal connection attempts from a single source IP targeting multiple destination ports within a short period of time.


---

# 2. Lab Environment

## Components

- SIEM: Splunk Enterprise
- Log Collection: Splunk Universal Forwarder
- Endpoint OS: Windows
- Telemetry Sources:
  - Windows Security Event Logs
  - Sysmon Operational Logs
- Attacker Machine: Kali Linux


## Network Communication


Attacker
Kali Linux
192.168.81.104

    |
    |
    v

Target
Windows Endpoint
192.168.81.138



---

# 3. Attack Simulation

The reconnaissance activity was simulated using Nmap from the attacker machine.

The objective was to discover accessible services and identify open ports on the target endpoint.


Example command:

```bash
nmap -sS -p 22,80,135,445,3389 192.168.81.138

Attack Technique:

MITRE ATT&CK:

T1046 - Network Service Scanning
4. Detection Logic

The detection rule was designed to identify abnormal port scanning behavior by measuring the number of unique destination ports contacted by the same source address within a short time window.

Detection indicators:

Multiple destination ports
Same source address
Short time interval
Windows Security network events

Relevant Windows Event Codes:

EventCode	Description
5156	Windows Filtering Platform allowed connection
5157	Windows Filtering Platform blocked connection
5152	Windows Filtering Platform packet dropped
5. Splunk Investigation

The investigation workflow included:

Filtering events by source IP
Reviewing targeted ports
Analyzing activity timeline
Reviewing raw security events

Dashboard Components:

Recon Activity Timeline
Top Targeted Ports
Top Source IPs
Raw Investigation Events
6. Investigation Findings

The investigation identified:

A single source IP generating multiple connection attempts.
Multiple destination ports targeted within a short timeframe.
Activity pattern consistent with network reconnaissance.

The source IP was confirmed as the authorized Kali Linux testing machine used during the simulation.

7. Response Actions

Actions performed:

Validated the source of activity.
Reviewed related Windows Security events.
Confirmed the activity was part of an authorized security test.
Documented detection logic and investigation workflow.
8. Lessons Learned

This scenario demonstrated:

Windows telemetry collection using Splunk.
Building SPL-based detections.
Investigating reconnaissance activity.
Creating SOC investigation dashboards.
Using drilldown workflows for faster analysis.
Evidence

Screenshots:

Detection Dashboard
Investigation Dashboard
Drilldown Workflow
Splunk Search Results