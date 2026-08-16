Incident Report: Network Reconnaissance / Port Scanning

Field| Value
Report ID| SOC-2026-001
Date| 2026-08-16
Time (UTC)| 14:37
Author| حذيفة أبو الرجال — SOC Analyst L1 (Lab)
Reviewer| N/A — Personal SOC Home Lab
Classification| Internal
Severity| Medium
Priority| P3
Status| Closed
Related Alerts| Network Reconnaissance Detection

---

1. Executive Summary

A controlled network reconnaissance activity was performed against a Windows endpoint within the SOC Home Lab environment using Nmap from an authorized Kali Linux testing machine.

The objective of the simulation was to identify exposed TCP services and validate whether network reconnaissance behavior could be detected through Windows Security Event Logs and analyzed using Splunk Enterprise.

Windows Filtering Platform events were collected and ingested into Splunk. The investigation identified multiple connection attempts originating from the same source IP and targeting multiple destination ports within a short period of time.

The observed behavior was consistent with network service scanning and was mapped to MITRE ATT&CK technique T1046 — Network Service Scanning. The source was subsequently confirmed as the authorized Kali Linux testing machine. No unauthorized compromise or production impact occurred.

---

2. Incident Overview

- Attack Type: Network Reconnaissance / Network Service Scanning
- Attacker IP / Hostname: Kali Linux — "192.168.213.53"
- Target IP / Hostname: Windows Endpoint — "192.168.213.138"
- Tools / Malware Used: Nmap
- Affected Systems: Windows Endpoint
- Detection Platform: Splunk Enterprise
- Log Sources: Windows Security Event Logs / Windows Filtering Platform
- Business Impact: No production impact. The activity was performed inside the controlled SOC Home Lab environment.
- Initial Vector: Direct network connectivity from the authorized Kali Linux testing machine to the Windows endpoint followed by TCP port scanning.

Attack Objective

The simulation was designed to determine whether the SOC monitoring stack could identify reconnaissance behavior based on:

- Multiple destination ports.
- Repeated connection attempts.
- A common source IP.
- Short time intervals between events.
- Windows Filtering Platform telemetry.
- Correlation of network events inside Splunk.

---

3. Lab Environment

Component| Configuration
SIEM| Splunk Enterprise
Attacker Machine| Kali Linux
Attacker IP| "192.168.213.53"
Target Endpoint| Windows
Target IP| "192.168.213.138"
Attack Tool| Nmap
Telemetry Source| Windows Security Event Logs
Relevant Event Codes| 5156, 5157, 5152
Detection Platform| Splunk Enterprise
Investigation| Splunk Detection & Investigation Dashboards

Network Communication

Kali Linux
192.168.213.53
      |
      | TCP SYN Port Scan
      | Nmap
      v
Windows Endpoint
192.168.213.138

---

4. Attack Simulation

The reconnaissance activity was simulated using Nmap from the authorized Kali Linux testing machine.

The objective was to identify potentially accessible services and determine which TCP ports were exposed on the Windows endpoint.

Nmap Command

nmap -sS -p 22,80,135,445,3389 192.168.213.138

The "-sS" option performs a TCP SYN scan. The scan targeted ports commonly associated with network services, including SSH, HTTP, RPC, SMB and RDP.

The scan generated network connection activity against multiple destination ports on the Windows endpoint.

The resulting Windows Security telemetry was then used to validate the Splunk detection.

MITRE ATT&CK

T1046 — Network Service Scanning

The activity maps to T1046 because the testing machine performed network probing against multiple ports to identify available network services.

---

5. Detection & Alerting

5.1 Detection Source

The activity was detected using Splunk Enterprise after Windows Security Event Logs were collected from the Windows endpoint.

The detection focused on identifying a single source communicating with multiple destination ports within a short period.

5.2 Relevant Windows Event Codes

Event Code| Description| Detection Value
5156| Windows Filtering Platform permitted a connection| Provides evidence of allowed network communication
5157| Windows Filtering Platform blocked a connection| Provides evidence of blocked network communication
5152| Windows Filtering Platform blocked a packet| Provides additional network filtering telemetry

These events provide network telemetry that can be correlated using source address, destination address, destination port and timestamp.

5.3 Detection Logic

The detection identifies potential port scanning by looking for:

- One source IP.
- One target endpoint.
- Multiple destination ports.
- Multiple network events within a short time window.
- Repeated connection attempts.
- A high number of unique destination ports.

The detection principle is:

«A single host contacting multiple destination ports on the same endpoint within a short period is a potential indicator of network service scanning.»

5.4 Splunk Detection

index=main
(EventCode=5156 OR EventCode=5157 OR EventCode=5152)
| stats dc(DestinationPort) as unique_dest_ports
    count as connection_count
    values(DestinationPort) as targeted_ports
    values(DestinationIp) as destination_ips
    by SourceIp
| where unique_dest_ports >= 5
| sort - unique_dest_ports

Detection Logic:

The search groups Windows Filtering Platform events by source IP and calculates the number of unique destination ports contacted.

A source generating connections to a high number of different destination ports is treated as a potential network reconnaissance indicator.

The detection was validated against the controlled Nmap activity generated by the Kali Linux testing machine.

---

6. Splunk Investigation

After the detection identified suspicious network activity, the analyst performed a structured investigation in Splunk.

Investigation Workflow

1. Identified the source IP.
2. Confirmed that the source belonged to the authorized Kali Linux testing machine.
3. Identified the target Windows endpoint.
4. Reviewed the destination ports.
5. Reviewed the event timeline.
6. Examined raw Windows Security events.
7. Correlated allowed and blocked network activity.
8. Compared the observed behavior with the Nmap scan.
9. Confirmed that the activity was authorized.
10. Documented the findings.

Dashboard Components

The Splunk investigation workflow included:

- Recon Activity Timeline
- Top Targeted Ports
- Top Source IPs
- Raw Investigation Events
- Drilldown Investigation Workflow

---

7. Investigation Findings

The investigation identified the following:

- A single source IP generated multiple network connection attempts.
- The source was "192.168.213.53".
- The target Windows endpoint was "192.168.213.138".
- Multiple destination ports were targeted within a short period.
- Windows Filtering Platform events provided supporting network telemetry.
- The activity pattern was consistent with Nmap network reconnaissance.
- The source was confirmed as the authorized Kali Linux testing machine.
- No evidence of unauthorized compromise was identified.

Analyst Assessment

Classification: Confirmed Authorized Security Testing Activity

The observed behavior initially matched the characteristics of network reconnaissance. After validating the source IP and correlating the activity with the controlled Nmap execution, the analyst confirmed that the activity was an authorized laboratory simulation.

This demonstrates an important SOC L1 principle:

«A detection identifies suspicious behavior; analyst investigation determines whether the behavior is malicious, benign or authorized.»

---

8. Indicators of Compromise (IOCs)

Because this activity was intentionally generated in the SOC Home Lab, these indicators are classified as test indicators rather than confirmed malicious IOCs.

Type| Value| Context| Source
IP| "192.168.213.53"| Authorized reconnaissance source| Windows Security Logs
IP| "192.168.213.138"| Target Windows endpoint| Windows Security Logs
Tool| Nmap| Network scanning tool used during simulation| Kali Linux
Ports| "22, 80, 135, 445, 3389"| Ports targeted during the Nmap scan| Nmap Execution
Event Codes| "5156, 5157, 5152"| Windows network filtering telemetry| Windows Security Logs

---

9. Investigation Evidence

The investigation used Splunk dashboards and search results to validate the reconnaissance behavior.

9.1 Detection Dashboard

"Reconnaissance Detection Dashboard" (screenshots/recon_detection_dashboard.png)

Evidence: The dashboard provides visibility into the detected reconnaissance activity, including source activity and targeted ports.

---

9.2 Investigation Dashboard

"Reconnaissance Investigation Dashboard" (screenshots/recon_investigation_dashboard.png)

Evidence: The investigation dashboard provides deeper analysis of the source IP, destination ports, timeline and raw Windows Security events.

---

Additional Evidence

Supporting evidence collected during the exercise included:

- Nmap execution output.
- Splunk detection search results.
- Windows Event ID 5156 events.
- Windows Event ID 5157 events.
- Windows Event ID 5152 events.
- Raw event details.
- Source and destination IP correlation.
- Dashboard investigation results.
- Drilldown investigation results.

---

10. Root Cause Analysis

5 Whys / Cause & Effect

1. Why was reconnaissance activity detected?
   The Kali Linux testing machine generated multiple network connection attempts against different destination ports on the Windows endpoint.

2. Why did the activity generate Windows Security events?
   Windows Filtering Platform monitored and recorded the network connection activity.

3. Why was the activity visible in Splunk?
   Windows Security telemetry was collected and ingested into Splunk Enterprise.

4. Why was the behavior classified as reconnaissance?
   The same source contacted multiple destination ports within a short period, matching the expected behavior of network service scanning.

5. Root Cause:
   The SOC Home Lab intentionally allowed the authorized Kali Linux testing machine to perform network scanning against the Windows endpoint to validate detection and investigation capabilities.

This root cause describes the controlled laboratory simulation and does not represent a production security weakness.

---

11. Containment, Eradication & Recovery (PICERL)

Stage| Action Taken| Responsible| Status
Containment| No containment required because the source was authorized| SOC Analyst| Not Required
Eradication| No malware or compromise identified| SOC Analyst| Not Required
Recovery| Windows endpoint remained operational| Lab Administrator| Completed
Post-Incident| Detection and investigation workflow documented| SOC Analyst| Completed
Improvement| SPL detection and dashboard workflow reviewed| SOC Analyst| Completed

---

12. Recommendations & Remediation

Immediate (0–24 hours)

- Validate the source IP whenever a reconnaissance detection triggers.
- Confirm whether the scanning activity is authorized.
- Review targeted ports and associated services.
- Investigate unexpected scanning sources.

Short-term (1 week)

- Tune the port-scanning threshold based on normal network behavior.
- Correlate Windows Filtering Platform Event Codes 5156, 5157 and 5152.
- Include source IP, destination IP and destination port information in alerts.
- Maintain drilldown functionality from detection dashboards to raw events.
- Create alerting for repeated reconnaissance from the same source.

Long-term (1 month)

- Establish a baseline for normal network connection behavior.
- Integrate Windows telemetry with firewall and IDS/IPS telemetry.
- Develop correlation between reconnaissance and subsequent exploitation attempts.
- Detect reconnaissance followed by suspicious process execution.
- Maintain detection rules and investigation procedures as part of the SOC documentation.

---

13. Lessons Learned

This scenario demonstrated the complete SOC workflow for detecting and investigating network reconnaissance activity.

Key lessons learned:

- Windows Security Event Logs can provide useful network telemetry for endpoint-based detection.
- Event Codes 5156, 5157 and 5152 provide complementary visibility into network filtering activity.
- Counting unique destination ports is a useful behavioral indicator for identifying port scanning.
- Detection must be combined with analyst context to distinguish authorized security testing from malicious activity.
- Splunk dashboards make reconnaissance patterns easier to identify.
- Drilldown workflows reduce the time required to move from detection to raw evidence.
- Detection rules should be tuned against normal network behavior to minimize false positives.

Future Detection Enhancement

A future version of the detection should correlate:

Network Reconnaissance → Exploitation Attempt → Process Creation → Persistence

This would allow the SOC to detect not only the reconnaissance stage but also potentially malicious activity that follows it.

---

14. MITRE ATT&CK Mapping

Tactic| Technique| Sub-Technique| ID| Description| Evidence
Reconnaissance| Network Service Scanning| —| T1046| Adversaries may scan systems to identify available network services| Multiple destination ports targeted by Nmap

---

15. References

- "MITRE ATT&CK — T1046: Network Service Scanning" (https://attack.mitre.org/techniques/T1046/)
- "Microsoft — Windows Security Auditing Event 5156" (https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156)
- "Microsoft — Windows Security Auditing Event 5157" (https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5157)
- "Microsoft — Windows Security Auditing Event 5152" (https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5152)
- Splunk Enterprise — SOC Home Lab Documentation

---

16. Appendices

Appendix A — Attack Command

nmap -sS -p 22,80,135,445,3389 192.168.213.138

Appendix B — Relevant Telemetry

EventCode=5156
EventCode=5157
EventCode=5152

Appendix C — Investigation Workflow

Nmap Scan
    ↓
Windows Security Events
    ↓
Splunk Ingestion
    ↓
SPL Detection
    ↓
Reconnaissance Detection
    ↓
Detection Dashboard
    ↓
Investigation Dashboard
    ↓
Raw Event Drilldown
    ↓
Source Validation
    ↓
MITRE T1046
    ↓
Incident Documentation