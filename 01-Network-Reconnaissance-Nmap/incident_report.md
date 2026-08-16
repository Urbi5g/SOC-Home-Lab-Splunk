# Incident Report: Network Reconnaissance / Port Scanning

| Field            | Value                              |
|------------------|------------------------------------|
| **Report ID**    | SOC-2026-001                       |
| **Date**         | 2026-08-16                         |
| **Time (UTC)**   | 14:37                              |
| **Author**       | حذيفة أبو الرجال — SOC Analyst L1 (Lab) |
| **Reviewer**     | N/A — Personal SOC Home Lab        |
| **Classification** | Internal                         |
| **Severity**     | Medium                             |
| **Priority**     | P3                                 |
| **Status**       | Closed                             |
| **Related Alerts** | Network Reconnaissance Detection |

---

## 1. Executive Summary

A controlled network reconnaissance activity was performed against a Windows endpoint within the SOC Home Lab environment using Nmap from an authorized Kali Linux testing machine.

The objective of the simulation was to identify exposed TCP services and validate whether network reconnaissance behavior could be detected through Windows Security Event Logs and analyzed using Splunk Enterprise.

Windows Filtering Platform events were collected and ingested into Splunk. The investigation identified multiple connection attempts originating from the same source IP and targeting multiple destination ports within a short period of time.

The observed behavior was consistent with network service scanning and was mapped to MITRE ATT&CK technique T1046 — Network Service Scanning. The source was subsequently confirmed as the authorized Kali Linux testing machine. No unauthorized compromise or production impact occurred.

---

## 2. Incident Overview

- **Attack Type:** Network Reconnaissance / Network Service Scanning  
- **Attacker IP / Hostname:** 192.168.213.53 (Kali Linux)  
- **Target IP / Hostname:** 192.168.213.138 (Windows Endpoint)  
- **Tools / Malware Used:** Nmap 7.94  
- **Affected Systems:** Windows Endpoint (192.168.213.138)  
- **Business Impact:** No production impact. The activity was performed inside the controlled SOC Home Lab environment.  
- **Initial Vector:** Direct network connectivity from the authorized Kali Linux testing machine to the Windows endpoint followed by TCP port scanning.

### Attack Objective

The simulation was designed to determine whether the SOC monitoring stack could identify reconnaissance behavior based on:

- Multiple destination ports.
- Repeated connection attempts.
- A common source IP.
- Short time intervals between events.
- Windows Filtering Platform telemetry.
- Correlation of network events inside Splunk.

---

## 3. Lab Environment

| Component            | Configuration                     |
|----------------------|-----------------------------------|
| SIEM                 | Splunk Enterprise                 |
| Attacker Machine     | Kali Linux                        |
| Attacker IP          | 192.168.213.53                    |
| Target Endpoint      | Windows                           |
| Target IP            | 192.168.213.138                   |
| Attack Tool          | Nmap 7.94                         |
| Telemetry Source     | Windows Security Event Logs       |
| Relevant Event Codes | 5156, 5157, 5152                  |
| Detection Platform   | Splunk Enterprise                 |
| Investigation        | Splunk Detection & Investigation Dashboards |

### Network Communication

```
Kali Linux (192.168.213.53)
          |
          | TCP SYN Port Scan (Nmap)
          v
Windows Endpoint (192.168.213.138)
```

---

## 4. Attack Simulation

The reconnaissance activity was simulated using Nmap from the authorized Kali Linux testing machine.  
The objective was to identify potentially accessible services and determine which TCP ports were exposed on the Windows endpoint.

### Nmap Command

```bash
nmap -sS -p 22,80,135,445,3389 192.168.213.138
```

The `-sS` option performs a TCP SYN scan. The scan targeted ports commonly associated with network services, including SSH (22), HTTP (80), RPC (135), SMB (445), and RDP (3389).  
The scan generated network connection activity against multiple destination ports on the Windows endpoint.  
The resulting Windows Security telemetry was then used to validate the Splunk detection.

---

## 5. Detection & Alerting

### 5.1 Detection Source

The activity was detected using Splunk Enterprise after Windows Security Event Logs were collected from the Windows endpoint.  
The detection focused on identifying a single source communicating with multiple destination ports within a short period.

### 5.2 Relevant Windows Event Codes

| Event Code | Description                                              | Detection Value                                      |
|------------|----------------------------------------------------------|------------------------------------------------------|
| 5156       | Windows Filtering Platform permitted a connection        | Provides evidence of allowed network communication   |
| 5157       | Windows Filtering Platform blocked a connection          | Provides evidence of blocked network communication   |
| 5152       | Windows Filtering Platform blocked a packet              | Provides additional network filtering telemetry      |

These events provide network telemetry that can be correlated using source address, destination address, destination port, and timestamp.

### 5.3 Detection Logic

The detection identifies potential port scanning by looking for:

- One source IP.
- One target endpoint.
- Multiple destination ports.
- Multiple network events within a short time window.
- Repeated connection attempts.
- A high number of unique destination ports.

The detection principle is:

> **A single host contacting multiple destination ports on the same endpoint within a short period is a potential indicator of network service scanning.**

### 5.4 Splunk SPL Query

```spl
index=main (EventCode=5156 OR EventCode=5157 OR EventCode=5152)
| stats dc(DestinationPort) as unique_dest_ports
    count as connection_count
    values(DestinationPort) as targeted_ports
    values(DestinationIp) as destination_ips
    by SourceIp
| where unique_dest_ports >= 5
| sort - unique_dest_ports
```

**Detection Explanation:**  
The search groups Windows Filtering Platform events by source IP and calculates the number of unique destination ports contacted.  
A source generating connections to a high number of different destination ports (≥5) is treated as a potential network reconnaissance indicator.  
The detection was validated against the controlled Nmap activity generated by the Kali Linux testing machine.

### 5.5 Sigma Rule (Optional)

```yaml
title: Network Reconnaissance - Port Scanning
id: 7d2b4f1e-9a3c-4b8d-9e1a-5c6f2d8a3b7e
status: experimental
description: Detects a single source IP contacting multiple destination ports on a target within a short time window.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 5156
      - 5157
      - 5152
  timeframe: 30s
  condition: selection | count() by SourceIp > 5
fields:
  - SourceIp
  - DestinationIp
  - DestinationPort
level: medium
tags:
  - attack.reconnaissance
  - attack.t1046
```

### 5.6 Alert Configuration

- **Alert Name:** Network Reconnaissance Detection  
- **Schedule:** Scheduled detection (every 1 minute)  
- **Detection Window:** 30 seconds  
- **Trigger Condition:** unique_dest_ports >= 5  
- **Notification:** Email to SOC analyst  
- **Status:** Successfully triggered and tested  

---

## 6. MITRE ATT&CK Mapping

| Tactic           | Technique                  | Sub-Technique | ID      | Description                                                   | Evidence                          |
|------------------|----------------------------|---------------|---------|---------------------------------------------------------------|-----------------------------------|
| Reconnaissance   | Network Service Scanning   | —             | T1046   | Adversaries may scan systems to identify available network services | Multiple destination ports targeted by Nmap |

**Technique Rationale:**  
The activity maps to **T1046 – Network Service Scanning** because the Kali Linux machine performed network probing against multiple ports to identify available network services.

---

## 7. Affected Assets & Impact

| Asset / Hostname   | IP Address     | OS / Service | Criticality | Impact Description                                    |
|--------------------|----------------|--------------|-------------|-------------------------------------------------------|
| Windows Endpoint   | 192.168.213.138 | Windows 10   | Medium      | Received multiple TCP connection attempts to various ports |
| Splunk Enterprise  | Lab Environment | Splunk       | Monitoring  | Collected logs, detected activity, supported investigation |

**Monitoring Infrastructure:**  
Splunk Enterprise was used to collect logs, detect the activity, generate alerts, and support the investigation. It was not a target of the attack.

**Impact Assessment:**  
This was a controlled security exercise performed inside the SOC Home Lab.  
No production infrastructure, real user accounts, or sensitive business data were affected.  
If the same behavior occurred against a production system, it could indicate a precursor to exploitation attempts targeting the identified services.

---

## 8. Investigation Steps

| Step | Action Taken                                        | Findings / Results                                            |
|------|-----------------------------------------------------|---------------------------------------------------------------|
| 1    | Reviewed the Splunk detection                       | Detection identified suspicious network activity             |
| 2    | Identified the source IP                            | Source IP 192.168.213.53 confirmed as Kali Linux             |
| 3    | Identified the target endpoint                      | Target IP 192.168.213.138 confirmed as Windows endpoint      |
| 4    | Reviewed destination ports                          | Ports 22, 80, 135, 445, 3389 were targeted                   |
| 5    | Reviewed event timeline                             | Multiple connection attempts occurred within short time      |
| 6    | Examined raw Windows Security events                | Event IDs 5156, 5157, 5152 observed                          |
| 7    | Correlated allowed and blocked network activity     | Connection attempts were logged consistently                 |
| 8    | Compared observed behavior with Nmap scan           | Activity matched Nmap SYN scan pattern                       |
| 9    | Confirmed source was authorized                     | Kali Linux was approved for security testing                 |
| 10   | Classified the incident                             | Confirmed Authorized Security Testing Activity               |
| 11   | Documented findings                                 | Evidence and detection workflow recorded                     |

---

## 9. Indicators of Compromise (IOCs)

Because this activity was intentionally generated in the SOC Home Lab, these indicators are classified as test indicators rather than confirmed malicious IOCs.

| Type        | Value                    | Context                                          | Source                    |
|-------------|--------------------------|--------------------------------------------------|---------------------------|
| IP          | 192.168.213.53           | Authorized reconnaissance source                 | Windows Security Logs     |
| IP          | 192.168.213.138          | Target Windows endpoint                          | Windows Security Logs     |
| Tool        | Nmap 7.94                | Network scanning tool used during simulation     | Kali Linux                |
| Ports       | 22, 80, 135, 445, 3389   | Ports targeted during the Nmap scan              | Nmap Execution            |
| Event Codes | 5156, 5157, 5152         | Windows network filtering telemetry              | Windows Security Logs     |

---

## 10. Evidence

The investigation used Splunk dashboards and search results to validate the reconnaissance behavior.

### 10.1 Detection Dashboard

![Reconnaissance Detection Dashboard](screenshots/detection_dashboard.png)

**Evidence:** The dashboard provides visibility into the detected reconnaissance activity, including source activity and targeted ports.

### 10.2 Investigation Dashboard

![Reconnaissance Investigation Dashboard](screenshots/investigation_dashboard.png)

**Evidence:** The investigation dashboard provides deeper analysis of the source IP, destination ports, timeline, and raw Windows Security events.

### Additional Evidence

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

## 11. Root Cause Analysis

**5 Whys / Cause & Effect**

1. **Why was reconnaissance activity detected?**  
   The Kali Linux testing machine generated multiple network connection attempts against different destination ports on the Windows endpoint.

2. **Why did the activity generate Windows Security events?**  
   Windows Filtering Platform monitored and recorded the network connection activity.

3. **Why was the activity visible in Splunk?**  
   Windows Security telemetry was collected and ingested into Splunk Enterprise.

4. **Why was the behavior classified as reconnaissance?**  
   The same source contacted multiple destination ports within a short period, matching the expected behavior of network service scanning.

5. **Root Cause:**  
   The SOC Home Lab intentionally allowed the authorized Kali Linux testing machine to perform network scanning against the Windows endpoint to validate detection and investigation capabilities.

> **Note:** This root cause describes the controlled laboratory simulation and does not represent a production security weakness.

---

## 12. Containment, Eradication & Recovery (PICERL)

| Stage            | Action Taken                                      | Responsible      | Status      |
|------------------|---------------------------------------------------|------------------|-------------|
| Containment      | No containment required; source was authorized    | SOC Analyst      | Not Required|
| Eradication      | No malware or compromise identified               | SOC Analyst      | Not Required|
| Recovery         | Windows endpoint remained operational             | Lab Administrator| Completed   |
| Post-Incident    | Detection and investigation workflow documented   | SOC Analyst      | Completed   |
| Improvement      | SPL detection and dashboard workflow reviewed     | SOC Analyst      | Completed   |

---

## 13. Recommendations & Remediation

### Immediate (0–24 hours)
- Validate the source IP whenever a reconnaissance detection triggers.
- Confirm whether the scanning activity is authorized.
- Review targeted ports and associated services.
- Investigate unexpected scanning sources.

### Short-term (1 week)
- Tune the port-scanning threshold based on normal network behavior.
- Correlate Windows Filtering Platform Event Codes 5156, 5157, and 5152.
- Include source IP, destination IP, and destination port information in alerts.
- Maintain drilldown functionality from detection dashboards to raw events.
- Create alerting for repeated reconnaissance from the same source.

### Long-term (1 month)
- Establish a baseline for normal network connection behavior.
- Integrate Windows telemetry with firewall and IDS/IPS telemetry.
- Develop correlation between reconnaissance and subsequent exploitation attempts.
- Detect reconnaissance followed by suspicious process execution.
- Maintain detection rules and investigation procedures as part of the SOC documentation.

---

## 14. Lessons Learned

This scenario demonstrated the complete SOC workflow for detecting and investigating network reconnaissance activity.

**Key lessons learned:**

- Windows Security Event Logs can provide useful network telemetry for endpoint-based detection.
- Event Codes 5156, 5157, and 5152 provide complementary visibility into network filtering activity.
- Counting unique destination ports is a useful behavioral indicator for identifying port scanning.
- Detection must be combined with analyst context to distinguish authorized security testing from malicious activity.
- Splunk dashboards make reconnaissance patterns easier to identify.
- Drilldown workflows reduce the time required to move from detection to raw evidence.
- Detection rules should be tuned against normal network behavior to minimize false positives.

### Future Detection Enhancement

A future version of the detection should correlate:

**Network Reconnaissance → Exploitation Attempt → Process Creation → Persistence**

This would allow the SOC to detect not only the reconnaissance stage but also potentially malicious activity that follows it.

---

## 15. References

- [MITRE ATT&CK — T1046: Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [Microsoft — Windows Security Auditing Event 5156](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156)
- [Microsoft — Windows Security Auditing Event 5157](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5157)
- [Microsoft — Windows Security Auditing Event 5152](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5152)
- Splunk Enterprise — SOC Home Lab Documentation

---

## 16. Appendices

### Appendix A — Attack Command

```bash
nmap -sS -p 22,80,135,445,3389 192.168.213.138
```

### Appendix B — Relevant Telemetry

```
EventCode=5156
EventCode=5157
EventCode=5152
```

### Appendix C — Investigation Workflow

```
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
```

---

## 17. Conclusion

The incident was successfully detected, investigated, and documented.  
The activity was confirmed as an authorized security testing simulation from the Kali Linux machine.  
No real systems were compromised, and the detection capability for network reconnaissance was validated end-to-end.  
All SOC workflow components (log collection, detection, alerting, investigation, and documentation) functioned as intended.