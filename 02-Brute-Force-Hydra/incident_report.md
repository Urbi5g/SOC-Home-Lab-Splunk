# Incident Report – Web Login Brute Force Attack

## Executive Summary

A simulated web login brute force attack was conducted against the DVWA login portal using Hydra. Splunk Enterprise successfully detected the malicious activity by identifying multiple HTTP POST authentication attempts from the same source IP within a short time window. A scheduled alert was triggered, an email notification was delivered, and the incident was investigated using custom Splunk dashboards.

---

# Incident Details

| Field          | Value                           |
| -------------- | ------------------------------- |
| Incident Name  | Web Login Brute Force Attack    |
| Severity       | High                            |
| Status         | Closed                          |
| Detection Name | Web Login Brute Force Detection |
| Attack Tool    | Hydra                           |
| Target         | DVWA Login Portal               |
| Log Source     | Apache Access Logs              |
| MITRE ATT&CK   | T1110 – Brute Force             |

---

# Detection Summary

The detection rule monitored HTTP POST requests targeting the DVWA authentication page and grouped events by source IP within a 30-second window. An alert was generated when the number of login attempts exceeded the configured threshold.

Detection Indicators:

* Multiple HTTP POST requests.
* Repeated authentication attempts.
* Single source IP.
* Automated login behavior.

---

# Investigation Summary

The investigation was performed using a dedicated Splunk Investigation Dashboard.

The analyst reviewed:

* Source IP activity
* Login attempt timeline
* Raw Apache Access Logs
* User-Agent information
* HTTP Status Codes
* Detection summary

The collected evidence confirmed the activity as a brute force attack simulation.

---

# Timeline

| Phase            | Description                                                    |
| ---------------- | -------------------------------------------------------------- |
| Attack Execution | Hydra initiated repeated login attempts against DVWA.          |
| Log Collection   | Apache Access Logs recorded all authentication requests.       |
| Detection        | Splunk identified excessive login attempts.                    |
| Alerting         | A scheduled alert was triggered.                               |
| Notification     | Email notification was successfully delivered.                 |
| Investigation    | The incident was analyzed through the Investigation Dashboard. |
| Documentation    | Findings were documented for future reference.                 |

---

# Evidence Collected

The following evidence was collected during the investigation:

* Hydra execution output
* Detection SPL search results
* Triggered Splunk alert
* Email notification
* Detection Dashboard
* Drilldown investigation workflow
* Investigation Dashboard
* Raw Apache Access Log events

---

# MITRE ATT&CK Mapping

| Technique ID | Technique   |
| ------------ | ----------- |
| T1110        | Brute Force |

---

# Impact Assessment

This activity was executed within a controlled SOC Home Lab environment. No production systems or real user accounts were affected.

In a production environment, this attack could result in:

* Credential compromise
* Unauthorized account access
* Privilege escalation
* Lateral movement
* Data exposure

---

# Recommendations

* Enable Multi-Factor Authentication (MFA).
* Implement account lockout policies.
* Apply login rate limiting.
* Monitor authentication logs continuously.
* Block confirmed malicious source IP addresses.
* Review successful login events following brute force activity.

---

# Conclusion

This laboratory exercise demonstrated the complete SOC workflow for detecting and investigating a web login brute force attack using Splunk Enterprise. The project covered attack simulation, detection engineering, alert generation, email notification, dashboard development, incident investigation, and security documentation, providing practical experience aligned with SOC Analyst Level 1 responsibilities.
