# Web Login Brute Force Detection & Investigation - Splunk SOC Lab

## Overview

This project simulates a real-world Web Login Brute Force attack against a vulnerable web application (DVWA), then demonstrates how a SOC Analyst detects, investigates, and responds to the incident using Splunk SIEM.

The objective of this scenario is to build a complete detection engineering workflow, starting from attack execution, collecting security logs, creating Splunk detection logic, generating alerts, performing investigation, and documenting the incident.

---

# Lab Environment

| Component          | Description                            |
| ------------------ | -------------------------------------- |
| SIEM               | Splunk Enterprise                      |
| Target Application | DVWA (Damn Vulnerable Web Application) |
| Attack Tool        | Hydra                                  |
| Log Source         | Apache Access Logs                     |
| Detection Type     | Web Login Brute Force                  |
| Severity           | High                                   |
| MITRE ATT&CK       | T1110 - Brute Force                    |

---

# Attack Scenario

A brute force attack was simulated against the DVWA login page using Hydra.

The attacker attempts multiple username/password combinations against:

```
/dvwa/login.php
```

The attack generates multiple HTTP POST requests from the same source IP within a short period of time.

The goal of this simulation is to detect abnormal authentication behavior and create a SOC investigation workflow.

---

# Attack Execution

The attack was performed using Hydra to generate repeated login attempts against the DVWA web login portal.

Attack indicators:

* Multiple POST requests to the login endpoint.
* High number of authentication attempts.
* Same source IP generating multiple requests.
* Suspicious automated User-Agent activity.

Attack commands used during the simulation are documented in:

```
attack/hydra_commands.txt
```

---

# Detection Engineering

A Splunk detection rule was created to identify brute force login behavior.

The detection logic:

* Monitors POST requests to the DVWA login page.
* Groups events by source IP.
* Counts login attempts within a 30-second window.
* Triggers when the number of attempts exceeds the defined threshold.

Detection Query:

```
index=main sourcetype=access_combined method=POST uri="/dvwa/login.php"
| bin _time span=30s
| stats count as attempts values(useragent) as useragent earliest(_time) as first_attempt latest(_time) as last_attempt by clientip
| where attempts >= 5
```

The complete SPL query is available in:

```
detection/spl_query.txt
```

---

# Alert Configuration

A scheduled Splunk alert was created for the brute force detection rule.

Alert configuration:

* Alert Name:

```
Web Login Brute Force Detection
```

* Severity:

```
High
```

* Trigger Condition:

```
Number of Results > 0
```

* Action:

```
Email Notification
```

When the detection condition is met, Splunk automatically generates an alert and sends a notification to the SOC analyst.

---

# Detection Dashboard

A dedicated Splunk Dashboard was created to visualize the detected brute force activity.

Dashboard capabilities:

* Total login attempts.
* Source IP analysis.
* Attack timeline visualization.
* Top attacking sources.
* Detection summary.
* Filtering by time range and source IP.

The dashboard helps analysts quickly identify suspicious authentication behavior.

---

# Investigation Workflow

After detecting the alert, the analyst performs investigation using a dedicated Investigation Dashboard.

The workflow:

```
Detection Alert
       |
       |
       v
Detection Dashboard
       |
       |
       v
Select Source IP
       |
       |
       v
Investigation Dashboard
```

The Source IP is passed through a dashboard drilldown token to automatically filter investigation data.

---

# Investigation Dashboard

The investigation dashboard provides detailed analysis of the attack.

Features:

## Attack Timeline

Shows when brute force activity started and how the attempts were distributed over time.

## Raw Login Events

Displays the original web requests related to the attack.

Information includes:

* Timestamp
* Source IP
* HTTP Method
* Requested URI
* HTTP Status
* User-Agent

## User-Agent Analysis

Identifies the client or tool used during the attack.

Examples:

* Hydra
* Browser
* Automated scripts

## HTTP Status Analysis

Provides visibility into HTTP response behavior during the attack.

## Incident Summary

Provides a quick overview:

* Attacker IP
* Number of attempts
* First seen time
* Last seen time
* User-Agent
* Severity
* MITRE Technique

---

# MITRE ATT&CK Mapping

## T1110 - Brute Force

Adversaries may attempt to gain access to accounts by repeatedly trying different passwords or credentials.

This detection focuses on identifying repeated authentication attempts against a web login portal.

---

# Incident Response Recommendations

Recommended SOC actions:

* Block the attacking source IP if malicious activity is confirmed.
* Review affected user accounts.
* Enable multi-factor authentication.
* Implement login rate limiting.
* Monitor for additional suspicious activity from the same source.
* Investigate whether successful authentication occurred.

---

# Project Structure

```
02-Brute-Force-Hydra
│
├── README.md
├── incident_report.md
│
├── attack
│   └── hydra_commands.txt
│
├── detection
│   └── spl_query.txt
│
└── screenshots
    ├── hydra_execution.png
    ├── spl_search.png
    ├── alert_triggered.png
    ├── email_notification.png
    ├── detection_dashboard.png
    ├── drilldown_workflow.png
    ├── investigation_dashboard.png
    └── raw_events.png
```

---

# Skills Demonstrated

* Splunk SIEM Detection Engineering
* SPL Query Development
* Alert Creation and Notification
* Web Attack Detection
* SOC Investigation Workflow
* MITRE ATT&CK Mapping
* Incident Documentation
* Dashboard Development
