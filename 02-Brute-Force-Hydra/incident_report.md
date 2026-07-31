# Incident Report: Web Login Brute Force Attack

## 1. Incident Overview

A web login brute force attack was simulated against the DVWA vulnerable web application using Hydra.

The attack generated multiple HTTP POST requests against the login endpoint in an attempt to discover valid credentials through repeated username and password combinations.

Splunk SIEM successfully detected the suspicious authentication pattern, generated a High Severity alert, and provided investigation capabilities through dedicated dashboards.

---

# 2. Incident Details

| Field                  | Details                         |
| ---------------------- | ------------------------------- |
| Incident Name          | Web Login Brute Force Attack    |
| Detection Name         | Web Login Brute Force Detection |
| Severity               | High                            |
| Attack Type            | Credential Attack               |
| Target Application     | DVWA Login Portal               |
| Attack Tool            | Hydra                           |
| Log Source             | Apache Access Logs              |
| MITRE ATT&CK Technique | T1110 - Brute Force             |

---

# 3. Attack Description

The attacker performed automated login attempts against the DVWA authentication endpoint:

```
/dvwa/login.php
```

The attack was identified by observing:

* Multiple POST requests within a short time period.
* Repeated login attempts from the same source IP.
* Automated User-Agent behavior.
* Abnormal authentication request frequency.

The activity matches the behavior of a brute force credential attack.

---

# 4. Attack Execution

The attack was simulated using Hydra.

Attack characteristics:

* Tool: Hydra
* Target: DVWA Web Login Page
* Protocol: HTTP POST
* Attack Method: Username and Password Enumeration

The attack execution details are documented in:

```
attack/hydra_commands.txt
```

---

# 5. Detection Logic

The detection rule was created in Splunk to identify repeated login attempts.

Detection methodology:

1. Monitor HTTP POST requests.
2. Filter requests targeting:

```
/dvwa/login.php
```

3. Group events by source IP.
4. Count authentication attempts within a 30-second window.
5. Trigger an alert when the threshold is exceeded.

Detection Query:

```spl
index=main sourcetype=access_combined method=POST uri="/dvwa/login.php"
| bin _time span=30s
| stats count as attempts values(useragent) as useragent earliest(_time) as first_attempt latest(_time) as last_attempt by clientip
| where attempts >= 5
```

---

# 6. Alert Information

Splunk generated the following alert:

| Field              | Value                           |
| ------------------ | ------------------------------- |
| Alert Name         | Web Login Brute Force Detection |
| Severity           | High                            |
| Trigger Type       | Scheduled Alert                 |
| Action             | Email Notification              |
| Detection Category | Web Application Attack          |

The alert notification was successfully delivered to the SOC analyst email.

---

# 7. Investigation Process

After receiving the alert, the analyst performed investigation using the Splunk Investigation Dashboard.

The investigation workflow:

```
Alert Triggered
       |
       |
       v
Detection Dashboard
       |
       |
       v
Analyze Source IP
       |
       |
       v
Investigation Dashboard
       |
       |
       v
Review Events and Indicators
```

---

# 8. Investigation Findings

The investigation identified the following indicators:

## Source IP Analysis

The source IP generated a high number of login attempts against the DVWA login page.

## Timeline Analysis

The activity occurred within a short time window, indicating automated attack behavior.

## User-Agent Analysis

The User-Agent information helped identify automated attack tooling.

## HTTP Request Analysis

The investigation confirmed repeated POST requests to:

```
/dvwa/login.php
```

---

# 9. Indicators of Compromise (IOCs)

| Indicator      | Description                      |
| -------------- | -------------------------------- |
| Source IP      | Attacking client address         |
| URI            | /dvwa/login.php                  |
| HTTP Method    | POST                             |
| User-Agent     | Automated client                 |
| Attack Pattern | Multiple authentication attempts |

---

# 10. Impact Assessment

Since this was a controlled laboratory simulation against DVWA, no real user accounts or production systems were affected.

In a real environment, a successful brute force attack could lead to:

* Unauthorized account access.
* Credential compromise.
* Data exposure.
* Further system compromise.

---

# 11. Recommended Response Actions

SOC analyst recommendations:

1. Block or investigate the source IP.
2. Review successful authentication attempts.
3. Reset compromised credentials if required.
4. Enable Multi-Factor Authentication (MFA).
5. Apply login rate limiting.
6. Implement account lockout policies.
7. Continue monitoring for related activity.

---

# 12. Lessons Learned

This exercise demonstrated the complete SOC workflow:

* Simulating an attack.
* Collecting security logs.
* Engineering a Splunk detection rule.
* Creating automated alerts.
* Performing investigation.
* Documenting incident response procedures.

The scenario improved practical skills in Splunk SIEM monitoring, detection engineering, and SOC Level 1 investigation.
