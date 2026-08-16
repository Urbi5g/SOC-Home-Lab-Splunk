# 🛡️ SOC Home Lab | Detection Engineering & Threat Hunting using Splunk

![Splunk](https://img.shields.io/badge/Splunk-000000?style=for-the-badge\&logo=splunk)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-555C6E?style=for-the-badge\&logo=kali-linux\&logoColor=white)
![Windows Server](https://img.shields.io/badge/Windows_Server-0078D6?style=for-the-badge\&logo=windows\&logoColor=white)
![Active Directory](https://img.shields.io/badge/Active_Directory-0078D4?style=for-the-badge\&logo=microsoft)
![OPNsense](https://img.shields.io/badge/OPNsense-E94B35?style=for-the-badge)
![Suricata](https://img.shields.io/badge/Suricata-FF0000?style=for-the-badge)
![Sysmon](https://img.shields.io/badge/Sysmon-5C2D91?style=for-the-badge)
![MITRE ATT\&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-ED1C24?style=for-the-badge)
![Status](https://img.shields.io/badge/Lab_Status-Active-success?style=for-the-badge)

---

## 📌 Overview

A practical **Security Operations Center (SOC) home lab** designed to simulate realistic cyber attack scenarios, collect security telemetry, engineer detection rules, perform threat hunting, and investigate security incidents using **Splunk Enterprise**.

The environment combines:

* **Windows Server / Active Directory** for identity and domain-based infrastructure.
* **Windows endpoints** for endpoint telemetry and security event generation.
* **Kali Linux** for adversary emulation and attack simulation.
* **OPNsense Firewall** for network segmentation, traffic filtering, and security enforcement.
* **Suricata IDS/IPS** for network intrusion detection and network security monitoring.
* **Sysmon** for detailed endpoint process, network, and system telemetry.
* **Splunk Enterprise** as the centralized SIEM, detection, investigation, and visualization platform.

The project follows a SOC-oriented workflow:

> **Attack Simulation → Telemetry Collection → Log Ingestion → Detection Engineering → Alert Analysis → Threat Hunting → Incident Investigation → Documentation**

The goal is not only to generate attacks, but to understand **how an analyst detects, investigates, correlates, documents, and responds to suspicious activity across endpoint, identity, and network telemetry**.

---

## 🎯 Key Objectives

* 🎯 **Attack Simulation:** Emulate realistic adversary TTPs aligned with the MITRE ATT&CK framework.
* 🏢 **Identity Monitoring:** Monitor Active Directory authentication and Windows security events.
* 🖥️ **Endpoint Monitoring:** Collect Windows Security Logs and Sysmon telemetry.
* 🌐 **Network Security Monitoring:** Monitor network traffic through OPNsense and Suricata.
* 🔥 **Firewall Monitoring:** Analyze firewall allow/block events and suspicious network connections.
* 🚨 **IDS/IPS Monitoring:** Detect network-based suspicious activity using Suricata.
* 🔍 **Detection Engineering:** Develop, test, and optimize SPL-based detections.
* 🕵️ **Threat Hunting:** Investigate suspicious activity using multiple telemetry sources.
* 📊 **Security Dashboards:** Build SOC-oriented dashboards in Splunk Dashboard Studio.
* 📝 **Incident Response Documentation:** Produce structured SOC Level-1/Level-2 incident reports.
* 🧩 **MITRE ATT&CK Mapping:** Map observed behavior to adversary techniques and tactics.

---

# 🏗️ Architecture & Lab Environment

The lab is designed as a layered SOC environment where security telemetry is generated at the **endpoint, identity, and network layers** and centralized in Splunk.

### Core Architecture

```text
                         ┌──────────────────────┐
                         │     Kali Linux       │
                         │  Adversary Emulator  │
                         │ Nmap / Hydra / etc.  │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │      OPNsense        │
                         │      Firewall        │
                         │ Network Gateway      │
                         └──────────┬───────────┘
                                    │
                       ┌────────────┴────────────┐
                       │                         │
                       ▼                         ▼
              ┌────────────────┐       ┌────────────────┐
              │    Suricata    │       │ Windows Network│
              │    IDS / IPS   │       │   Traffic      │
              └───────┬────────┘       └───────┬────────┘
                      │                         │
                      └────────────┬────────────┘
                                   │
                                   ▼
                    ┌───────────────────────────┐
                    │      Windows Server       │
                    │    Active Directory       │
                    │     Domain Services       │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │      Windows Endpoint     │
                    │ Security Logs + Sysmon    │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │       Splunk Enterprise    │
                    │                            │
                    │  Log Ingestion             │
                    │  Detection Engineering     │
                    │  Threat Hunting            │
                    │  Correlation               │
                    │  Dashboards                │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │       SOC Analyst         │
                    │ Detection → Investigation │
                    │ → Documentation → Response │
                    └───────────────────────────┘
```

---

## 🧱 Lab Components

| Component                   | Technology                                       | Role                                                                   |
| :-------------------------- | :----------------------------------------------- | :--------------------------------------------------------------------- |
| **SIEM**                    | Splunk Enterprise                                | Centralized log ingestion, detection, investigation, and visualization |
| **Identity Infrastructure** | Windows Server + Active Directory                | Domain services, authentication, identity management                   |
| **Endpoint**                | Windows 10/11                                    | Endpoint security telemetry and attack target                          |
| **Endpoint Telemetry**      | Sysmon v15.15                                    | Process, network, file, registry, and system monitoring                |
| **Attacker**                | Kali Linux                                       | Adversary emulation and attack simulation                              |
| **Firewall / Gateway**      | OPNsense                                         | Network routing, filtering, segmentation, and firewall logging         |
| **Network IDS/IPS**         | Suricata                                         | Network intrusion detection and prevention                             |
| **Log Collection**          | Windows Event Logs / Syslog / Security Telemetry | Security event collection                                              |
| **Visualization**           | Splunk Dashboard Studio                          | SOC investigation and detection dashboards                             |
| **Threat Framework**        | MITRE ATT&CK                                     | Adversary behavior classification and mapping                          |

---

# 🔐 Security Monitoring Layers

The environment is divided into multiple telemetry layers.

### 1. Identity Layer

**Windows Server / Active Directory**

Monitored activity includes:

* Successful authentication
* Failed authentication
* Logon type analysis
* Kerberos authentication
* NTLM authentication
* Account activity
* Domain authentication
* Privileged account activity
* Authentication anomalies

Relevant Windows Security Event IDs include:

```text
4624  Successful Logon
4625  Failed Logon
4648  Explicit Credential Logon
4672  Special Privileges Assigned
4688  Process Creation
4768  Kerberos Authentication Ticket Requested
4769  Kerberos Service Ticket Requested
4771  Kerberos Pre-Authentication Failed
4776  NTLM Authentication
```

---

### 2. Endpoint Layer

**Windows + Sysmon**

Sysmon provides detailed endpoint telemetry that can be correlated with Windows Security Logs.

Examples include:

```text
Process Creation
Network Connections
DNS Queries
File Creation
Registry Activity
PowerShell Activity
Process Relationships
```

This layer is used to detect suspicious execution, PowerShell activity, reconnaissance, persistence, and other endpoint-based TTPs.

---

### 3. Network Security Layer

**OPNsense Firewall + Suricata**

OPNsense provides network visibility and enforcement through:

* Firewall allow/deny events
* Network connection logging
* Interface-level visibility
* Traffic filtering
* Network segmentation
* Syslog forwarding

Suricata provides:

* Network intrusion detection
* Signature-based detection
* Suspicious traffic analysis
* IDS/IPS alerts
* Network security telemetry
* EVE JSON / syslog-based security events

---

### 4. SIEM Layer

**Splunk Enterprise**

Splunk acts as the central security analytics platform.

Responsibilities include:

```text
Log Ingestion
      ↓
Normalization
      ↓
Search / SPL
      ↓
Detection Engineering
      ↓
Correlation
      ↓
Alert Analysis
      ↓
Threat Hunting
      ↓
Dashboard Visualization
      ↓
Incident Documentation
```

---

# 📡 Telemetry Sources

The lab currently collects telemetry from multiple security layers:

| Source                    | Telemetry                                   | Security Value                   |
| :------------------------ | :------------------------------------------ | :------------------------------- |
| **Windows Security Logs** | Authentication / process / privilege events | Identity & endpoint detection    |
| **Sysmon**                | Process / network / system telemetry        | Deep endpoint visibility         |
| **Active Directory**      | Domain authentication and identity activity | Identity monitoring              |
| **OPNsense**              | Firewall / network traffic events           | Network visibility & enforcement |
| **Suricata**              | IDS/IPS alerts                              | Network threat detection         |
| **Kali Linux**            | Attack activity                             | Adversary simulation             |
| **Splunk**                | Centralized security analytics              | Detection & investigation        |

---
# ⚔️ Attack Scenarios & Detection Coverage

| ID | Attack Scenario | MITRE ATT&CK | Status | Documentation |
| :---: | :--- | :---: | :---: | :---: |
| 01 | Network Reconnaissance (Nmap) | [T1046](https://attack.mitre.org/techniques/T1046/) | 🟢 Completed | [01-Network-Reconnaissance-Nmap](./01-Network-Reconnaissance-Nmap/) |
| 02 | SSH/RDP Brute Force (Hydra) | [T1110](https://attack.mitre.org/techniques/T1110/) | 🟢 Completed | [02-Brute-Force-Hydra](./02-Brute-Force-Hydra/) |
| 03 | Malicious PowerShell Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | 🟢 Completed | [03-PowerShell-Attack](./03-PowerShell-Attack/) |
| 04 | Active Directory Authentication Monitoring | Multiple | 🟡 In Progress | [docs/active-directory](./docs/active-directory/) |
| 05 | Firewall / Network Security Monitoring | Multiple | 🟡 In Progress | [docs/opnsense](./docs/opnsense/) |
| 06 | Suricata Network Intrusion Detection | Multiple | 🟡 In Progress | [docs/suricata](./docs/suricata/) |
> New attack scenarios will be added as detection content and investigation workflows are developed.

---

# 🔎 Detection Engineering Workflow

```text
             Attack Simulation
                    │
                    ▼
        ┌────────────────────────┐
        │ Endpoint / Identity /  │
        │ Network Telemetry      │
        └────────────┬───────────┘
                     │
                     ▼
              Splunk Ingestion
                     │
                     ▼
             Data Normalization
                     │
                     ▼
              SPL Detection
                     │
                     ▼
             Alert / Finding
                     │
                     ▼
            SOC Investigation
                     │
                     ▼
              Threat Hunting
                     │
                     ▼
           MITRE ATT&CK Mapping
                     │
                     ▼
            Incident Report
                     │
                     ▼
          Detection Improvement
```

---

# 📊 Dashboard & Investigation

### Network Reconnaissance Detection Dashboard

![Network Reconnaissance Detection Dashboard](./01-Network-Reconnaissance-Nmap/screenshots/detection_dashboard.png)

### Recon Investigation Dashboard

![Recon Investigation Dashboard](./01-Network-Reconnaissance-Nmap/screenshots/investigation_dashboard.png)

Future dashboards will cover:

* Active Directory authentication
* Windows security events
* PowerShell activity
* Firewall activity
* Suricata IDS alerts
* Network reconnaissance
* Brute-force activity
* Endpoint process execution
* Cross-source correlation

---

# 📝 Incident Investigation Methodology

Each attack follows a consistent SOC investigation process:

```text
1. Detection
      ↓
2. Alert Validation
      ↓
3. Event Collection
      ↓
4. Timeline Construction
      ↓
5. Source / Destination Analysis
      ↓
6. User / Host Analysis
      ↓
7. MITRE ATT&CK Mapping
      ↓
8. Evidence Collection
      ↓
9. Impact Assessment
      ↓
10. Recommended Response
      ↓
11. Incident Documentation
```

Each incident is documented using a standardized `incident_report.md` structure.

---

# 🧠 Skills Demonstrated

### Splunk / SIEM

* Splunk Enterprise Administration
* SPL Query Development
* Detection Engineering
* Log Analysis
* Data Correlation
* Dashboard Studio
* Security Monitoring

### Windows / Active Directory

* Windows Security Event Analysis
* Active Directory Monitoring
* Authentication Analysis
* Kerberos / NTLM Event Analysis
* Process Creation Analysis
* Windows Security Telemetry

### Network Security

* OPNsense Firewall Administration
* Firewall Rule Analysis
* Network Traffic Monitoring
* Syslog Collection
* Suricata IDS/IPS
* Network Intrusion Detection

### SOC Operations

* Alert Triage
* Threat Hunting
* Incident Investigation
* Evidence Analysis
* MITRE ATT&CK Mapping
* Incident Documentation
* Detection Improvement

---

---

# 🚀 Current Lab Status

| Area                             |                  Status                  |
| :------------------------------- | :--------------------------------------: |
| Splunk Enterprise                |              🟢 Operational              |
| Windows Endpoint Monitoring      |              🟢 Operational              |
| Sysmon Telemetry                 |              🟢 Operational              |
| Kali Linux Attack Simulation     |              🟢 Operational              |
| Network Reconnaissance Detection |               🟢 Completed               |
| Hydra Brute Force Scenario       |               🟢 Completed               |
| Windows Server                   |                 🟢 Added                 |
| Active Directory                 |                 🟢 Added                 |
| OPNsense Firewall                |                 🟢 Added                 |
| Suricata IDS/IPS                 | 🟡 Configuration / Detection Development |
| PowerShell Detection             |              🟡 In Progress              |
| Active Directory Detection       |              🟡 In Progress              |
| Network Security Detection       |              🟡 In Progress              |
| Cross-Source Correlation         |              🟡 In Progress              |

---

# 🎯 Future Development

The lab will continue evolving toward a more realistic SOC environment.

Planned improvements include:

* Advanced Active Directory attack simulations
* Kerberoasting detection
* Password spraying detection
* Privileged account monitoring
* PowerShell threat hunting
* Windows lateral movement detection
* Suricata rule tuning
* Firewall-to-Splunk correlation
* Cross-source detection engineering
* Automated alerting
* Risk-based alert prioritization
* Additional SOC dashboards
* Expanded MITRE ATT&CK coverage
* Detection-as-Code practices

---

# 🏆 Project Goal

The ultimate goal of this project is to build a realistic, documented, and continuously improving **SOC detection engineering laboratory** that demonstrates the ability to:

> **Simulate → Collect → Detect → Correlate → Hunt → Investigate → Document → Improve**

The environment is intentionally built around multiple telemetry sources so that security events can be investigated from different perspectives:

```text
Identity
   +
Endpoint
   +
Network
   +
Firewall
   +
IDS/IPS
   ↓
Splunk SIEM
   ↓
SOC Detection & Investigation
```

This project serves as a practical demonstration of **SOC Level-1/Level-2 analysis, Splunk detection engineering, Windows security monitoring, Active Directory monitoring, network security monitoring, and MITRE ATT&CK-based investigation**.
