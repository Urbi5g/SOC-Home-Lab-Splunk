# SOC Home Lab — Infrastructure Overview

## 1. Overview

This document describes the infrastructure used in the SOC Home Lab for security monitoring, log collection, threat detection, and incident investigation.

The environment includes a firewall, a Windows Active Directory environment, a Splunk SIEM server, a Windows 10 endpoint, and an Ubuntu Linux endpoint.

The lab is designed to support practical Blue Team activities, including log analysis, detection engineering, threat hunting, and incident response.

## 2. Lab Components

| Component | Role | Address / Identifier |
|---|---|---|
| OPNsense | Firewall, routing, and network services | `192.168.50.1` |
| Splunk Enterprise | SIEM and log analysis | `192.168.50.2` |
| Active Directory Domain Controller | AD, DNS, and Windows security events | `192.168.50.10` |
| Windows 10 Endpoint | Domain workstation and Windows telemetry source | `192.168.50.126` |
| Ubuntu Linux Endpoint | Linux telemetry and authentication-log analysis | `huthifa-virtual-machine` |
| Kali Linux | Security testing within the lab | `192.168.50.137` |

The addresses above reflect previously observed lab values and should be revalidated if the network configuration changes.

## 3. Network Architecture

The lab uses a dedicated internal network:

- Network: `192.168.50.0/24`
- Default gateway: `192.168.50.1`
- Splunk server: `192.168.50.2`
- Domain Controller: `192.168.50.10`

The Windows domain is `soclab.local`.

The Windows endpoint communicates with the Active Directory environment and generates security telemetry for investigation. Linux telemetry is also collected for cross-platform monitoring.

## 4. SIEM and Log Collection

Splunk Enterprise is the central log analysis platform.

The lab uses log forwarding and event collection to make endpoint activity searchable in Splunk.

The documented forwarding destination for the Windows Universal Forwarder is:

`192.168.50.2:9997`

The actual forwarding configuration and successful ingestion must be validated separately for each endpoint.

## 5. Monitoring Objectives

The infrastructure supports the following activities:

- Windows Security Event Log analysis.
- Sysmon process and network telemetry analysis.
- Linux authentication and system-log analysis.
- Active Directory authentication monitoring.
- Kerberos service-ticket investigation.
- Suspicious process execution detection.
- Network reconnaissance and authentication-attack detection.
- Incident documentation and evidence collection.

## 6. Validation Requirements

For each endpoint, document:

- Operating system and version.
- Hostname and current IP address.
- Network configuration.
- Relevant log sources.
- Forwarding configuration.
- Splunk index and sourcetype.
- Evidence of successful event ingestion.

## 7. Security and Scope

All testing is intended for the isolated, authorized home lab.

Do not publish passwords, authentication tokens, private keys, or other sensitive information in the repository.

## 8. Maintenance

Update this document whenever a lab VM is added, removed, renamed, or reconfigured.

Validate addresses and forwarding settings before relying on this document during an investigation.
