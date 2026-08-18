# Windows Server Configuration

## 1. Overview

This document describes the configuration of the Windows Server used as the
primary Windows infrastructure server in the SOC Home Lab.

The server provides the core Windows infrastructure required for the lab,
including Active Directory Domain Services (AD DS) and DNS.

The server is deployed as a virtual machine using VMware and is integrated
into the isolated SOC laboratory environment.

---

## 2. System Role

| Property | Value |
|---|---|
| Hostname | `AD-DC` |
| Domain | `soclab.local` |
| Server Role | Primary Domain Controller |
| Operating System | Microsoft Windows Server 2025 Standard |
| Architecture | x64 |
| Virtualization Platform | VMware |
| System Model | VMware20,1 |
| Processor Allocation | 2 vCPUs |
| Memory | ~5 GB |
| IPv4 Address | `192.168.50.10` |
| Subnet Mask | `255.255.255.0` |
| Default Gateway | `192.168.50.1` |
| DNS Server | `192.168.50.10` |
| DHCP | Disabled |
| IP Routing | Disabled |

---

## 3. Operating System

The server is running:

```text
Microsoft Windows Server 2025 Standard
Version: 10.0.26100
Build: 26100

Installation Information
Original installation date: 2026-08-09
System type: x64-based PC
System locale: en-US
Time zone configured on the server: UTC-08:00 Pacific Time

The system is configured as a Primary Domain Controller for the `SOCLAB.LOCAL` laboratory domain.

---

## 🖴 4. Virtual Machine Configuration

The Windows Server is deployed as a virtual machine using VMware with the following virtual hardware specifications:

| Virtual Hardware Component | Configuration Details |
| :--- | :--- |
| **Hypervisor** | VMware |
| **Virtual CPU** | 2 vCPUs |
| **Architecture** | x64 |
| **Memory** | ~5 GB |
| **Network Adapter** | Intel(R) 82574L Gigabit Network Connection |
| **Virtual System Model** | VMware20,1 |

*Note: The server is intended to provide Windows infrastructure services within the SOC Home Lab rather than operate as a production system.*

---

## 🏷️ 5. Hostname and Domain

* **Hostname:** `AD-DC`
* **Primary DNS Suffix & AD Domain:** `soclab.local`
* **Logon Server Identifier:** `\\AD-DC`

This establishes the server as the central Windows identity and authentication component of the laboratory environment.

---

## 🌐 6. Network Configuration

The server uses a statically configured IPv4 address.

### IPv4 Configuration
* **IP Address:** `192.168.50.10`
* **Subnet Mask:** `255.255.255.0`
* **Default Gateway:** `192.168.50.1`
* **DHCP:** `Disabled`

### IPv6 Configuration
The network adapter also has a link-local IPv6 address automatically assigned by Windows. 
*IPv6 is not used as the primary addressing mechanism for the SOC Home Lab documentation and detection workflows.*

### DNS Configuration
The server is configured to use:
* `::1`
* `192.168.50.10`

The IPv4 DNS configuration points directly to the server itself (`192.168.50.10`), which is appropriate for a Domain Controller hosting the laboratory DNS service.

## 🛠️ 7. Installed Server Roles and Features

The following Windows Server roles and features were confirmed as installed:

### Core Server Roles
* Active Directory Domain Services (AD DS)
* DNS Server
* File and Storage Services
  * File Server
  * Storage Services

### Management and Administration
* Group Policy Management
* Remote Server Administration Tools (RSAT)
  * AD DS and AD LDS Tools
  * Active Directory PowerShell module
  * Active Directory Administrative Center
  * AD DS Management Tools
  * DNS Server Tools

### Security Components
* Microsoft Defender Antivirus

### Framework and System Components
* .NET Framework 4.8
* Windows PowerShell 5.1
* WoW64 Support
* WCF Services
* TCP Port Sharing

*Additional installed components include Windows Admin Center Setup, System Data Archiver, Wireless LAN Service, and XPS Viewer.*

---

## 👑 8. Domain Controller Configuration

The server is configured as the Primary Domain Controller for **`SOCLAB.LOCAL`**.

> **Reference:** The Active Directory configuration itself is documented separately in [active-directory.md](./active-directory.md). This separation keeps the general Windows Server configuration independent from the detailed Active Directory structure.

---

## 🔒 9. Security Configuration

The following security-related components and tools were confirmed on the server:
* Microsoft Defender Antivirus
* Active Directory Domain Services (AD DS)
* Group Policy Management & RSAT

The server acts as a controlled infrastructure component of the SOC Home Lab. Security monitoring and Windows event collection are documented separately in [logging-sysmon.md](./logging-sysmon.md).

---

## 🏗️ 10. SOC Lab Integration

The Windows Server acts as a core infrastructure component of the SOC Home Lab, providing identity and infrastructure services that generate security telemetry for detection and investigation.

### Lab Integration Architecture
```text
                         SOC Home Lab
                              |
         +--------------------+--------------------+
         |                                         |
Windows AD Environment                     Network Security
         |                                         |
       AD-DC                                   OPNsense
         |                                         |
     AD DS + DNS                               Suricata IDS
         |
  Windows Events
         |
       Sysmon
         |
      Splunk


## 📦 11. Patch Information

The server currently reports the following installed Windows updates:

* `KB5049622`
* `KB5053598`
* `KB5052915`

*These values were collected directly from the Windows Server system configuration.*

---

## 🔍 12. Validation & Verification

The configuration was validated using native Windows PowerShell commands.

### Hostname Verification
```powershell
hostname
* **Result:** `AD-DC`

### Operating System Information
        '''systeminfo
* **Confirmed:** Windows Server 2025 Standard (Build 26100), Primary Domain Controller configuration, `soclab.local` domain membership, static IPv4 configuration, and VMware virtualized environment.

### Network Configuration Verification
            '''ipconfig /all
* **Confirmed:** IPv4 Address (`192.168.50.10`), Subnet Mask (`255.255.255.0`), Gateway (`192.168.50.1`), DNS (`192.168.50.10`), and DHCP Disabled.

### Installed Windows Features
        '''Get-WindowsFeature | Where-Object {$_.InstallState -eq "Installed"}
* **Confirmed:** Installation of AD DS, DNS Server, Group Policy Management, RSAT, Microsoft Defender Antivirus, and other required Windows components.

## 📊 13. Current Status Summary
| Component                        | Status         |
| -------------------------------- | -------------- |
| Windows Server                   |🟢 Operational  |
| Hostname                         | `AD-DC`        |
| Active Directory Domain Services |🟢 Installed    |
| DNS Server                       |🟢 Installed    |
| Domain                           | `soclab.local` |
| Static IPv4                      | Configured     |
| DHCP Client                      |🔴 Disabled     |
| Microsoft Defender Antivirus     |🟢 Installed    |
| RSAT                             |🟢 Installed    |
| Group Policy Management          |🟢 Installed    |
| VMware Virtual Machine           |🟢 Operational    |


## 📁 14. Related Documentation
active-directory.md — Active Directory domain, users, groups, and organizational structure.

logging-sysmon.md — Windows event logging, Sysmon, and security telemetry collection.

../../4-SOC-Methodology-Docs/lab-architecture.md — Overall SOC Home Lab architecture.

../../4-SOC-Methodology-Docs/network-topology.drawio — Editable network topology diagram.