# Active Directory Environment

## 1. Overview

This document describes the Active Directory environment deployed as part of
the SOC Home Lab.

The environment is built on Microsoft Windows Server 2025 and provides the
centralized identity, authentication, authorization, and directory services
required by the laboratory.

Active Directory Domain Services (AD DS) and DNS are hosted on the primary
Domain Controller:

`AD-DC.soclab.local`

The laboratory Active Directory domain is:

`soclab.local`

The environment is intentionally designed as a controlled virtualized
laboratory for cybersecurity monitoring, detection engineering, threat
hunting, and SOC investigation workflows.

---

## 2. Active Directory Architecture

The current laboratory environment consists of a single Active Directory
forest containing a single domain.

| Property | Value |
|---|---|
| Forest | `soclab.local` |
| Root Domain | `soclab.local` |
| Domain | `soclab.local` |
| NetBIOS Name | `SOCLAB` |
| Forest Mode | `Windows2025Forest` |
| Domain Mode | `Windows2025Domain` |
| Domain Controller | `AD-DC` |
| Fully Qualified Hostname | `AD-DC.soclab.local` |
| IPv4 Address | `192.168.50.10` |
| Global Catalog | Enabled |
| Read-Only Domain Controller | No |
| Active Directory Site | `Default-First-Site-Name` |

The forest and domain currently contain a single Domain Controller.

---

## 3. Domain Controller

The Active Directory Domain Controller is:

`AD-DC.soclab.local`

The Domain Controller provides the central directory and authentication
services for the laboratory domain.

### Domain Controller Configuration

| Property | Value |
|---|---|
| Hostname | `AD-DC` |
| FQDN | `AD-DC.soclab.local` |
| Domain | `soclab.local` |
| IPv4 Address | `192.168.50.10` |
| Operating System | Windows Server 2025 Standard |
| OS Version | `10.0 (26100)` |
| Global Catalog | Yes |
| Read-Only | No |
| LDAP | Port `389` |
| LDAPS | Port `636` |
| AD Site | `Default-First-Site-Name` |

The Domain Controller is also the Global Catalog server for the current
forest.

---

## 4. Forest Configuration

The laboratory uses a single Active Directory forest.

### Forest Properties

| Property | Value |
|---|---|
| Forest Name | `soclab.local` |
| Root Domain | `soclab.local` |
| Forest Mode | `Windows2025Forest` |
| Domain Naming Master | `AD-DC.soclab.local` |
| Schema Master | `AD-DC.soclab.local` |
| Global Catalog | `AD-DC.soclab.local` |
| Sites | `Default-First-Site-Name` |

No additional domains or cross-forest references are currently configured.

---

## 5. Domain Configuration

The Active Directory domain is:

`soclab.local`

The domain uses the NetBIOS name:

`SOCLAB`

### Domain Properties

| Property | Value |
|---|---|
| DNS Root | `soclab.local` |
| NetBIOS Name | `SOCLAB` |
| Domain Mode | `Windows2025Domain` |
| Domain Controller | `AD-DC.soclab.local` |
| PDC Emulator | `AD-DC.soclab.local` |
| RID Master | `AD-DC.soclab.local` |
| Infrastructure Master | `AD-DC.soclab.local` |
| Replica Domain Controllers | `AD-DC.soclab.local` |

Because the lab currently contains a single Domain Controller, the FSMO
(Flexible Single Master Operations) roles are hosted on `AD-DC`.

---

## 6. Active Directory Organizational Units

The following Organizational Units (OUs) are currently configured.

| Organizational Unit | Distinguished Name |
|---|---|
| Domain Controllers | `OU=Domain Controllers,DC=soclab,DC=local` |
| IT_Department | `OU=IT_Department,DC=soclab,DC=local` |
| Ali ALI | `OU=Ali ALI,OU=IT_Department,DC=soclab,DC=local` |

### OU Structure

```text
SOCLAB.LOCAL
│
├── Domain Controllers
│
└── IT_Department
    │
    └── Ali ALI

The OU structure provides the organizational framework required for managing
users, computers, and Group Policy within the laboratory

## 7. Domain Users

The current Active Directory environment contains the following user
accounts.

| Display Name | SamAccountName | Enabled |
|---|---|---|
| Administrator | `Administrator` | Yes |
| Guest | `Guest` | No |
| krbtgt | `krbtgt` | No |
| huthifa ABU_Alrijal | `kali` | Yes |
| Ayman Ali | `Ali123` | No |

The `Administrator` account is currently enabled and is a member of the
`Domain Admins` security group.

The laboratory user account `kali` is currently enabled.

The `Guest`, `krbtgt`, and `Ali123` accounts are currently disabled according
to the retrieved Active Directory configuration.

---

## 8. Domain Groups

The Active Directory environment contains the standard Windows security
groups provided by the operating system and domain configuration.

Important security groups currently present include:

| Group | Scope | Category |
|---|---|---|
| Domain Admins | Global | Security |
| Domain Users | Global | Security |
| Domain Computers | Global | Security |
| Domain Controllers | Global | Security |
| Enterprise Admins | Universal | Security |
| Schema Admins | Universal | Security |
| Group Policy Creator Owners | Global | Security |
| Protected Users | Global | Security |
| Key Admins | Global | Security |
| Enterprise Key Admins | Universal | Security |
| DnsAdmins | DomainLocal | Security |
| Remote Desktop Users | DomainLocal | Security |
| Event Log Readers | DomainLocal | Security |
| Remote Management Users | DomainLocal | Security |
| OpenSSH Users | DomainLocal | Security |

The environment also contains additional built-in Windows security and
administrative groups.

---

## 9. Domain Admin Membership

The membership of the `Domain Admins` group was verified using PowerShell.

The current membership is:

| Account | Object Type |
|---|---|
| `Administrator` | User |

Current group structure:

```text
Domain Admins
└── Administrator

No other members were returned by the validation command.

. Group Policy Configuration

Two Group Policy Objects (GPOs) are currently configured in the Active
Directory domain.

GPO	ID
Default Domain Policy	31b2f340-016d-11d2-945f-00c04fb984f9
Default Domain Controllers Policy	6ac1786c-016f-11d2-945f-00c04fb984f9
10.1 Default Domain Policy

The Default Domain Policy is the standard domain-level Group Policy
provided by Active Directory.

It is linked to the domain and provides baseline policy settings for domain
members.

10.2 Default Domain Controllers Policy

The Default Domain Controllers Policy provides baseline policy settings for
Domain Controllers.

Additional security hardening and detection-focused Group Policy settings
may be added to the laboratory as the environment evolves.

11. DNS and Active Directory Integration

DNS is an essential component of the Active Directory environment.

The Domain Controller hosts the DNS service for the laboratory domain:

soclab.local

The Domain Controller uses itself as the primary IPv4 DNS server:

192.168.50.10

The local IPv6 loopback address is also configured:

::1

Active Directory relies on DNS for the discovery and resolution of domain
services.

The DNS infrastructure supports services including:

Domain Controller discovery
Kerberos authentication
LDAP service discovery
Domain member discovery
Active Directory replication
Group Policy processing
12. Active Directory Authentication

The Active Directory environment provides centralized authentication for
domain accounts.

The primary authentication infrastructure is provided by:

AD-DC.soclab.local

Windows domain authentication generates security telemetry that can be
collected and analyzed by the SOC monitoring infrastructure.

Important authentication-related Windows Security events include:

Event ID	Description
4624	Successful logon
4625	Failed logon
4634	Logoff
4647	User initiated logoff
4672	Special privileges assigned to new logon

These events are important for authentication monitoring, threat hunting,
and SOC investigation workflows.

13. Active Directory Security Events

The Active Directory environment can generate several categories of
security-relevant Windows events.

13.1 Account Management Events
Event ID	Description
4720	User account created
4722	User account enabled
4725	User account disabled
4726	User account deleted
4738	User account changed
4740	User account locked out
13.2 Group Management Events
Event ID	Description
4728	Member added to a global security group
4729	Member removed from a global security group
4732	Member added to a local security group
4733	Member removed from a local security group
4756	Member added to a universal security group
4757	Member removed from a universal security group

These events provide valuable telemetry for detecting account manipulation,
privilege escalation, unauthorized group membership changes, and other
security-relevant activity.

14. Active Directory and SOC Integration

The Active Directory environment is a core telemetry source for the SOC Home
Lab.

The intended monitoring workflow is:

Windows Server
      |
      v
Active Directory
      |
      +---- Authentication Events
      |
      +---- Account Management Events
      |
      +---- Group Management Events
      |
      +---- Windows Security Events
      |
      +---- Sysmon Telemetry
      |
      v
Splunk
      |
      v
Detection / Investigation / Threat Hunting

Active Directory provides visibility into authentication activity, account
changes, group membership changes, privilege-related activity, and other
security-relevant events.

Detailed Windows event collection and Sysmon configuration are documented
separately in:

logging-sysmon.md

15. Current Active Directory Status
Component	Status
Active Directory Domain Services	Operational
Forest	soclab.local
Domain	soclab.local
Domain Controller	AD-DC.soclab.local
Global Catalog	Enabled
Read-Only Domain Controller	No
DNS Integration	Configured
Organizational Units	Configured
Domain Users	Configured
Security Groups	Configured
Domain Admins	Configured
Group Policy	Configured
FSMO Roles	Hosted by AD-DC
16. Validation & Verification

The Active Directory configuration was validated using native Windows
PowerShell and Active Directory management commands.

16.1 Domain Verification
Get-ADDomain

Confirmed:

Domain: soclab.local
NetBIOS Name: SOCLAB
Domain Mode: Windows2025Domain
PDC Emulator: AD-DC.soclab.local
RID Master: AD-DC.soclab.local
Infrastructure Master: AD-DC.soclab.local
16.2 Forest Verification
Get-ADForest

Confirmed:

Forest: soclab.local
Root Domain: soclab.local
Forest Mode: Windows2025Forest
Global Catalog: AD-DC.soclab.local
Schema Master: AD-DC.soclab.local
Domain Naming Master: AD-DC.soclab.local
16.3 Domain Controller Verification
Get-ADDomainController

Confirmed:

Domain Controller: AD-DC
FQDN: AD-DC.soclab.local
IPv4 Address: 192.168.50.10
Global Catalog: Enabled
Read-Only: No
LDAP: Port 389
LDAPS: Port 636
Operating System: Windows Server 2025 Standard
16.4 Organizational Unit Verification
Get-ADOrganizationalUnit -Filter * |
Select-Object Name, DistinguishedName

Confirmed the following Organizational Units:

Domain Controllers
IT_Department
Ali ALI
16.5 User Verification
Get-ADUser -Filter * |
Select-Object Name, SamAccountName, Enabled

Confirmed the currently configured domain user accounts and their enabled
or disabled state.

16.6 Group Verification
Get-ADGroup -Filter * |
Select-Object Name, GroupScope, GroupCategory

Confirmed the available Active Directory security groups and their scopes.

16.7 Domain Admin Verification
Get-ADGroupMember -Identity "Domain Admins"

Confirmed that the current Domain Admins group contains:

Administrator
16.8 Group Policy Verification
Get-GPO -All |
Select-Object DisplayName, Id

Confirmed the following Group Policy Objects:

Default Domain Policy
Default Domain Controllers Policy
17. Related Documentation

The following documents provide additional information about the Windows
Active Directory environment:

configuration.md — Windows Server operating system, network,
virtualization, and server configuration.
logging-sysmon.md — Windows event logging, Sysmon, and security telemetry
collection.
../../4-SOC-Methodology-Docs/lab-architecture.md — Overall SOC Home Lab
architecture.
../../4-SOC-Methodology-Docs/network-topology.drawio — Editable network
topology diagram.
18. Notes

This Active Directory environment is part of an isolated cybersecurity
laboratory and is intended for authorized testing, detection engineering,
threat hunting, and SOC investigation exercises.

The environment is not intended to represent a production Active Directory
deployment.

The directory structure, users, groups, policies, and security controls may
be expanded as additional SOC Home Lab scenarios are implemented