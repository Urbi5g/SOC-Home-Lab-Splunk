# Windows 10 Endpoint — Configuration

## 1. Overview

The Windows 10 endpoint is a domain-joined workstation used to generate Windows security telemetry and support detection-engineering exercises in the SOC Home Lab.

It is used for Active Directory authentication testing, Sysmon telemetry collection, Windows Event Log analysis, and controlled security simulations.

## 2. Host Information

| Property | Value |
|---|---|
| Operating System | Windows 10 Pro — verify current build |
| Hostname | `DESKTOP-9SMH3UQ` |
| Domain | `soclab.local` |
| Observed IPv4 Address | `192.168.50.126` |
| Domain Controller | `Ad-DC.soclab.local` |
| Domain Controller IP | `192.168.50.10` |
| Splunk Server | `192.168.50.2` |
| Forwarding Port | `9997` |
| Endpoint Telemetry | Windows Event Logs and Sysmon |

The hostname and IP address reflect previously observed lab values. Verify the current configuration before using them as evidence of the endpoint's present state.

## 3. Domain Membership

The endpoint is configured as a workstation in the `soclab.local` Active Directory domain.

The domain environment supports authentication monitoring, Group Policy testing, and investigation of Windows security events.

## 4. Telemetry Sources

The monitoring scope includes:

- Windows Security Event Logs.
- Sysmon process-creation events.
- Sysmon file and network-related events, where configured.
- Windows authentication and Kerberos activity.
- PowerShell activity, subject to the enabled logging policy.

The availability and completeness of each event type depend on the active audit policies, Sysmon configuration, and event collection settings.

## 5. Sysmon

Sysmon is used to provide additional endpoint telemetry for investigation and detection engineering.

Previously documented lab configuration:

`C:\Sysmon\sysmonconfig-export.xml`

Verify the active Sysmon service, version, and configuration before treating these settings as current.

## 6. Network and Forwarding

The endpoint's previously observed address was `192.168.50.126`.

The documented Splunk Universal Forwarder destination is:

`192.168.50.2:9997`

Verify the current network settings and forwarder configuration on the VM.

## 7. Verification Commands

Run these commands in PowerShell on the Windows 10 endpoint:

```powershell
hostname
ipconfig
Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber
Get-Service Sysmon64, SplunkForwarder -ErrorAction SilentlyContinue
```

Check the domain membership with:

```powershell
(Get-CimInstance Win32_ComputerSystem) |
    Select-Object Name, Domain, PartOfDomain
```

## 8. Security Monitoring Objectives

The endpoint supports investigation of:

- Process execution.
- PowerShell activity.
- Authentication and Kerberos service-ticket requests.
- Suspicious file creation and network connections.
- Controlled Atomic Red Team simulations.
- Windows event forwarding and SIEM detection.

## 9. Status

The endpoint is documented as part of the SOC lab. Verify the current operating system build, IP address, active Sysmon configuration, and log-forwarding status before considering its configuration fully validated.
