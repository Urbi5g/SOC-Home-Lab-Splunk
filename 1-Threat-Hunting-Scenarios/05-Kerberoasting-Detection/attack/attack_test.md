# Atomic Red Team Test — Kerberoasting (T1558.003)

> **SOC Home Lab | Attack Simulation | Active Directory | PowerShell | Atomic Red Team**

---

## 1. Test Overview

This document records the attempted simulation of **Kerberoasting (MITRE ATT&CK T1558.003)** in a controlled Active Directory lab.

The objective was to generate and investigate Kerberos service-ticket activity associated with a service principal name (SPN), then examine the resulting Windows Security telemetry in Splunk.

The activity consisted of two distinct parts:

1. A manual Kerberos service-ticket request from a domain-joined Windows endpoint.
2. An attempted Atomic Red Team test for T1558.003.

The manual request was performed, and relevant Kerberos events were subsequently identified in Splunk. However, the available evidence does not establish that the manual request caused the specific events returned by the searches.

The Atomic Red Team test did not complete because the endpoint could not resolve `raw.githubusercontent.com`.

> **Test Status:** Incomplete  
> **Environment:** Controlled SOC Home Lab  
> **Primary Technique:** T1558.003 — Kerberoasting  
> **Production Impact:** None reported

---

## 2. MITRE ATT&CK Mapping

| Attribute | Description |
|---|---|
| **Tactic** | Credential Access |
| **Technique** | Kerberoasting |
| **Technique ID** | T1558.003 |
| **Platform** | Windows / Active Directory |
| **Primary Telemetry** | Windows Security Event ID 4769 |
| **Investigation Platform** | Splunk Enterprise |
| **Detection Content Workflow** | Splunk Security Essentials (SSE) |

Kerberoasting involves requesting service tickets associated with service accounts and attempting to recover account passwords through offline cracking of ticket material.

A service-ticket request alone does not demonstrate that ticket extraction or password cracking occurred.

---

## 3. Lab Environment

| Component | Details |
|---|---|
| Active Directory Domain | `soclab.local` |
| Domain Controller | `Ad-DC.soclab.local` |
| Domain Controller IP | `192.168.50.10` |
| Windows Endpoint | `DESKTOP-9SMH3UQ` |
| Requesting Account Observed in Events | `hdhru@SOCLAB.LOCAL` |
| Target Service Account | `svc-mssql` |
| Target SPN | `MSSQLSvc/dc01.soclab.local:1433` |
| SIEM | Splunk Enterprise 10.0.2 |
| Splunk Index | `wineventlog` |
| Relevant Event ID | `4769` |
| Attack Simulation Framework | Atomic Red Team |

The activity was performed in a controlled lab environment for defensive monitoring and detection-engineering practice.

---

## 4. Target Service Principal Name

The target SPN used in the manual service-ticket request was:

```text
MSSQLSvc/dc01.soclab.local:1433
```

The associated service account identified during the investigation was:

```text
svc-mssql
```

A previous SPN lookup using `setspn -Q */*` identified SPNs associated with the `svc-mssql` account, including the SQL Server SPN used in this exercise.

SPNs identify services associated with domain accounts and help Kerberos determine which service principal should receive a requested service ticket.

---

## 5. Manual Kerberos Service-Ticket Request

The following commands were executed in PowerShell on the Windows endpoint:

```powershell
klist purge

Add-Type -AssemblyName System.IdentityModel

New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dc01.soclab.local:1433"
```

### Command Breakdown

#### Step 1 — Clear Cached Kerberos Tickets

```powershell
klist purge
```

This command clears cached Kerberos tickets for the current logon session. It was used to reduce the influence of previously cached tickets during the lab exercise.

It does not disable Kerberos or remove tickets from other users' logon sessions.

#### Step 2 — Load the Required .NET Assembly

```powershell
Add-Type -AssemblyName System.IdentityModel
```

This loads the .NET assembly that provides the `KerberosRequestorSecurityToken` class used in the next step.

#### Step 3 — Request a Service Ticket

```powershell
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dc01.soclab.local:1433"
```

This requests a Kerberos service ticket for the specified SPN through the current security context.

The request is relevant to Kerberoasting investigations because Event ID `4769` records Kerberos service-ticket request activity.

However, the command itself does not establish that a ticket was extracted for offline cracking or that the associated service-account password was recovered.

---

## 6. Atomic Red Team Test Attempt

The following command was used to attempt Atomic Red Team test number 1 for T1558.003:

```powershell
Invoke-AtomicTest T1558.003 -TestNumbers 1
```

The prerequisite check indicated that the test prerequisites were met.

The test execution then attempted to retrieve a PowerShell resource hosted on:

```text
raw.githubusercontent.com
```

The endpoint failed to resolve the hostname, producing the following error:

```text
The remote name could not be resolved: 'raw.githubusercontent.com'
```

Because the external script could not be retrieved and loaded, the subsequent command failed with an error indicating that `Invoke-Kerberoast` was not recognized.

### Observed Failure

| Observation | Result |
|---|---|
| Atomic Test Command | Executed |
| Prerequisite Check | Reported as met |
| External Resource Retrieval | Failed |
| DNS Resolution | Failed for `raw.githubusercontent.com` |
| `Invoke-Kerberoast` Availability | Not available in the session |
| Intended Atomic Test Completion | Not achieved |
| Overall Test Status | Incomplete |

The Atomic execution output later displayed `Exit code 0` and a completion message. This output was not treated as proof that the intended test succeeded because the command output contained errors that prevented the required actions from completing.

**Important:** The Atomic Red Team attempt must be documented as incomplete, not as a successful Kerberoasting simulation.

---

## 7. Troubleshooting Notes

The immediate failure was associated with hostname resolution for the external GitHub-hosted resource.

Potential follow-up checks in the isolated lab include:

- Verify that the endpoint has working DNS resolution for permitted external domains.
- Review the configured DNS server and upstream forwarding path.
- Check whether the lab firewall or network policy blocks the required outbound connection.
- Confirm that the resource is reachable before repeating the test.
- Review the Atomic Red Team test definition and prerequisites before rerunning it.

Connectivity should be tested without weakening the lab's security controls unnecessarily.

The Atomic test should only be marked successful after the intended test actions complete and the expected evidence is verified.

---

## 8. Expected Defensive Telemetry

A Kerberos service-ticket request may generate Windows Security Event ID `4769` on the domain controller, provided the relevant auditing and logging configuration is enabled.

The investigation focused on the following telemetry:

| Event / Field | Purpose |
|---|---|
| Event ID `4769` | Identifies Kerberos service-ticket request activity. |
| `TargetUserName` | Identifies the requesting account as recorded in the event. |
| `ServiceName` | Helps identify the requested service account or service. |
| `TicketEncryptionType` | Indicates the ticket encryption type recorded in the event. |
| `TicketOptions` | Provides additional information about the ticket request. |
| `_time` | Supports event timeline correlation. |
| `Computer` / `host` | Identifies the system that generated or supplied the event. |

The presence and exact field names depend on the Windows event, collection configuration, and field extraction in Splunk.

---

## 9. Splunk Validation

The following query was used to investigate service-ticket events associated with `svc-mssql`:

```spl
index=wineventlog EventCode=4769 ServiceName="svc-mssql"
| sort _time desc
| table _time, TargetUserName, ServiceName, TicketEncryptionType, IpAddress
```

A focused query was also used to inspect RC4-HMAC-related events:

```spl
index=wineventlog sourcetype=XmlWinEventLog EventCode=4769
TicketEncryptionType="0x17"
(TicketOptions="0x40810000" OR TicketOptions="0x40800000" OR TicketOptions="0x40810010")
| table _time host Computer TargetUserName ServiceName TicketEncryptionType TicketOptions
| sort - _time
```

The observed search returned six events containing these common attributes:

| Field | Observed Value |
|---|---|
| `host` | `Ad-DC` |
| `Computer` | `Ad-DC.soclab.local` |
| `TargetUserName` | `hdhru@SOCLAB.LOCAL` |
| `ServiceName` | `svc-mssql` |
| `TicketEncryptionType` | `0x17` |
| `TicketOptions` | `0x40810000` |

These events confirm that matching records were present in the observed Splunk search results. They do not independently confirm that the Atomic test succeeded or that the manual request generated these exact events.

The event timestamps must be correlated with the actual command execution time before a direct causal relationship can be claimed.

---

## 10. Evidence Collection

The following evidence files are intended for the scenario repository:

| Evidence | Path | Purpose |
|---|---|---|
| Manual PowerShell Activity | `evidence/screenshots/powershell_attack.png` | Documents the manual service-ticket request. |
| Splunk Kerberos Events | `evidence/screenshots/detection_events.png` | Shows the relevant Event ID 4769 search results. |

### Manual Request Evidence

![Manual Kerberos Service-Ticket Request](../evidence/screenshots/powershell_attack.png)

**Figure 1 — PowerShell service-ticket request activity.**

### Detection Evidence

![Splunk Kerberos Event Evidence](../evidence/screenshots/detection_events.png)

**Figure 2 — Splunk search results for Kerberos Event ID 4769 and RC4-HMAC-related fields.**

These image references require the actual screenshot files to be present in the specified repository paths.

Do not substitute fabricated terminal output or edited evidence for genuine lab results.

---

## 11. Operational Safety and Scope

This exercise was conducted as part of a controlled defensive lab.

The documented activity includes a manual service-ticket request and an attempted Atomic Red Team test. It does not establish that a complete Kerberoasting attack occurred.

No successful ticket extraction, offline password cracking, or credential compromise is claimed.

Any repeat testing should remain within the authorized lab environment and use only accounts and systems under the lab operator's control.

---

## 12. Results and Limitations

### Confirmed Observations

- A manual Kerberos service-ticket request was performed for the specified SPN.
- A Splunk search returned six events matching the selected RC4-related conditions.
- The observed events included Event ID `4769`, `svc-mssql`, and encryption type `0x17`.
- An Atomic Red Team test for T1558.003 was attempted.
- The Atomic test encountered a DNS resolution failure.
- The Splunk alert was saved, but its triggering behavior has not been verified.

### Outstanding Validation

- Correlate the manual request timestamp with the returned event timestamps.
- Resolve the Atomic test's DNS issue and repeat the test if appropriate.
- Confirm that the expected telemetry is generated during a controlled retest.
- Verify the saved alert's schedule, search window, trigger conditions, and execution history.
- Capture and commit the genuine evidence screenshots.

---

## 13. Conclusion

This test record documents the manual Kerberos service-ticket request, the attempted Atomic Red Team simulation, and the subsequent Splunk investigation.

The observed Event ID `4769` records and RC4-HMAC encryption metadata provide useful material for further Kerberoasting detection work. However, the Atomic test remained incomplete, and the available evidence does not establish a direct causal relationship between the manual request and the six matching events.

The next steps are to validate the event timeline, troubleshoot the failed external resource resolution, verify alert execution, and complete the evidence package.

**Test Status:** Incomplete  
**Primary MITRE Technique:** T1558.003 — Kerberoasting  
**Environment:** Controlled SOC Home Lab  
**Next Steps:** Timeline correlation, Atomic test troubleshooting, alert validation, and evidence review

---

**Author:** Huthifa  
**Project:** SOC Home Lab | Splunk Detection Engineering & Incident Response