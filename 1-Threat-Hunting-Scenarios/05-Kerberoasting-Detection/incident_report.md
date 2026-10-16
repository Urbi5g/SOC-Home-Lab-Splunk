# Incident Report: Kerberoasting Detection (T1558.003)

> **SOC Home Lab | Incident Response | Detection Engineering | Atomic Red Team | Splunk Enterprise | Active Directory**

---

## Incident Overview

This report documents the investigation of Kerberos service-ticket activity associated with a potential **Kerberoasting** detection scenario in a controlled Active Directory lab.

The investigation involved manually requesting a Kerberos service ticket for a service principal name (SPN), reviewing Windows Security Event ID **4769** in Splunk, and examining service-ticket encryption metadata.

The investigation identified events containing the RC4-HMAC encryption type (`0x17`) associated with the `svc-mssql` service account. However, the available evidence does not establish that the manually executed request caused those specific events, and RC4 usage alone does not confirm malicious Kerberoasting.

The Atomic Red Team test was also attempted but did not complete because the endpoint could not resolve `raw.githubusercontent.com`.

**Primary MITRE ATT&CK Technique:** T1558.003 — Kerberoasting

> **Environment:** Controlled SOC Home Lab  
> **Production Impact:** None reported  
> **Detection Assessment:** Potentially relevant Kerberos activity identified  
> **Alert Status:** Saved; triggering not verified  
> **Investigation Status:** In Progress — validation required

---

# Case Summary

| Field | Value |
|---|---|
| **Case ID** | SOC-2026-005 |
| **Incident Type** | Potential Kerberoasting Activity |
| **Primary Technique** | T1558.003 |
| **SIEM** | Splunk Enterprise 10.0.2 |
| **Log Source** | Windows Security Event Log |
| **Splunk Index** | `wineventlog` |
| **Event ID** | `4769` |
| **Domain** | `soclab.local` |
| **Domain Controller** | `Ad-DC.soclab.local` |
| **Domain Controller IP** | `192.168.50.10` |
| **Monitored Endpoint** | `DESKTOP-9SMH3UQ` |
| **Observed Requesting Account** | `hdhru@SOCLAB.LOCAL` |
| **Service Account** | `svc-mssql` |
| **Target SPN** | `MSSQLSvc/dc01.soclab.local:1433` |
| **Observed Encryption Type** | `0x17` — RC4-HMAC |
| **Detection Method** | Splunk SPL |
| **Alert Status** | Saved; firing not verified |
| **Report Author** | Huthifa |
| **Case Status** | Open — Investigation In Progress |

---

# Lab Environment

| Component | Description |
|---|---|
| SIEM | Splunk Enterprise 10.0.2 |
| Directory Service | Microsoft Active Directory |
| Domain Controller | `Ad-DC.soclab.local` |
| Domain | `soclab.local` |
| Domain Controller Address | `192.168.50.10` |
| Endpoint | Domain-joined Windows 10 |
| Endpoint Hostname | `DESKTOP-9SMH3UQ` |
| Log Source | Windows Security Events |
| Splunk Index | `wineventlog` |
| Relevant Event | Kerberos Service Ticket Operations — Event ID 4769 |
| Attack Simulation Framework | Atomic Red Team |
| Investigation Platform | Splunk Search & Reporting |

The objective was to evaluate the lab's visibility into Kerberos service-ticket requests and develop a preliminary detection approach for activity potentially associated with Kerberoasting.

---

# Incident Description

Kerberoasting is an Active Directory attack technique in which an attacker requests service tickets for accounts associated with service principal names (SPNs) and attempts to extract or crack the ticket material offline to recover the service account's password.

During this lab exercise, a service ticket was manually requested for the following SPN:

`MSSQLSvc/dc01.soclab.local:1433`

The associated service account identified during the investigation was:

`svc-mssql`

Splunk searches subsequently identified Kerberos service-ticket events containing:

- Event ID `4769`
- Service name `svc-mssql`
- Ticket encryption type `0x17`
- Ticket options `0x40810000`
- Requesting account `hdhru@SOCLAB.LOCAL`

These observations provide relevant material for investigating Kerberos authentication behavior. They do not independently demonstrate password cracking, credential compromise, or a successful malicious attack.

---

# Attack Simulation

## Manual Service-Ticket Request

The following commands were executed in the controlled Windows lab:

```powershell
klist purge

Add-Type -AssemblyName System.IdentityModel

New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dc01.soclab.local:1433"
```

### Command Analysis

| Command | Purpose |
|---|---|
| `klist purge` | Clears cached Kerberos tickets for the current logon session. |
| `Add-Type -AssemblyName System.IdentityModel` | Loads the .NET assembly required by the subsequent PowerShell operation. |
| `KerberosRequestorSecurityToken` | Requests a Kerberos service ticket for the specified SPN. |

The service-ticket request demonstrates the execution of a Kerberos-related operation. It does not, by itself, extract a ticket for offline cracking or prove that a Kerberoasting attack was completed.

## Atomic Red Team Attempt

The following Atomic Red Team test was attempted:

```powershell
Invoke-AtomicTest T1558.003 -TestNumbers 1
```

The prerequisite check indicated that the test prerequisites were met. However, the actual test execution encountered a DNS resolution failure while attempting to retrieve an external PowerShell resource from `raw.githubusercontent.com`.

The subsequent `Invoke-Kerberoast` command was unavailable because the script containing that function had not been retrieved and loaded.

**Execution result:** Incomplete.

The framework's final `Exit code 0` message was not treated as proof of successful attack execution because the output contained errors preventing the intended test from completing.

No successful hash extraction or password cracking is claimed in this report.

---

# Detection Engineering

The investigation used Windows Security Event ID `4769`, which records Kerberos service-ticket request activity.

The initial investigation query was:

```spl
index=wineventlog EventCode=4769 ServiceName="svc-mssql"
| sort _time desc
| table _time, TargetUserName, ServiceName, TicketEncryptionType, IpAddress
```

A more focused query was used to review events associated with RC4-HMAC encryption:

```spl
index=wineventlog sourcetype=XmlWinEventLog EventCode=4769
TicketEncryptionType="0x17"
(TicketOptions="0x40810000" OR TicketOptions="0x40800000" OR TicketOptions="0x40810010")
| table _time host Computer TargetUserName ServiceName TicketEncryptionType TicketOptions
| sort - _time
```

The search returned six events in the observed result set with the following common attributes:

| Field | Observed Value |
|---|---|
| `host` | `Ad-DC` |
| `Computer` | `Ad-DC.soclab.local` |
| `TargetUserName` | `hdhru@SOCLAB.LOCAL` |
| `ServiceName` | `svc-mssql` |
| `TicketEncryptionType` | `0x17` |
| `TicketOptions` | `0x40810000` |

These results show that the indexed data contains events matching the search conditions. The event times have not yet been correlated with the exact execution time of the manual request.

### Detection Documentation

- [SPL Detection Query](./detection/spl_query.md)
- [Alert Configuration](./detection/alert_config.md)

---

# Investigation Findings

## Finding 1 — Kerberos Service-Ticket Activity

Event ID `4769` records Kerberos service-ticket requests on a domain controller. The observed events were associated with the `svc-mssql` service account.

This is relevant to the investigation because service-ticket requests are part of the activity that may be examined when hunting for Kerberoasting.

## Finding 2 — RC4-HMAC Encryption

The observed ticket encryption type was `0x17`, corresponding to RC4-HMAC.

RC4 usage can be a useful investigation signal, particularly when combined with service-account context, requester behavior, unusual request volume, and other supporting evidence.

However, RC4 may also occur in legitimate environments. Its presence alone is not sufficient to classify an event as malicious.

## Finding 3 — Atomic Test Incomplete

The Atomic Red Team test could not complete because an external hostname failed to resolve.

The manual service-ticket request and the incomplete Atomic test must be documented as separate activities. The available evidence does not establish that either activity generated every event returned by the Splunk searches.

## Finding 4 — Alert Validation Pending

A Splunk alert was saved for the detection scenario. Its actual firing behavior has not yet been verified.

The alert must not be reported as successfully triggered until a corresponding alert execution or triggered result is confirmed.

---

# Evidence Review

| Evidence | Location | Purpose |
|---|---|---|
| PowerShell Attack Activity | `evidence/screenshots/powershell_attack.png` | Documents the manual service-ticket request. |
| Kerberos Detection Events | `evidence/screenshots/detection_events.png` | Documents the relevant Splunk search results. |
| SPL Detection Query | `detection/spl_query.md` | Records the detection logic used during investigation. |
| Alert Configuration | `detection/alert_config.md` | Records the saved alert's configuration and validation status. |
| Atomic Test Details | `attack/atomic_test.md` | Documents the attempted Atomic Red Team test and its failure. |

The screenshot paths above are intended evidence locations. The files should be added to the repository before this report is considered fully evidenced.

---

# Investigation Workflow

The investigation followed a practical SOC analyst workflow:

```text
Prepare Controlled Lab
        |
        v
Identify Target Service SPN
        |
        v
Perform Manual Service-Ticket Request
        |
        v
Review Windows Security Event 4769
        |
        v
Inspect Encryption Type and Service Account
        |
        v
Develop and Test SPL Query
        |
        v
Save Alert Configuration
        |
        v
Validate Alert Execution
        |
        v
Correlate Event Timeline
        |
        v
Review Supporting Evidence
        |
        v
Document Findings and Recommendations
```

The investigation focused on the following questions:

- Which account requested the service ticket?
- Which service account and SPN were involved?
- Was Event ID `4769` present in Splunk?
- Which ticket encryption type was recorded?
- Did the event timeline match the manual test execution?
- Did the Atomic Red Team test complete successfully?
- Did the saved Splunk alert trigger?
- Is there evidence of ticket extraction or password cracking?
- What additional validation is required before closing the case?

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID | Relevance |
|---|---|---|---|
| Credential Access | Kerberoasting | **T1558.003** | Primary investigation technique |

## T1558.003 — Kerberoasting

Kerberoasting involves requesting service tickets associated with SPNs and attempting to recover service-account credentials through offline cracking.

The lab investigation examined service-ticket activity and RC4-HMAC encryption metadata relevant to this technique.

The presence of Event ID `4769` or RC4 encryption does not independently establish that the complete technique was executed successfully.

---

# Recommendations

1. **Correlate the timeline:** Compare the exact manual test execution time with the timestamps of the corresponding Event ID `4769` records.
2. **Validate the alert:** Confirm the saved alert's schedule, search window, trigger conditions, and actual execution results.
3. **Improve detection precision:** Evaluate service-ticket volume, distinct SPNs, requester baselines, service-account context, and encryption type rather than relying on RC4 alone.
4. **Review service-account security:** Assess password strength, account privileges, SPN requirements, and whether modern encryption is supported.
5. **Resolve the Atomic test prerequisite issue:** Troubleshoot DNS and external connectivity in the isolated lab before attempting to rerun the test.
6. **Preserve evidence:** Add the actual screenshots and relevant sanitized event details to the repository.
7. **Avoid premature conclusions:** Do not report successful Kerberoasting, credential compromise, or alert triggering without supporting evidence.

---

# Conclusion

This case study established a practical starting point for investigating Kerberos service-ticket activity using Active Directory telemetry and Splunk Enterprise.

The investigation identified six matching RC4-related events in the observed Splunk result set and documented a manual service-ticket request for the `MSSQLSvc/dc01.soclab.local:1433` SPN. The available evidence does not yet prove that the manual request caused those specific events or that credential extraction and cracking occurred.

The Atomic Red Team test remained incomplete because of a DNS resolution failure, and the saved alert's firing behavior remains unverified.

Further timeline correlation and alert validation are required before the case can be classified as a confirmed detection of malicious Kerberoasting.

**Case Status:** Open — Investigation In Progress  
**Primary MITRE Technique:** T1558.003 — Kerberoasting  
**Environment:** Controlled SOC Home Lab  
**Production Impact:** None reported  
**Next Steps:** Timeline correlation, alert validation, and evidence review

---

**Report Author:** Huthifa  
**Project:** SOC Home Lab | Splunk Detection Engineering & Incident Response