# Kerberoasting Detection — Splunk SPL Queries

## 1. Overview

This document contains the Splunk Search Processing Language (SPL) queries used to investigate Kerberos service-ticket events and identify potential Kerberoasting indicators in the SOC home lab.

The detection focuses on Windows Security Event ID `4769`, particularly service-ticket requests using RC4-HMAC encryption (`TicketEncryptionType=0x17`).

**Detection objective:** Identify Kerberos service-ticket requests that match the configured RC4-related detection conditions and provide evidence for further investigation.

**Important:** RC4 usage is a detection indicator, not conclusive proof of Kerberoasting.

## 2. Lab Environment

| Component | Value |
|---|---|
| SIEM | Splunk Enterprise 10.0.2 |
| Index | `wineventlog` |
| Sourcetype | `XmlWinEventLog` |
| Event ID | `4769` |
| Domain | `soclab.local` |
| Domain Controller | `Ad-DC.soclab.local` |
| Domain Controller IP | `192.168.50.10` |
| Test Workstation | `192.168.50.126` |
| Observed User | `hdhru@SOCLAB.LOCAL` |
| Observed Service Account | `svc-mssql` |
| MITRE ATT&CK | `T1558.003 — Kerberoasting` |

## 3. Query 1 — Baseline Event Validation

### Purpose

Retrieve Event ID 4769 records without applying RC4-specific filtering. This query validates that Kerberos service-ticket events are available in Splunk and allows the analyst to inspect the fields required for detection.

### SPL Query

```spl
index=wineventlog sourcetype=XmlWinEventLog EventCode=4769
| table _time host TargetUserName ServiceName TicketEncryptionType TicketOptions IpAddress
| sort - _time
```

### Observed Results

The baseline search returned 41 events in the observed result set.

The displayed records included:

- `TargetUserName`: `hdhru@SOCLAB.LOCAL`
- `ServiceName`: `svc-mssql`
- `TicketEncryptionType`: `0x17`
- `TicketOptions`: `0x40810000`
- Source address: `::ffff:192.168.50.126`
- Event source host: `Ad-DC`

Other events contained encryption type `0x12`, demonstrating why the encryption type must be inspected rather than assuming all Event ID 4769 events are RC4-related.

The 41-event count applies to the observed baseline search and does not represent the number of results returned by the scheduled alert search.

## 4. Query 2 — RC4 Kerberos Service-Ticket Investigation

### Purpose

Filter Event ID 4769 records for RC4-HMAC encryption and inspect the relevant user, service, ticket options, and source address.

### SPL Query

```spl
index=wineventlog sourcetype=XmlWinEventLog EventCode=4769
TicketEncryptionType="0x17"
(TicketOptions="0x40810000" OR TicketOptions="0x40800000" OR TicketOptions="0x40810010")
| table _time host TargetUserName ServiceName TicketEncryptionType TicketOptions IpAddress
| sort - _time
```

### Analysis

This query narrows the baseline events using the observed encryption type and selected TicketOptions values.

The analyst should verify the field names and values against the actual Windows Security events collected in Splunk. The TicketOptions conditions are filters used by this lab query; they are not, by themselves, proof of malicious activity.

## 5. Query 3 — Detection Search Used by the Alert

### Purpose

The following SPL represents the detection search configured for the saved alert:

`Kerberoasting - RC4 TGS Request Detection`

### SPL Query

```spl
index=wineventlog sourcetype=XmlWinEventLog EventCode=4769
TicketEncryptionType="0x17"
(TicketOptions="0x40810000" OR TicketOptions="0x40800000" OR TicketOptions="0x40810010")
| where isnotnull(ServiceName) AND NOT like(ServiceName,"%$")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(TargetUserName) as user
    values(ServiceName) as service
    by Computer TicketEncryptionType TicketOptions
| eval dest=Computer
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S")
| eval lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
| eval detection="Kerberoasting SPN Request with RC4 Encryption"
| eval MITRE="T1558.003"
```

### Query Logic

| SPL Component | Purpose |
|---|---|
| `EventCode=4769` | Select Kerberos service-ticket request events |
| `TicketEncryptionType="0x17"` | Select events using RC4-HMAC |
| `TicketOptions` conditions | Restrict the search to the configured values |
| `isnotnull(ServiceName)` | Exclude events without a ServiceName value |
| `NOT like(ServiceName,"%$")` | Exclude service names ending in `$` |
| `stats` | Aggregate matching events and preserve observed users and services |
| `firstTime` and `lastTime` | Record the earliest and latest event times in each group |
| `detection` | Add a descriptive detection label |
| `MITRE` | Add the ATT&CK technique identifier |

### Detection Logic Considerations

The configured aggregation groups events by `Computer`, `TicketEncryptionType`, and `TicketOptions`, while storing user and service values as multivalue fields.

Consequently, one result row may contain multiple users or services. For clearer event-to-user-to-service correlation during investigation, consider grouping by `Computer`, `TargetUserName`, `ServiceName`, `TicketEncryptionType`, and `TicketOptions`.

The `count` field counts events within each group. It does not count distinct service principal names.

The current filter excludes service names ending in `$`. Validate this exclusion against the actual event data and detection requirements before treating it as a comprehensive service-account filter.

## 6. Recommended Investigation Query

For investigations where each result should retain its individual user and service association, use the following query in Search & Reporting:

```spl
index=wineventlog sourcetype=XmlWinEventLog EventCode=4769
TicketEncryptionType="0x17"
(TicketOptions="0x40810000" OR TicketOptions="0x40800000" OR TicketOptions="0x40810010")
| where isnotnull(ServiceName) AND NOT like(ServiceName,"%$")
| stats count min(_time) as firstTime max(_time) as lastTime
    by Computer TargetUserName ServiceName TicketEncryptionType TicketOptions
| rename TargetUserName as user ServiceName as service
| eval dest=Computer
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S")
| eval lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
| eval detection="Kerberoasting SPN Request with RC4 Encryption"
| eval MITRE="T1558.003"
```

This is a recommended investigation-oriented version, not a claim that the saved alert has already been updated. Test it manually before deciding whether to replace the current saved search.

## 7. Alert Configuration Reference

| Setting | Configured Value |
|---|---|
| Alert Name | `Kerberoasting - RC4 TGS Request Detection` |
| Schedule | Every 5 minutes |
| Trigger Condition | When search results are returned |
| Configured Actions | Trigger alert and send an email |
| Execution Status | Not yet verified |
| Email Delivery | Not yet verified |

The saved alert is reported to run every five minutes and to trigger when results are returned. The configured actions include an alert and an email message.

The actual scheduled execution history and successful email delivery have not yet been verified. These must be checked independently in Splunk before claiming that the end-to-end alert workflow works.

The search time range should also be reviewed to ensure that scheduled executions cover the intended period and do not repeatedly process an unnecessarily broad historical range.

## 8. Validation Procedure

1. Run the baseline query manually and verify that Event ID 4769 records are returned.
2. Run the RC4 investigation query and inspect the actual matching events.
3. Run the exact saved alert SPL manually using the intended time range.
4. Compare the output with the expected detection logic and verify the returned fields.
5. Confirm that the saved alert is enabled and scheduled every five minutes.
6. Review the alert execution history for successful scheduled runs.
7. Verify that an actual alert trigger was recorded.
8. Check the configured email action and confirm whether a test or real notification was delivered.
9. Record the validation results and any errors in the alert configuration documentation.

A successful manual search does not establish that a scheduled alert has fired or that its email action has succeeded.

## 9. False Positives and Limitations

Potential benign explanations for RC4-related Kerberos service-ticket requests include legacy applications, services that require older encryption types, and existing domain configurations.

The following limitations apply:

- RC4-HMAC usage alone does not prove Kerberoasting.
- Event ID 4769 alone does not establish malicious intent.
- TicketOptions values are contextual filters, not standalone indicators of compromise.
- A service-ticket request does not prove that a ticket was extracted or cracked.
- The query does not establish whether a password was recovered.
- The current aggregation may combine multiple users and services into one row.
- Detection thresholds and exclusions require validation against normal lab activity.

Investigate the requesting account, service account, source workstation, timestamps, encryption settings, and surrounding authentication events before determining incident severity.

## 10. Evidence

Store the actual collected evidence in the scenario's evidence directory:

```text
evidence/
├── screenshots/
│   ├── detection_events.png
│   └── powershell_attack.png
├── raw_logs/
│   └── splunk_search_results.csv
└── pcaps/
```

The filenames above are intended documentation paths. Include only files that have actually been created and saved.

Recommended evidence:

- A screenshot of the baseline Event ID 4769 results.
- A screenshot of the PowerShell test commands and their actual output.
- Exported Splunk search results, if available.
- Alert execution or trigger evidence once collected.
- Email-delivery evidence, if available and safe to publish.

Review screenshots and exported logs for credentials, tokens, and other sensitive information before publishing them.

## 11. MITRE ATT&CK Mapping

**Technique:** T1558.003 — Kerberoasting.

This mapping describes the threat technique the detection is intended to investigate. It does not establish that the observed activity successfully completed the technique.

## 12. Conclusion

The baseline search confirmed that Event ID 4769 records are available in the lab and that some observed service-ticket events used RC4-HMAC encryption.

A saved alert named `Kerberoasting - RC4 TGS Request Detection` is configured with a five-minute schedule, a trigger condition based on returned results, and alert and email actions.

The alert's successful scheduled execution, actual triggering, and email delivery remain unverified. The detection should therefore be documented as configured but not yet fully validated.

The next step is to test the exact saved alert search, verify its execution history, and confirm the configured notification behavior before marking the alert as operationally validated.
