# Kerberoasting Detection — Alert Configuration

## 1. Overview

This document describes the Splunk alert configuration used in the Kerberoasting detection scenario.

The alert searches Windows Security Event ID `4769` records for Kerberos service-ticket requests that match the configured RC4-HMAC encryption and TicketOptions conditions.

The purpose is to identify potentially suspicious Kerberos activity and support further investigation.

**Validation status:** The alert configuration has been documented, but successful alert triggering and email delivery have not yet been verified.

## 2. Alert Details

| Setting | Configured Value |
|---|---|
| Alert Name | `Kerberoasting - RC4 TGS Request Detection` |
| SIEM | Splunk Enterprise 10.0.2 |
| Data Index | `wineventlog` |
| Sourcetype | `XmlWinEventLog` |
| Event ID | `4769` |
| Detection Focus | Kerberos service-ticket requests using RC4-HMAC |
| Encryption Type | `0x17` |
| MITRE ATT&CK | `T1558.003 — Kerberoasting` |
| Schedule | Every 5 minutes |
| Trigger Condition | When search results are returned |
| Configured Actions | Trigger alert and send an email |
| Successful Alert Trigger | Not yet verified |
| Email Delivery | Not yet verified |

## 3. Detection SPL

The following query is the detection search reported as configured for the saved alert.

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

### Detection Logic

- `EventCode=4769` selects Kerberos service-ticket request events.
- `TicketEncryptionType="0x17"` selects records using RC4-HMAC.
- The `TicketOptions` conditions restrict the search to the configured values.
- `isnotnull(ServiceName)` excludes events without a ServiceName value.
- `NOT like(ServiceName,"%$")` excludes service names ending with `$`.
- `stats` aggregates matching events and records the first and last observed times.
- `detection` and `MITRE` add descriptive fields to the results.

**Detection limitation:** These conditions identify events for investigation; they do not independently confirm malicious Kerberoasting activity. The current aggregation can combine multiple users and services into a single result because `TargetUserName` and `ServiceName` are stored as multivalue fields rather than included in the grouping keys.

## 4. Scheduling and Trigger Conditions

The saved alert is configured to run every five minutes.

The trigger condition is set to launch the alert when the search returns results.

The following operational details must be verified in the saved alert settings:

- The alert is enabled.
- The configured schedule is active.
- The search time range covers the intended detection window.
- The search completes successfully during scheduled executions.
- The trigger condition behaves as expected when matching results are present.
- Repeated executions do not generate unnecessary duplicate notifications.

A five-minute schedule does not, by itself, prove that the alert has executed successfully or that its time range is appropriate.

## 5. Configured Alert Actions

Two actions are reported as configured:

### 5.1 Trigger Alert

Splunk is configured to trigger the alert when the search returns results.

The actual trigger event must be confirmed through the available alert history or activity records.

### 5.2 Send Email

An email action is configured for the alert.

The following items have not yet been verified:

- Whether the scheduled search successfully triggered the alert.
- Whether Splunk executed the email action.
- Whether the email was accepted by the configured mail service.
- Whether the message reached the intended recipient.

The presence of an email action in the configuration does not establish successful delivery.

## 6. Validation Procedure

Use the following checklist to validate the saved alert.

### Search Validation

- [x] The baseline Event ID 4769 query returned events.
- [x] The observed baseline results included requests associated with `svc-mssql` using encryption type `0x17`.
- [ ] Run the exact saved alert SPL manually.
- [ ] Verify the returned fields and matching events.
- [ ] Review the search time range and ensure it matches the intended detection window.

### Alert Validation

- [x] Alert name identified.
- [x] Five-minute schedule reported.
- [x] Trigger condition reported as results returned.
- [x] Alert and email actions reported as configured.
- [ ] Confirm the alert is enabled.
- [ ] Verify successful scheduled executions.
- [ ] Confirm that an actual alert trigger was recorded.
- [ ] Confirm that the email action executed.
- [ ] Verify email delivery independently.

### Evidence Collection

When available, retain:

- A screenshot of the saved alert configuration.
- A screenshot of the exact detection search results.
- Evidence of a successful scheduled execution.
- Evidence of an actual triggered alert.
- Email-delivery evidence, with sensitive information removed.

Only mark a checklist item complete when it has been verified.

## 7. False Positives and Tuning Considerations

RC4-HMAC Kerberos service-ticket requests can occur in legitimate environments, particularly where legacy applications or services use older encryption configurations.

Potential investigation factors include:

- Whether the service normally uses RC4.
- Whether the requesting account regularly accesses the service.
- Whether the source workstation is expected.
- Whether the activity is unusual for the account or service.
- Whether other suspicious authentication events occurred around the same time.

The current search uses selected TicketOptions values and excludes service names ending in `$`. These filters should be evaluated against the lab's actual data and expected detection requirements.

The current query does not use a distinct-service threshold. Its `count` field counts matching events per aggregation group, not distinct service principal names.

Do not classify an event as a confirmed attack solely because its encryption type is `0x17`.

## 8. MITRE ATT&CK Mapping

**Technique:** T1558.003 — Kerberoasting.

This mapping identifies the threat technique the detection is intended to investigate. It does not prove that a ticket was extracted, a password was cracked, or an account was compromised.

## 9. Current Status

| Validation Item | Status |
|---|---|
| Relevant Event ID 4769 data observed | Confirmed |
| RC4-related records observed | Confirmed |
| Alert configuration details documented | Confirmed from reported settings |
| Scheduled execution verified | Pending |
| Actual alert trigger verified | Pending |
| Email action execution verified | Pending |
| Email delivery verified | Pending |
| End-to-end detection test | Pending |

## 10. Conclusion

The Splunk alert `Kerberoasting - RC4 TGS Request Detection` is reported to be configured with a five-minute schedule, a trigger condition based on returned search results, and alert and email actions.

The baseline search returned Event ID 4769 records, including observed service-ticket requests associated with `svc-mssql` using RC4-HMAC encryption.

However, the successful execution of the scheduled alert, the occurrence of an actual trigger, and the delivery of the email notification have not yet been verified.

The alert should therefore be documented as **Configured — Validation Pending** until its execution history, trigger behavior, and email delivery have been checked.

These validation steps are necessary before declaring the detection operationally tested.