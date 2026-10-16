# Windows 10 — Sysmon and Splunk Log Forwarding

## 1. Objective

This document describes the collection and forwarding of Windows endpoint telemetry to Splunk Enterprise.

The purpose is to make endpoint events available for detection engineering, threat hunting, and incident investigation.

## 2. Components

| Component | Role |
|---|---|
| Windows Event Logging | Records operating system and security events |
| Sysmon | Provides additional endpoint telemetry |
| Splunk Universal Forwarder | Forwards configured event data to Splunk |
| Splunk Enterprise | Receives, indexes, and searches events |

## 3. Forwarding Destination

| Setting | Value |
|---|---|
| Splunk Server | `192.168.50.2` |
| Receiving Port | `9997` |
| Protocol | TCP |
| Index | Verify actual configuration |
| Sourcetype | Verify actual configuration |

## 4. Sysmon Validation

Check the Sysmon service:

```powershell
Get-Service Sysmon64
```

Inspect the Sysmon version:

```powershell
C:\Sysmon\Sysmon64.exe -c
```

Confirm the active configuration and relevant event types before documenting the exact telemetry collected.

## 5. Universal Forwarder Validation

Check the forwarder service:

```powershell
Get-Service SplunkForwarder
```

Inspect the configured forwarding destination using the installed Universal Forwarder command-line tool and its actual installation path.

A typical configuration inspection command is:

```powershell
& "$env:ProgramFiles\SplunkUniversalForwarder\bin\splunk.exe" list forward-server
```

If the forwarder is installed in a different directory, adjust the path accordingly.

The expected destination in this lab is `192.168.50.2:9997`, but the command output must be checked to confirm the active configuration.

## 6. Splunk Search Validation

Use the following search as a starting point to inspect Windows event data:

```spl
index=wineventlog
| stats count by host sourcetype
| sort - count
```

To inspect Sysmon process-creation events, if they are indexed in `wineventlog` with the expected sourcetype, use:

```spl
index=wineventlog EventCode=1
| table _time host EventCode Image CommandLine ParentImage User
| sort - _time
```

Adjust the index, sourcetype, and field names to match the actual event data.

## 7. Troubleshooting

If expected events are missing, verify:

1. The endpoint's network connectivity.
2. The Sysmon service and active configuration.
3. The Universal Forwarder service.
4. The forwarding destination and receiving port.
5. The configured Windows event inputs.
6. The target index and sourcetype.
7. The forwarder's internal logs and Splunk search results.

## 8. Evidence

Recommended evidence includes:

- Sysmon service and configuration output.
- Universal Forwarder service status.
- Active forwarding destination.
- Splunk search results showing events from the endpoint.
- A sample of relevant event records.

Remove sensitive information before publishing screenshots or exported logs.

## 9. Validation Status

The forwarding destination is documented from the lab configuration. Current service status, successful event ingestion, and event coverage must be independently verified before declaring the endpoint fully validated.
