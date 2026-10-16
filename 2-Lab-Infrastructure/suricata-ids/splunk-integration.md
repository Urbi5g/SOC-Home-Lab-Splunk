# OPNsense and Splunk Integration

## 1. Objective

This integration sends selected OPNsense logs to Splunk Enterprise to support centralized monitoring, investigation, and threat hunting.

## 2. Lab Components

| Component | Configuration |
|---|---|
| Firewall | OPNsense |
| Firewall LAN Address | `192.168.50.1` |
| Splunk Server | `192.168.50.2` |
| Syslog Transport | UDP |
| Syslog Port | `514` |
| SIEM Platform | Splunk Enterprise |

## 3. Log Collection Flow

```text
Lab Network Traffic
        |
        v
OPNsense Firewall
        |
        v
Selected Firewall / System Logs
        |
        v
Remote Syslog (UDP 514)
        |
        v
Splunk Syslog Input
        |
        v
Search, Dashboards, and Alerts
```

The diagram describes the intended data flow. Confirm each stage independently before reporting the integration as operational.

## 4. OPNsense Configuration

In the OPNsense web interface:

1. Open the system logging settings.
2. Locate the remote logging configuration.
3. Configure the Splunk server address as `192.168.50.2`.
4. Configure UDP port `514`.
5. Select the required log categories, such as firewall events and relevant system events.
6. Apply the changes.
7. Generate a controlled test event and inspect the receiving side.

Menu labels may vary between OPNsense versions.

## 5. Splunk Receiver

Confirm that the Splunk server has a configured input capable of receiving the selected syslog traffic.

Validate all of the following:

- The receiving input is enabled.
- The destination IP and UDP port match the OPNsense configuration.
- The host firewall and VMware network allow the traffic.
- Incoming events are assigned to the intended index and sourcetype.
- Event timestamps and source metadata are parsed correctly.

Do not assume that a syslog destination setting on OPNsense automatically creates a receiving input in Splunk.

## 6. Splunk Validation

First, search the index that is actually configured for firewall logs. For example, if firewall events are intentionally stored in `main`:

```spl
index=main
| stats count by host source sourcetype
| sort - count
```

To inspect likely firewall-related events:

```spl
index=main
| search "filterlog" OR "firewall" OR "suricata"
| table _time host source sourcetype _raw
| sort - _time
```

The search terms above are exploratory. Refine them after observing the actual event format, index, and sourcetype.

If the logs are assigned to another index, replace `main` with that index.

## 7. Troubleshooting

If no events appear in Splunk:

1. Confirm the remote logging destination in OPNsense.
2. Confirm that the selected log categories generate events.
3. Verify connectivity between `192.168.50.1` and `192.168.50.2`.
4. Check that Splunk is listening on the configured UDP port.
5. Review VMware network connectivity and host firewall rules.
6. Verify the target index, sourcetype, and event time range.
7. Generate a new test event and repeat the search.

UDP does not provide delivery confirmation, so a configured destination alone does not prove that a log was received.

## 8. Security Considerations

- Limit access to the Splunk management interface.
- Allow only necessary traffic to the syslog receiver.
- Use a dedicated index when appropriate for log separation.
- Protect sensitive event data and exported evidence.
- Consider a reliable or encrypted transport when the deployment requirements justify it.

## 9. Evidence Checklist

- [ ] Remote syslog destination configured.
- [ ] Splunk receiving input verified.
- [ ] Firewall events observed in Splunk.
- [ ] Correct index and sourcetype identified.
- [ ] Evidence screenshot captured.

**Status:** Mark the integration as operational only after confirming that real OPNsense events are visible in Splunk.
