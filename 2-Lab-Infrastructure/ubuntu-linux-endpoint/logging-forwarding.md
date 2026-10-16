# Ubuntu Linux — Log Collection and Splunk Forwarding

## 1. Objective

This document describes the process for collecting Ubuntu Linux telemetry and making it available for investigation in Splunk Enterprise.

The goal is to centralize Linux authentication and system logs alongside Windows and Active Directory telemetry.

## 2. Log Sources

The collection scope may include:

- Authentication and sudo activity.
- System and service messages.
- SSH authentication events, if the SSH service is enabled.
- Additional audit or process telemetry, if explicitly configured.

Common sources include `/var/log/auth.log`, `/var/log/syslog`, and the systemd journal, depending on the operating system and logging configuration.

## 3. Collection Method

Record the actual collection method used on this endpoint.

Possible methods include:

- Splunk Universal Forwarder.
- Syslog forwarding.
- Another explicitly configured log collector.

Do not assume that a forwarder is installed or configured until the endpoint has been inspected.

## 4. Splunk Destination

| Setting | Value |
|---|---|
| Splunk Server | `192.168.50.2` |
| Forwarding Port | `9997` |
| Protocol | TCP, when using the standard Splunk receiving configuration |
| Index | To be verified |
| Sourcetype | To be verified |

The destination and port must match the actual receiving and forwarding configurations.

## 5. Endpoint Validation

Run the following commands on Ubuntu to inspect available log sources and the current forwarding configuration:

```bash
hostname
ip -br address
sudo ss -tnp
```

If Splunk Universal Forwarder is installed, check its service and configuration using the appropriate installation path:

```bash
sudo systemctl status SplunkForwarder
```

The service name and installation path may differ if a different collection method was used.

## 6. Splunk Validation

Search the relevant index in Splunk Search & Reporting. For example, if the events are stored in `main` with sourcetype `syslog`, use:

```spl
index=main sourcetype=syslog
| sort - _time
| table _time host source sourcetype _raw
```

Adjust the index and sourcetype to match the actual ingested events.

Validate that:

- The events originate from the Ubuntu endpoint.
- The timestamps are current and plausible.
- The expected authentication or system activity is present.
- Events continue to arrive after new activity occurs on Ubuntu.

A successful network connection to the Splunk port does not, by itself, prove that events are being ingested.

## 7. Troubleshooting

If events are missing, check:

1. The endpoint's current IP address and connectivity.
2. Whether the collection service is installed and running.
3. The configured forwarding destination and port.
4. The Splunk receiving configuration.
5. Input definitions and file permissions.
6. The index and sourcetype used by the ingested data.
7. The endpoint and Splunk service logs for errors.

## 8. Validation Status

The log sources, collection method, index, sourcetype, and successful forwarding status must be confirmed from the running environment before marking this integration as validated.

## 9. Evidence

Recommended evidence includes:

- The Ubuntu hostname and IP address.
- The actual forwarding configuration, with sensitive details removed.
- The relevant Splunk search results.
- A sample of received Linux authentication or system events.

Do not include passwords, tokens, or other secrets in the repository.
