# Ubuntu Linux Endpoint — Configuration

## 1. Overview

Ubuntu Linux is included in the SOC Home Lab as a Linux endpoint and telemetry source.

The endpoint provides an environment for investigating Linux authentication activity, privilege-related events, system logs, and suspicious command execution.

## 2. Host Information

| Property | Value |
|---|---|
| Operating System | Ubuntu Linux |
| Hostname | `huthifa-virtual-machine` |
| Virtualization Platform | VMware Workstation |
| IP Address | To be verified |
| Subnet | To be verified |
| Default Gateway | To be verified |
| DNS Server | To be verified |
| CPU / Memory | To be documented |
| SIEM | Splunk Enterprise |
| Splunk Server | `192.168.50.2` |

The hostname is based on observed lab log data. Verify the current hostname, operating system release, network address, and VM resources before treating this table as a complete configuration record.

## 3. Network Configuration

The Ubuntu endpoint participates in the home lab network.

The intended configuration allows the endpoint to communicate with the Splunk server for centralized log collection.

Verify the current address and routing configuration using:

```bash
hostnamectl
ip -br address
ip route
resolvectl status
```

Some Ubuntu versions may not have `resolvectl`; if unavailable, inspect the active network configuration using the appropriate system tools.

## 4. Security Monitoring Purpose

The endpoint supports investigation of:

- Linux authentication events.
- SSH login activity, when SSH is enabled.
- Sudo session activity.
- System service and operational events.
- Process execution, when suitable telemetry is configured.
- Log forwarding and ingestion troubleshooting.

## 5. Expected Log Sources

Potential log sources include:

| Log Source | Purpose |
|---|---|
| `/var/log/auth.log` | Authentication and privilege-related activity on systems using this file |
| `/var/log/syslog` | General system and service messages on systems using this file |
| systemd journal | System and service logs, depending on the collection method |

Actual log paths depend on the Ubuntu release and logging configuration.

## 6. Verification

Before considering the endpoint fully integrated, verify:

- The OS version and hostname.
- The current IP address and default gateway.
- The availability of the relevant log sources.
- The configured log collection method.
- Successful ingestion of Linux events into Splunk.

## 7. Security Considerations

Only collect logs required for the lab's monitoring objectives.

Review exported logs before publishing them to ensure that sensitive information is not exposed.

## 8. Status

The Ubuntu endpoint is documented as part of the lab infrastructure. Its current hardware allocation, network configuration, and end-to-end log forwarding status must be verified against the running VM.
