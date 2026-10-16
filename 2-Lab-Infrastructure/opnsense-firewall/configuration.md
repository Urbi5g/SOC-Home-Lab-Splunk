# OPNsense Firewall Configuration

## 1. Overview

OPNsense provides firewalling and network security capabilities for the SOC home lab. It separates the lab network from the external network and supports traffic filtering, network troubleshooting, and security monitoring.

## 2. Lab Network Configuration

| Component | Documented Value |
|---|---|
| Firewall Platform | OPNsense |
| Version | 26.7 |
| LAN Interface Address | `192.168.50.1/24` |
| WAN Address | `192.168.190.139` |
| WAN Network | VMware NAT network |
| LAN Network | `192.168.50.0/24` |
| Windows Domain Controller | `192.168.50.10` |
| Splunk Server | `192.168.50.2` |
| Syslog Destination Port | UDP `514` |
| IDS/IPS Platform | Suricata 8.0.6 |

Verify current interface addresses in OPNsense before relying on them, as VMware DHCP or network changes may alter the WAN address.

## 3. Network Roles

### WAN

The WAN interface connects the firewall to the VMware NAT network, providing external connectivity when the host and virtual network permit it.

### LAN

The LAN interface connects lab machines to the internal network `192.168.50.0/24`.

### DHCP and DNS

The lab uses OPNsense for DHCP according to the documented setup. The Windows Server also provides Active Directory DNS services for the `soclab.local` domain.

Domain-joined Windows clients should use the Active Directory DNS server for domain name resolution. Configure external name resolution through the intended DNS forwarding or recursive-resolution design.

## 4. Firewall and Monitoring Components

### Firewall Rules

Review firewall rules for:

- Necessary connectivity between lab systems.
- DNS and domain-controller communication.
- Splunk event-forwarding traffic.
- Restricted access to management interfaces.
- Unnecessary inbound access from external networks.

Document the actual enabled rules rather than assuming default or recommended rules are present.

### Suricata

Suricata is the lab's network intrusion detection and prevention component.

Depending on its configured mode and enabled rulesets, it can generate alerts for suspicious network traffic. Validate whether it is operating in IDS or IPS mode and whether the relevant interfaces are selected for inspection.

## 5. Validation Checklist

- [ ] Confirm the LAN and WAN addresses in the OPNsense interface.
- [ ] Confirm the active DHCP configuration.
- [ ] Verify DNS resolution from a lab endpoint.
- [ ] Review enabled firewall rules.
- [ ] Confirm Suricata service status, operating mode, and monitored interfaces.
- [ ] Confirm that firewall logs are generated.
- [ ] Confirm log forwarding to Splunk.

## 6. Evidence

Suggested screenshots:

- Interface overview.
- LAN and WAN configuration.
- DHCP configuration.
- Firewall rules relevant to the lab.
- Suricata configuration and alert view.

**Status:** Configuration values are documented from the lab notes; verify current settings before marking all checks complete.
