# Network Architecture Diagram

## Lab Topology Overview

This document provides a comprehensive view of the cybersecurity homelab network architecture, including network topology, IP allocations, port mappings, and traffic flows.

---

## ASCII Network Diagram

```
                              INTERNET
                                 |
                                 |
                         [Physical Router]
                                 |
                                 |
                    ┌────────────┴────────────┐
                    │   VMware NAT Network    │
                    │   192.168.100.0/24      │
                    └────────────┬────────────┘
                                 │
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
        │                        │                        │
   ┌────┴─────┐            ┌────┴─────┐            ┌────┴─────┐
   │  Kali    │            │ Security │            │ Windows  │
   │  Linux   │            │  Onion   │            │ Server   │
   │          │            │          │            │  (DC)    │
   │ .100.10  │            │ .100.50  │            │ .100.40  │
   │ Attacker │            │   SIEM   │            │   AD     │
   └────┬─────┘            └────┬─────┘            └────┬─────┘
        │                       │                       │
        │                       │                       │
────────┴───────────────────────┴───────────────────────┴────────
        │            VMware Virtual Switch              │
────────┬───────────────────────┬───────────────────────┬────────
        │                       │                       │
        │                       │                       │
   ┌────┴─────┐            ┌────┴─────┐            ┌────┴─────┐
   │Metasploi-│            │  Ubuntu  │            │ Windows  │
   │  table   │            │  Server  │            │    10    │
   │          │            │          │            │          │
   │ .100.20  │            │ .100.30  │            │ .100.60  │
   │  Victim  │            │  Web Srv │            │  Client  │
   └──────────┘            └──────────┘            └──────────┘

```

---

## IP Allocation Table

| Hostname | IP Address | OS | Role | Services | Subnet Mask | Gateway |
|----------|------------|-------|------|----------|-------------|----------|
| **Kali Linux** | 192.168.100.10 | Kali Linux 2024.x | Attacker/Pentester | SSH, VNC, Various Tools | 255.255.255.0 | 192.168.100.2 |
| **Metasploitable** | 192.168.100.20 | Ubuntu 8.04 | Vulnerable Target | FTP, SSH, HTTP, SMB, MySQL | 255.255.255.0 | 192.168.100.2 |
| **Ubuntu Server** | 192.168.100.30 | Ubuntu Server 22.04 | Web Server | Apache, SSH, MySQL | 255.255.255.0 | 192.168.100.2 |
| **Windows Server** | 192.168.100.40 | Windows Server 2019/2022 | Domain Controller | AD DS, DNS, DHCP, SMB | 255.255.255.0 | 192.168.100.2 |
| **Security Onion** | 192.168.100.50 | Security Onion 2.x | SIEM/IDS/NSM | Elasticsearch, Kibana, Suricata, Zeek | 255.255.255.0 | 192.168.100.2 |
| **Windows 10** | 192.168.100.60 | Windows 10 Pro | Domain Client | RDP, SMB | 255.255.255.0 | 192.168.100.2 |

**Network Details:**
- **Network:** 192.168.100.0/24
- **Netmask:** 255.255.255.0
- **Gateway:** 192.168.100.2 (VMware NAT)
- **DNS:** 192.168.100.40 (Windows Server DC)
- **DHCP Range:** 192.168.100.100-200 (if enabled)
- **Broadcast:** 192.168.100.255

---

## Port Matrix

### Kali Linux (192.168.100.10)
| Port | Protocol | Service | Purpose |
|------|----------|---------|----------|
| 22 | TCP | SSH | Remote administration |
| 5900 | TCP | VNC | Remote desktop |
| 8080 | TCP | Various | Web proxy/testing |
| 4444 | TCP | Metasploit | Default listener port |
| 1337 | TCP | Custom | Reverse shell listener |

### Metasploitable (192.168.100.20)
| Port | Protocol | Service | Vulnerability |
|------|----------|---------|---------------|
| 21 | TCP | vsftpd 2.3.4 | Backdoor |
| 22 | TCP | SSH | Weak credentials |
| 23 | TCP | Telnet | Unencrypted |
| 25 | TCP | SMTP | Open relay |
| 80 | TCP | Apache | Multiple web vulns |
| 139/445 | TCP | Samba | SMB exploits |
| 3306 | TCP | MySQL | Weak root password |
| 5432 | TCP | PostgreSQL | Default config |
| 6667 | TCP | IRC | Backdoor |
| 8180 | TCP | Tomcat | Default creds |

### Ubuntu Server (192.168.100.30)
| Port | Protocol | Service | Purpose |
|------|----------|---------|----------|
| 22 | TCP | SSH | Secure administration |
| 80 | TCP | Apache/HTTP | Web server |
| 443 | TCP | HTTPS | Secure web server |
| 3306 | TCP | MySQL | Database server |

### Windows Server (192.168.100.40)
| Port | Protocol | Service | Purpose |
|------|----------|---------|----------|
| 53 | TCP/UDP | DNS | Domain name resolution |
| 88 | TCP/UDP | Kerberos | Authentication |
| 135 | TCP | RPC | Remote procedure calls |
| 139 | TCP | NetBIOS | Network basic I/O |
| 389 | TCP/UDP | LDAP | Directory services |
| 445 | TCP | SMB | File sharing |
| 636 | TCP | LDAPS | Secure LDAP |
| 3389 | TCP | RDP | Remote desktop |
| 5985 | TCP | WinRM HTTP | Remote management |
| 5986 | TCP | WinRM HTTPS | Secure remote mgmt |

### Security Onion (192.168.100.50)
| Port | Protocol | Service | Purpose |
|------|----------|---------|----------|
| 22 | TCP | SSH | Administration |
| 443 | TCP | HTTPS | Web interface |
| 5601 | TCP | Kibana | Log visualization |
| 9200 | TCP | Elasticsearch | Search engine |

### Windows 10 (192.168.100.60)
| Port | Protocol | Service | Purpose |
|------|----------|---------|----------|
| 135 | TCP | RPC | Remote procedure calls |
| 139 | TCP | NetBIOS | Network services |
| 445 | TCP | SMB | File sharing |
| 3389 | TCP | RDP | Remote desktop |

---

## Traffic Flow Patterns

### 1. Reconnaissance Phase
```
Kali (.10) ──[ICMP Echo]──> All Hosts
Kali (.10) ──[TCP SYN Scans]──> All Hosts:1-65535
Kali (.10) ──[DNS Queries]──> Windows Server (.40):53
Kali (.10) ──[LDAP Queries]──> Windows Server (.40):389
           └──[Logs]──> Security Onion (.50)
```

### 2. Exploitation Phase
```
Kali (.10) ──[Exploit Traffic]──> Metasploitable (.20):21,22,80,139,445
Kali (.10) ──[HTTP Attacks]──> Ubuntu Server (.30):80,443
Kali (.10) ──[SMB Exploits]──> Windows Server (.40):445
           └──[Alerts]──> Security Onion (.50)
```

### 3. Post-Exploitation Phase
```
Compromised Host ──[Reverse Shell]──> Kali (.10):4444
Kali (.10) ──[C2 Traffic]──> Compromised Host:Various
Kali (.10) ──[Lateral Movement]──> Other Hosts:445,3389,22
           └──[Detection]──> Security Onion (.50)
```

### 4. Monitoring & Detection
```
All Traffic ──[Mirror/Span]──> Security Onion (.50)
Security Onion ──[Suricata IDS]──> Alert Generation
Security Onion ──[Zeek NSM]──> Network Metadata
Security Onion ──[Elasticsearch]──> Log Storage
Analyst ──[Kibana:443]──> Security Onion (.50)
```

---

## Attack Surface Summary

### High Priority Targets

**Metasploitable (192.168.100.20)**
- **Risk Level:** Critical
- **Known Vulnerabilities:** 40+
- **Attack Vectors:** vsftpd backdoor, distcc, UnrealIRCd, Samba, weak MySQL
- **Initial Access:** Multiple RCE opportunities

**Windows Server (192.168.100.40)**
- **Risk Level:** High
- **Attack Vectors:** SMB vulnerabilities, Kerberos attacks, LDAP enumeration
- **Value:** Domain controller - full network compromise
- **Common Attacks:** AS-REP roasting, Kerberoasting, DCSync

**Ubuntu Server (192.168.100.30)**
- **Risk Level:** Medium
- **Attack Vectors:** Web application vulnerabilities, SSH brute force
- **Testing Focus:** OWASP Top 10, SQL injection, XSS, file upload

**Windows 10 (192.168.100.60)**
- **Risk Level:** Medium
- **Attack Vectors:** Phishing simulation, privilege escalation, credential harvesting
- **Lateral Movement:** Domain joined client

---

## Network Segmentation (Future Enhancement)

```
Proposed VLAN Structure:
┌─────────────────────────────────────────┐
│ VLAN 10 - Attack Network (192.168.10.0/24)
│ - Kali Linux
├─────────────────────────────────────────┤
│ VLAN 20 - Victim Network (192.168.20.0/24)
│ - Metasploitable
│ - Ubuntu Server
├─────────────────────────────────────────┤
│ VLAN 30 - Corporate Network (192.168.30.0/24)
│ - Windows Server (DC)
│ - Windows 10 Client
├─────────────────────────────────────────┤
│ VLAN 50 - Management Network (192.168.50.0/24)
│ - Security Onion
└─────────────────────────────────────────┘
```

---

## Quick Reference Commands

### Network Discovery
```bash
# Quick ping sweep
fping -a -g 192.168.100.0/24 2>/dev/null

# Nmap host discovery
nmap -sn 192.168.100.0/24

# ARP scan
arp-scan -l --interface eth0

# NetDiscover
netdiscover -r 192.168.100.0/24
```

### Port Scanning
```bash
# Quick scan all hosts
nmap -T4 -F 192.168.100.10,20,30,40,50,60

# Full TCP scan
nmap -p- -T4 192.168.100.20

# Service version detection
nmap -sV -sC -p- 192.168.100.20

# UDP scan (top 100 ports)
sudo nmap -sU --top-ports 100 192.168.100.40
```

### Connectivity Testing
```bash
# Test specific port
nc -zv 192.168.100.20 80

# Test multiple ports
for port in 21 22 80 139 445; do nc -zv 192.168.100.20 $port; done

# Trace route
traceroute 192.168.100.50

# MTR (combined ping and traceroute)
mtr 192.168.100.40
```

### DNS Testing
```bash
# Query DNS server
nslookup dc01.lab.local 192.168.100.40

# Reverse lookup
dig -x 192.168.100.40 @192.168.100.40

# Zone transfer attempt
dig axfr @192.168.100.40 lab.local
```

---

## Monitoring Points

### Security Onion Capture Configuration

**Interface Setup:**
- **Management Interface:** eth0 (192.168.100.50)
- **Monitor Interface:** eth1 (promiscuous mode)
- **Capture Method:** Full packet capture + metadata

**What to Monitor:**
1. All traffic between Kali and target systems
2. Lateral movement attempts
3. Unusual port scanning activity
4. Exploit attempts and payloads
5. Command and control traffic
6. Data exfiltration attempts

---

## Lab Objectives Mapped to Network

| Objective | Source | Target | Protocol | Purpose |
|-----------|--------|--------|----------|----------|
| Web App Testing | Kali (.10) | Ubuntu (.30) | HTTP/HTTPS | OWASP Top 10 |
| Vulnerability Exploitation | Kali (.10) | Metasploitable (.20) | Multi | Practice CVE exploitation |
| Active Directory Attacks | Kali (.10) | Windows Server (.40) | SMB/LDAP/Kerberos | AD security testing |
| Network Monitoring | Security Onion (.50) | All Traffic | All | SIEM/IDS practice |
| Lateral Movement | Kali (.10) | Win10 (.60) via DC (.40) | RDP/WinRM | Post-exploitation |

---

## Diagram Notation Key

```
┌─────┐
│ Box │  = Virtual Machine
└─────┘

  ───    = Network Connection
  ═══    = Highlighted/Important Path
  ┼      = Network Switch/Hub
 [Box]   = Network Device
  .XX    = Last Octet of IP Address
```

---

## Change Log

| Date | Version | Changes | Author |
|------|---------|---------|--------|
| 2025-12-15 | 1.0 | Initial network diagram and documentation | lenoshz |

---

## Next Steps

1. ✅ Document current flat network topology
2. ⬜ Implement VLAN segmentation
3. ⬜ Add firewall rules between VLANs
4. ⬜ Deploy additional honeypots
5. ⬜ Implement network tap for Security Onion
6. ⬜ Add DMZ for external-facing services

---

**Last Updated:** 2025-12-15  
**Maintained by:** lenoshz  
**Lab Version:** 1.0
