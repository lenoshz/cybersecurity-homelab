# 🛡️ Cybersecurity Homelab Portfolio

> **Goal:** Build a production-grade cybersecurity environment demonstrating offensive security, defensive monitoring, and incident detection capabilities.

---

## 🏗️ Lab Architecture

![Network Diagram](images/network-diagram.png)

### Infrastructure Components:
- **Attack Platform:** Kali Linux 2024.x
- **SIEM/Monitoring:** Security Onion / Wazuh
- **Target Network:**
  - Windows Server 2019 (Active Directory Domain Controller)
  - Windows 10 Client (Domain-joined workstation)
  - Ubuntu Server 22.04 (Web server - Apache/DVWA)
  - Metasploitable 2 (Intentionally vulnerable Linux)
- **Network Security:** pfSense firewall with segmented VLANs

---

## 🎯 Skills Demonstrated

### Offensive Security
- Network reconnaissance and enumeration
- Web application exploitation (OWASP Top 10)
- Active Directory attack chains (Kerberoasting, credential dumping)
- Password cracking and credential attacks
- Privilege escalation techniques

### Defensive Security
- SIEM deployment and configuration
- Log analysis and correlation
- Alert rule creation and tuning
- Incident detection and response
- Network traffic analysis

### Technical Skills
- Virtualization (VMware Workstation Pro)
- Linux/Windows system administration
- Network architecture and segmentation
- Security tool proficiency (Nmap, Metasploit, Burp Suite, Wireshark)
- Professional documentation and reporting

---

## 📂 Project Structure

### [Attack Scenarios](attacks/)
1. [Network Reconnaissance with Nmap](attacks/01-network-recon.md)
2. [Web Application Exploitation](attacks/02-web-exploitation.md)
3. [Active Directory Attack Chain](attacks/03-ad-attack.md)
4. [Password Attack & Detection](attacks/04-password-attack.md)
5. [Privilege Escalation](attacks/05-privilege-escalation.md)

### [Configuration Guides](configurations/)
- [Kali Linux Setup](configurations/kali-setup.md)
- [Security Onion SIEM Deployment](configurations/siem-setup.md)
- [Active Directory Lab Build](configurations/ad-setup.md)
- [Network Segmentation Configuration](configurations/network-setup.md)

### [Detection Engineering](detections/)
- [SIEM Alert Rules](detections/alert-rules.md)
- [Attack Traffic Analysis](detections/traffic-analysis.md)
- [Incident Timeline Examples](detections/incident-timelines.md)

---

## 🚀 Quick Start

### Prerequisites
- VMware Workstation Pro 17+
- Minimum 16GB RAM (32GB recommended)
- 200GB free disk space

### Build Instructions
1. Follow [Lab Setup Guide](LAB-SETUP.md)
2. Deploy VMs from [configurations/](configurations/)
3. Test connectivity and baseline monitoring
4. Execute attack scenarios from [attacks/](attacks/)

---

## 📊 Attack Scenario Examples

### Example 1: Active Directory Kerberoasting
**Objective:** Extract service account credentials from AD environment

**Attack Chain:**
```bash
# 1. Domain enumeration
bloodhound-python -d lab.local -u user -p password -ns 192.168.1.10

# 2. Kerberoasting
GetUserSPNs.py lab.local/user:password -request

# 3. Crack tickets
hashcat -m 13100 tickets.txt wordlist.txt
```

**Detection:** SIEM alerts on: 
- Unusual Kerberos TGS requests
- Multiple SPN queries from single host
- Event ID 4769 anomalies

[Full writeup →](attacks/03-ad-attack.md)

---

## 📈 Lab Evolution Timeline

- **Week 1:** Core infrastructure (Kali, targets, SIEM)
- **Week 2:** Attack scenarios + detection rules
- **Week 3:** Advanced scenarios + documentation polish

---

## 🎓 Related Coursework

This lab supports my **Cybersecurity Engineer Bootcamp** training:
- Foundations of Cybersecurity
- Security Operations & Threat Management
- Identity, Network & Cloud Security
- Ethical Hacking & Digital Forensics

---

## 📫 Contact

**GitHub:** [@lenoshz](https://github.com/lenoshz)  
**LinkedIn:** [Your LinkedIn URL]  
**Email:** [Your professional email]

---

## 📝 License

This project is for educational purposes. All attacks performed in isolated lab environment only.

---

## 🔄 Status

🚧 **Currently Building** - Actively developing attack scenarios and documentation

- [x] Repository structure
- [x] Lab setup documentation
- [ ] Core VM deployment
- [ ] SIEM integration
- [ ] Attack scenario execution
- [ ] Detection rule development
- [ ] Final documentation polish