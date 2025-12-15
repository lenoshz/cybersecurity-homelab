# 🏗️ Complete Lab Setup Guide

## Hardware Requirements

### Minimum Specs
- CPU: 4 cores (Intel i5/Ryzen 5 or better)
- RAM: 16GB
- Storage: 200GB SSD free space
- Host OS: Windows 10/11, Linux, or macOS

### Recommended Specs
- CPU: 6-8 cores (Intel i7/Ryzen 7)
- RAM: 32GB
- Storage: 500GB NVMe SSD

---

## Download All Required Files First

### VMware Workstation Pro
- [Download VMware Workstation Pro](https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html)
- **Version:** 17.x
- Install with default settings

### VM Images & ISOs

#### Kali Linux (Attacker)
```
URL: https://www.kali.org/get-kali/#kali-virtual-machines
File: kali-linux-2024.x-vmware-amd64.7z
Size: ~3.5GB
```

#### Metasploitable 2 (Vulnerable Target)
```
URL: https://sourceforge.net/projects/metasploitable/
File: metasploitable-linux-2.0.0.zip
Size: ~800MB
```

#### Ubuntu Server 22.04 (Web Server)
```
URL: https://ubuntu.com/download/server
File: ubuntu-22.04.x-live-server-amd64.iso
Size: ~2GB
```

#### Windows Server 2019 (AD Domain Controller)
```
URL: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019
File: Windows_Server_2019_Eval.iso
Size: ~5GB
Trial: 180 days
```

#### Windows 10 Enterprise (Domain Client)
```
URL: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise
File: Windows10_Enterprise_Eval.iso
Size: ~5GB
Trial: 90 days
```

#### Security Onion (SIEM)
```
URL: https://github.com/Security-Onion-Solutions/securityonion/blob/master/VERIFY_ISO.md
File: securityonion-2.x.iso
Size: ~3.5GB
```

---

## VM Build Order & Specifications

### VM 1: Kali Linux (Attacker Machine)

**Build Steps:**
1. Extract downloaded `.7z` file
2. Open VMware → File → Open → Select `.vmx` file
3. Edit VM settings:
   - CPUs: 2
   - RAM: 4-8GB
   - Network: Host-only (vmnet1) or NAT
4. Power on VM
5. Default credentials: `kali` / `kali`
6. Update system:
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y bloodhound crackmapexec impacket-scripts

# Install additional tools
sudo apt install -y gobuster nikto sqlmap metasploit-framework
```

7. Set static IP:
```bash
sudo nano /etc/network/interfaces
```
Add:
```
auto eth0
iface eth0 inet static
    address 192.168.100.10
    netmask 255.255.255.0
    gateway 192.168.100.1
```

8. **Snapshot:** "Fresh Install - Updated"

---

### VM 2: Metasploitable 2 (Vulnerable Target)

**Build Steps:**
1. Extract downloaded `.zip`
2. VMware → File → Open → Select `.vmx`
3. Edit VM settings:
   - CPUs: 1
   - RAM: 1-2GB
   - Network: Same as Kali (Host-only/NAT)
4. Power on
5. Default credentials: `msfadmin` / `msfadmin`
6. Check IP: `ifconfig`
7. Set static IP (optional):
```bash
sudo nano /etc/network/interfaces
```
Set to `192.168.100.20`

8. **Snapshot:** "Baseline"

**Verify from Kali:**
```bash
ping 192.168.100.20
nmap -sV 192.168.100.20
```

---

### VM 3: Ubuntu Server 22.04 (Web Server)

**Build Steps:**
1. VMware → Create New VM → Installer disc image (iso)
2. Select Ubuntu Server ISO
3. VM settings:
   - CPUs: 2
   - RAM: 2-4GB
   - Disk: 20GB
   - Network: Same as Kali
4. Install Ubuntu (minimal, OpenSSH server)
5. Set hostname: `webserver`
6. Create user: `labadmin`
7. After install, login and update:
```bash
sudo apt update && sudo apt upgrade -y
```

8. Install Apache + DVWA:
```bash
# Install prerequisites
sudo apt install -y apache2 mysql-server php php-mysqli php-gd libapache2-mod-php git

# Download DVWA
cd /var/www/html
sudo git clone https://github.com/digininja/DVWA.git dvwa
cd dvwa

# Configure
sudo cp config/config.inc.php.dist config/config.inc.php
sudo nano config/config.inc.php
```
Change database password to match your MySQL setup.

```bash
# Set permissions
sudo chown -R www-data:www-data /var/www/html/dvwa
sudo chmod -R 755 /var/www/html/dvwa

# Setup database
sudo mysql
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

9. Access from Kali: `http://192.168.100.30/dvwa`
10. Click "Create/Reset Database"
11. Default login: `admin` / `password`

12. **Snapshot:** "DVWA Configured"

---

### VM 4: Windows Server 2019 (Active Directory)

**Build Steps:**
1. VMware → Create New VM → Windows Server ISO
2. VM settings:
   - CPUs: 2
   - RAM: 4GB minimum
   - Disk: 40GB
   - Network: Same as Kali
3. Install Windows Server 2019 (Desktop Experience)
4. Set administrator password: `P@ssw0rd!Lab`
5. Set static IP:
   - IP: `192.168.100.40`
   - DNS: `127.0.0.1`

6. Install Active Directory Domain Services:
```powershell
# Open PowerShell as Administrator
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to Domain Controller
Install-ADDSForest -DomainName "lab.local" -DomainNetBIOSName "LAB" -InstallDns
```
Server will reboot.

7. Create test users:
```powershell
# After reboot, login as Administrator
New-ADUser -Name "John Doe" -GivenName "John" -Surname "Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@lab.local" -Path "CN=Users,DC=lab,DC=local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true

New-ADUser -Name "SQL Service" -SamAccountName "sqlsvc" -UserPrincipalName "sqlsvc@lab.local" -ServicePrincipalNames "MSSQLSvc/sqlserver.lab.local:1433" -Path "CN=Users,DC=lab,DC=local" -AccountPassword (ConvertTo-SecureString "Service123!" -AsPlainText -Force) -Enabled $true
```

8. **Snapshot:** "AD Configured"

---

### VM 5: Security Onion (SIEM)

**Build Steps:**
1. VMware → Create New VM → Security Onion ISO
2. VM settings:
   - CPUs: 4
   - RAM: 8-12GB (CRITICAL - SIEM needs resources)
   - Disk: 200GB (100GB minimum)
   - Network Adapter 1: Same as Kali (Management)
   - Network Adapter 2: Host-only (Monitor interface - promiscuous mode)

3. Boot from ISO → Install
4. Setup type: **STANDALONE**
5. Follow wizard:
   - Management interface: ens33 (static IP: 192.168.100.50)
   - Monitor interface: ens34 (no IP - promiscuous)
   - Admin email: `admin@lab.local`
   - Web password: Create strong password

6. Wait 20-30 minutes for initial setup

7. Access web interface: `https://192.168.100.50`

8. Configure log sources:
```bash
# From Ubuntu/Windows, send syslogs
# Ubuntu:
sudo apt install rsyslog
sudo nano /etc/rsyslog.conf
```
Add: `*.* @@192.168.100.50:514`
```bash
sudo systemctl restart rsyslog
```

9. **Snapshot:** "Baseline Monitoring"

---

## Network Verification Checklist

From Kali, verify all VMs:
```bash
# Ping test
ping -c 3 192.168.100.20  # Metasploitable
ping -c 3 192.168.100.30  # Ubuntu
ping -c 3 192.168.100.40  # Windows Server
ping -c 3 192.168.100.50  # Security Onion

# Port scan
nmap -sn 192.168.100.0/24  # Network discovery
```

---

## Troubleshooting

### VMs can't ping each other
- Check all VMs on same VMware network (vmnet1 or NAT)
- Verify firewall rules (disable temporarily for testing)
- Check IP addressing (no conflicts)

### Security Onion web interface not accessible
- Verify management interface IP: `ip addr`
- Check firewall: `sudo so-allow` (add your IP)
- Wait - initial setup takes time

### DVWA database errors
- Reset MySQL password
- Check `/var/www/html/dvwa/config/config.inc.php`
- Verify database exists: `sudo mysql -e "SHOW DATABASES;"`

---

## Next Steps

Once all VMs are running:
1. ✅ [Document Your Build](configurations/README.md)
2. ✅ [Verify SIEM is collecting logs](configurations/siem-setup.md)
3. ✅ [Run First Attack Scenario](attacks/01-network-recon.md)

---

## IP Address Reference Table

| VM Name | IP Address | Purpose | Credentials |
|---------|------------|---------|-------------|
| Kali Linux | 192.168.100.10 | Attacker | kali / kali |
| Metasploitable 2 | 192.168.100.20 | Vulnerable Target | msfadmin / msfadmin |
| Ubuntu Server | 192.168.100.30 | Web Server (DVWA) | labadmin / [your password] |
| Windows Server | 192.168.100.40 | AD Domain Controller | Administrator / P@ssw0rd!Lab |
| Security Onion | 192.168.100.50 | SIEM | admin@lab.local / [your password] |

---

## Estimated Build Time

- **VM 1 (Kali):** 30 minutes
- **VM 2 (Metasploitable):** 15 minutes
- **VM 3 (Ubuntu + DVWA):** 45 minutes
- **VM 4 (Windows AD):** 1 hour
- **VM 5 (Security Onion):** 1.5 hours

**Total: ~4 hours** (not including download time)

---

## Resource Usage (All VMs Running)

- **CPU:** 11 cores allocated
- **RAM:** ~24GB allocated
- **Disk:** ~300GB total
- **Network:** 1 virtual network

**💡 Tip:** You don't need all VMs running at once. Start/stop as needed for specific scenarios.