# Networking

## Tools
**LAN / WAN**

**OSI Model**

**TCP / IP Model**

**Network Protocols**

**IP v4 & IP v6**

**TCP**

**UDP**

**ICMP**

**Ports and Services**

**Routing & Switching**

**NAT / PAT**

**DNS**

**Network segmentation**

**Subnetting**

**VLANS**

## Tools

**Kali Linux**

**Wireshark**

**TCPDUMP**

**Netcat**

**Netstat**

**Nmap**

**Dig**

**Nslookup**

**Whois**

# Application Stack

## Topics

**Client Server Model**

**App and Web Servers**

**Application Architecture**

**Databases (Relational / Non-relational)**

**SQL basics RBAC (Role based access control)**

**Command Line Basics**

**Programming w/ Python**

**Version Control Basics**

**Virtual Environments**

**Cloud Security (IaaS / PaaS / Saa / Shared Responsibility / SLAs)**

## Tools

**NGNIXii**

**Apache**

**MySQL**

**PostgreSQL**

**Python**

**Git**

**PIP**

**VirtualENV**

**Django**

**AWS**

# Intro to Cybersecurity

## Topics

**Key Elements**

**CIA Triad**

**Defense-In-Depth**

**Domain Landscape**

**AAA Services**

**OWASP**

## Tools

**NIST 800**

**OWASP**

# Current Threat Landscape

## Topics

**Threat Sources & Events; Adversarial (Fraud / Theft)**

**Insider Threat**

**Malicious Hackers**

**Malicious Code**

**Malware**

**Ransomware**

**Espionage); Non-adversarial (Errors and Omissions**

**Physical Infrastructure**

**Privacy and Data Sharing**

**Threat Motivations (Monetary**

**Hacktivism**

**IP Theft**

**Espionage**

## Tools

**Verizon Data Breach Reports**

# Security Program


## Topics

**Governance**

**Risk (Rating methodologies**

**Strategies: Accept / Transfer / Mitigate)**

**Compliance (Legal / Regulatory / HIPAA / PCI - DSS)**

**Frameworks (NIST Cyber Security Framework / ISO 27001:02)**

**Administration (Policies / Procedures / Standards / Guidelines)**

**Privacy**

**Data Classification & Handling (Identification / Ownership / Data at rest / Data at motion / Scoping)**

# Social Engineering

## Topics

**Physical Access Controls**

**Deterrents and Monitoring**

**Security Awareness**

**Social Engineering (Email / Phishing / In-Person / Telephony)**

## Tools

**Lock picking**

# Defense, Detection, and Architecture

## Topics

**Firewalls (Access Control Lists / Filters / Rules / White List / Black List)**

**Proxies**

**Remote Access**

**VPN**

**Network Access Control**

**Architecture / Design**

**Detect / Defend**

**Traffic Analysis**

**Logging / Log Management**

**Security Information Event Management (SIEM)**

**Intrusion Detection System (IDS)**

**Intrusion Prevention System (IPS)**

**Data Loss Prevention (DLP)**

## Tools

**Splunk**

**IPtables**

**Elastic Stack**

**Palo Alto**

**OpenVPN**

**Docker**

**LogRhythm**

**QRadar**

# Security Hardening

## Topics

**Secure Design Principles**

**Built-In vs. Bolt-On**

**Hardening (Operating Systems: Linux & Windows**

**Servers**

**Web Applications**

**Mobile)**

**OWASP Top 10**

**Patching**

**Secure Software Development Lifecycle (SSDLC)

## Tools

**Snort**

**File ACLs**

**WebGoat**

**CentOS**

**Debian / Ubuntu**

# Cryptography

## Topics

**Boolean Logic**

**Modulus Arithmetic**

**Symmetric / Asymmetric**

**Hashing**

**TLS / SSL**

**Disk encryption**

**Key Derivation Functions**

**Digital Signatures**

**Key Management: Public Key Infrastructure**

**Password Cracking: Rainbow Tables**

## Tools

**OpenSSL**

**Hashcat**

**MD5 / SHA**

**VeraCrypt**

**Bcrypt**

**Hydra**

Hydra can be used to brute force usernames, passwords, and other fields.

`hydra -L wordlist.for.un.uniq -p password <host ip>`

-L gives a list to try for login, -l is for username, -p is for password, -P is a list to try for passwords,  

# Vulnerability Management and Offensive Security

## Topics

**Assessment Approach**

**Testing Viewpoints (Internal / External**

**Overt / Covert**

**White box / Gray Box / Black Box)**

**Mitigation and Remediation**

**Vulnerability Scanning**

**Penetration Testing**

**Bug Bounty**

**DevSecOps**

**Red Team / Blue Team**

## Tools

**Carbon Black**

**Metasploit**

**Nikto**

Very effective, but not stealthy - designed for security testing

use `nikto -h ho.st.ip.ad/domain.name` to scan a website. The output tells you which websites were found and links to vulnerabilities you can research on OSVDB.

**Nessus**

**Burp Suite**

**Veracode**

**Shodan**

**Discover scripts**

**Terraform**

**Qualys**

# Incident Response and Forensics

## Topics

**CSIRT**

**NIST: IR Methodology (Preparation / Detection & Analysis / Containment**

**Eradication & Recovery / Post-Incident Activity)**

**NIST: Forensics Process (Data Collection / Examination / Analysis / Reporting)**

**Threat Intelligence (Cyber Kill Chain / Diamond Model)**

## Tools

**FireEye Redline (Mandiant)**

**Volatility**


# Pentesting Tools

## Enumeration

### nmap

nmap [flags] filename ip.ad.dre.ss:port
`nmap -sn  10.0.0.0/24` ping scans the network

`nmap -p 1-65535` - specify ports to be scanned - there are other port options available, such as excluding ports, not randomizing, fast scan, and scanning the top ports

`-sS` SYN scan - the default and most popular scan option because it is relatively stealthy - it never completes a TCP connection and works against any compliant TCP stack

`-sY` SCTP INIT scan - SCTP is a new alternative to TCP and UDP which adds new features and combines many of their characteristics.

`-sN, -sF, -sX` - these scans differentiate between open and closed using a loophole in TCP definition in RFC 793. The xmas scan is the most popular of these, which sends the FIN, PSH, and URG flags "lighting up the packet like a christmas tree"

`-sA` - doesn't determine open or filtered, just used to map out firewall rulesets, determining whether they are stateful or not and which ports are filtered

`--scanflags` allows you to design your own scan by specifying arbitrary TCP flags

`-sZ` is an SCTP cookie echo scan - not as obvious as a

`-v` - verbose output

`-T#` - timing - higher is faster and less accurate

`-sV` - service and version info - more options available

`-o` - output options: includes normal (N), xml (X), script kiddie (S), greppable (G), three major at once (A)

`-O` - OS detection

`-sU` - does a udp scan

`-sC` - uses the default script

`--script <filename>` allows you to write and use scripts written in NSE (nmap scripting engine)

response rate limiting is an effective deterrent to nmapping of your networks, since it makes all scans take much longer to complete.

once you have nmapped, look for alternative names/DNS for help with where to use dirb, etc.

### masscan

`masscan -p 22,1000-2000 10.0.0.0/8` to scan ports 22, 1000-2000 on the 10.0.0.0/8 network

`--echo -> file.conf` dumps current configuration

`--banners --heartbleed` etc help you set banners. ....

### ncat

A tool for reading, writing, redirecting, and encrypting data across the netowrk.

ncat "aims to be a network swiss army knife" - you can:

- use it as a simple tcp/udp/sctp/ssl client for interacting with web, telnet, mail servers, and other TCP/IP network services. ncat allows you to control every character sent and view raw, unfiltered responses

- use it as a simple server for offering services to clients, or simply understanding what clients are up to

- redirect or proxy traffic to other ports or hosts

- encrypt communication with ssl and transport it over ipv4 or ipv6

- create connections, allowing two or more clients to connect to each other through a brokering server, enabling machines behind NAT gateways, and enabling ncat chat mode

ncat has two basic modes - connect mode and listen mode - in connect it initiates a connection to a service which is listening somewhere (client). In listen mode, it waits for incoming connections (server).

Use `ncat -l localhost 8080 < hello.http` to make a simple webserver with hello.http as the document on which it is based

You can use connection brokering to transfer files and to set up multi-user chat rooms.

`--exec /this/file` lets you run a command

a listening ncat may control which hosts connect to it using `--allow` and `--deny`

ncat can route connections through SOCKS or HTTP proxies using `--proxy <proxyhost>:<proxyport> --proxytype [http, socks4, socks5] <host>:<port>`

### nc

`nc -nvlp 1234` starts listening on port 1234

# Kali

## Burp Suite

Burp is designed to be used alongside a browser. It functions as a HTTP proxy server - all HTTP/HTTPS traffic from your browser passes through burp. Your browser must be configured before doing anything else with burp.

**Getting Started:** Make sure the proxy listener is active and working  - check under Proxy > Options in Burp Suite to ensure 127.0.0.1:8080 is listening. Follow the instructions here https://portswigger.net/burp/help/suite_gettingstarted to configure the proxy in your browser. Install the burp certificate authority SSL certificate. Close all browswer windows, and check it is working by forwarding and turning the intercept on and off.

Items that have been requested are shown in black, and other are gray. The core of the workflow is the ability to pass HTTP requests between the various burp tools to carry out particular tasks. Select messages and use the context menu to send the request to another tool.

### Point-and-Click Scanner



####Spider

Used for automatically crawling an application to discover content and functionality

### Scanner

Used for automatically scanning HTTP requests to find security vulnerabilities

### Intruder

Lets you perform customized automated attacks

### Repeater

Used to manually modify and reissue HTTP requests repeatedly

### Sequencer

Analyze the quality of randomness in application's session tokens

### Decoder

Lets you transform bits of application data using common schemes

### Comparer

Performs visual comparison of bits of application data to find interesting differences

## Recon-ng

## Shodan

## Dmitry, Sparta, Netdiscover, Zenmap

## Metasploit

## Meterpreter

## AV Bypass

## Privilege Escalation

`find / -perm -4000 -user root -exec ls -ld {} \; 2> /dev/null` ???

`nmap --interactive`

## Packet Capture

## MITM

## Social Engineering

## BeEF

## Password Cracking

## Wireless Network Attacks

## Mutillidae

## Maintaining Access

## Post Exploitation

## Payloads


