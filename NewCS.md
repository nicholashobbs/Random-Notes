# Networking

## Concepts

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

**Wireshark**

**TCPDUMP**

**Netcat**

**Netstat**

**Nmap**

**Dig**

**Nslookup**

**Whois**


# Security Basics

## Topics

**Key Elements**

**CIA Triad**

**Defense-In-Depth**

**Domain Landscape**

**AAA Services**

**OWASP**

**NIST 800**


# Threats

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

**Verizon DBIR**

# Security Program


## Topics

**Governance**

**Risk (Rating methodologies)**

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



# Defensive Tools

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





# NOTES FROM DEAD ARCH COMPUTER



2/28 OPSEC - SOC, SLAs, need support structure in place for escalating incidents OKTA - single sign on aws shared responsibility model

3/7 YARA rules eternal blue exploit applying patches

3/12 NIST - assessing risks, big picture overview, frameworks and whitepapers for everything generally 'standards' are paid, 'frameworks' are free ISO 27001 information security management system remediate - permanent fix risk product number - impact probability ability to detect risk register in an audit, you must remediate after pen-testing or you open yourself up to more liability. GDPR - 4% EU NIS NY DFS - ciso, risk management, data retention policy, data destruction policy, pen-testing and vulnerability scanning for consulting - show charts and graphs, make it succinct, let them ask questions, reflect back to them third party risk value and exposure factor > SLE * annual rate of occurence = ALE cost of control residual risk existing control practical threat assessment

3/13 frameworks are based on standards professional liability insurance for consultants starting part is always a policy - not having a policy is also a policy risk committee if everyone owns a risk, noone owns it risk rating matrix people, processes, technology HR/legal must pass policies

3/14 ISACA cobit training for consulting work - house of lies is a movie about consulting data breach in target's 10k - case study parkerian hexad - confidentiality, integrity, availability, control, authenticiy, utility PII - personally identifiable information NPPI - non-public personal information security management CMMI always get an email - ask for documentation whenever you do something which could have risks for your work or job 'send me an updated resume' - find a new job

3/15 CISO shouldnt report to CIO because your job would be to point out boss' flaws start with policy, then go on to delegate the details first meeting will always be guarded - when a consultant comes in, employees might think whatever they say could get them fired, and their job might be at risk different sets of scoping questions should be asked to different groups of people ask devops about data everything in cybersecurity starts with risk assessment DLP - data loss prevention

3/19 hack of all info about you and people you know - SF 86 fish always rise from the head its easier to fool people than convince them they have been fooled BEC - business email scan $98.9M CEO email fraud discovered by cyprus bank - still isnt public who was responsible wells fargo is particularly untraceable for some reason postal money orders have a high rate of fraud PIPEDA - canadian data privacy laws plant softball questions in crowd for public presentation backend vulnerabilities are 100x worse than front end - people dont maintain these systems because they see them as 'just internal' who is the expert, where is the documentation tactful way to ask peoples jobs - do you have an org chart?

3/21 physical security - often the most ignored aspect crime prevention through environmental design - make the attacker feel uncomfortable active vs passive monitoring wet pipe/dry pipe sprinklers solve it once now vs how many times later on? universal question for learning and business glass-backed polycarbonate

3/27 PKJ - certificate, registration authorities, database and store structure of a open software found? x509

3/28 cryptographic attacks - analytic, implementation, statistical prtk - password recovery tool kit applied cryptanalysis, self study course in block cipher c.a.

4/2 ingress - input, egress - output host - hardware/tcp based, application .. vs network - lower level, net socket for network NACs/ NACLs iptables regex splunk log investigation and analysis firewalls VLANs - create broadcast domains email gateway - router for email, receives email from outside, not a server placement of intrusion dettection systems/prevention dmz - an area where the trust boundary ends firewalls have a limited number of interfaces, so you don't want to use them for a workstation - instead you would use a switch firewalls can typically act as routers palo alto - application aware/ next gen firewall - other brands include cisco, sourcefire, sonicwall, checkpoint MITM can be a good or bad thing - not always an attack choosing a firewall starts with the needs of your organization virtualized firewalls are a good way to practice firewalls can exist on net, transport, application layers identify traffic and discover business needs based on that. write rules for a firewall with the most specific at the top, use implicit denial cookies at just the header is behind the times the first question is always what are the assets and value of those which the organization is trying to protect RFC 1918 defines private ips - look up other critical RFCs to referenece VLAN requires subnet, thus routing and switches - separate vlans for domains, roles, subnet schemes remember the authentication piece when doing maps each interface is one collision domain - each vlan is one broadcast domain trunks are layer 2, routers are layer 3, frame is layer 2, packet is layer 3 trunking - industry uses 802.1q, switches normally handle this packet goes in the frame, and is switched before it is routed SVI - switch virtual interface police traffic going between zones always impose policies at every level - trust nobody to do the right thing ISL - proprietary alternative to trunking dot notation eth1/1.10 - what does this mean? radius server - authenticate through firewall switch - a good way for remote workers to authenticate before connecting separation of concerns - isaac's favorite topic read up on 802.1q collision domains you should vlan every segment - never keep everything in the same broadcast domain anonymous system - as border gateway protocol - bgp VPC - virtual private cloud aws is virutalizing firewalls, switches, and everything else - adding more layers of abstraction so simultaneous complexity and ease NAT - translate private to public addresses

4/3 ip tables - deny is block traffic and notify, drop is block traffic attempt allow or accept is whitelist pre-routing - routing as traffic arrives the interface post-routing - as traffic leaves the interface basic firewall is stateless or stateful masquerading - nat OSPF - open shortest path first: a routing protocol other routing protocols include ISIS , RIP, EIGRP BGP allows the router to learn networks IP is a routed protocol, or a packet transmission methodology tcp-wrapper DHCP - discover, offer, request, acknowledge (server, client, layers, etc) IP is layer 2 NIC is a network interface controller Layer 2 fabric - switch, cat5, fiber, patch panel DHCP snooping - shutdown any unexpected requests always start with diagram, then establish rules and specifications next gen firewalls are capable of FQDN lookups and dynamic blocking DMZ, trust, untrust zones, routable services in DMZ MX record name roam/roll ? cable - pin a to pin b PuTTY is SSH for windows

4/4 SPAM - switch port analyzer, allows one part to copy traffic into another SYN flood - tcp request repeatedly - can be blocked by setting timeouts, etc DOCUMENTATION IS KEY Blackholing attacks - send it into nothing Detection - who what where when how most elegant defense is hardening the TCP stack Every machine should have logging capacities CIA attacks on logs include: C- reading logs I - altering logs A - easy access to unauthorized person controls against these: C - ACL, encryption I - FACL, hash tables, A - redundancy, RAID shadow files in var/log logging protocols - syslog - udp/514, snmp - udp/161,162(snmp trap) MIB - management info base object identifiers (OID) SIEM - security info event management MSSP - managed security service provider Ipsentry, whatsup, infovista servone STIXX/TAXII NIST is the basis of work security analyst positions require sysadmin, programming, db, statistics architecture, engineering, ops (design, building, maintenance) privileged access management - limited lifespan tokens active directory "one of the best things windows did" according to isaac security should be at the table when: making major changes, buying new product, building something new logrhythm is better than splunk in isaac's opinion

4/5 wireshark - tcp header formats tshark - terminal capture filter - tells you what sysinternals capture filter = what, companiiion with process explorer or htop how to get machines mac address little snitch phone home is your machine trying to communicate with outside spanning tree attacks are attempts to become the root bridge

4/7 logging: sources, schemes, health v security, challenges, maturation digital forensics, web app pentesting baselining is giving your system a sense of what the baseline is so you can analyze and identify extreme events ETL EPS - events per second, a way that companies commonly try to overcharge their clients EA - enterprise architecture Scraper for headlines and relative popularity python lab regex rules (separate doc) findall returns every matching object, search returns a match object SSL - three protocols, handshake, change ciphers, alert SSL connection - transport providing a secure p2p SSL session - a client-server protocol initialization vector - salting the hash

4/9 UCAN - sites, financial server, physical security, chicago, franklin park locations provided laptops and desktops which we are allowed to scan BYOD policy for cell phones IDS - intruder detection system IPS - intruder prevention system choke point - somewhere that all traffic flows through breaking point - an expensive testing product that has a grace period and free testing NIDS - network IDS, AIDS - application, HIDS - host NBA - network behavior analysis knock down silos and be inclusive to share knowledge anomaly based detection - what is normal? block after a number of failed logins stateful protocol analysis understands and tracks state of network transport components - sensor/agent, management server, database server, console capabilities - threshold, black and whitelists, alert settings, code view/edit in-line - traffic must flow through Passive - monitors a copy network tap - connects sensor to physical network medium fail-open - allow traffic fail-closed - deny traffic IBS - intelligent bypass switch if you have IPS, you should have IBS lastline, wildfire, and more firewall and IPS and blending into UTM - unified threat management MTTR management station - communicates threat info between locations shifttech ips poorly implemented leads to blackholing network LEARN TLS HANDSHAKE AND ENTIRE TCP CONNECTION

4/11 NIST recommends 4 locations, behind each ext, outside external, on all major net backbones, on critical subnets hackthebox jsbeautify check responsive console, dev tools, plugins 200 reply means success check encoding, use free decryption tools techbar and hackbar - addons for firefox 'or'1=1 is sqli how php works injecting into sql - understand!? google dorks, inurl tunnelblick vpn how to create transcendent relevant guide to BBH port knocking - use nmap, scapy filtered port - cant determine what is there ipython, jupyter keeps a log/cache burp suite - acts like a proxy, stands in between, lets you copy sites directory buffer - dictionary attack to search webpages pentestmonkey.net proc/version vulnhub how to make post requests? - check chat

4/12 learn nc -e /bin/bash to upload a reverse shell cd applications/splunk/bin weffriddles t pot - github honeypot honeynet mimics a network how to encrypt and backup a machine buscador, michael bazzell, custom search tools, how to 6 things for ucan - mobility, int vulnerability, security program, endpoint, social engineering, web vulnerability

4/16 machine data - logs splunk has: universal forwarder - log collector heavy forwarder - transform and drop data, cut uneccesary logs c99 backdoor LEARN - find, grep, etc other finding tools setup splunk home monitoring, find additional apps make security learning custom distribution ctrl a for beginning of line tamper data addon for viewing and modifying http headers

4/17 STRIDE - spoof, tamper, repudiation, info disclosure, dos, elevation of privilege DREAD - damage, reproducibility, exploitability, affected users, discoverability - often left out because security through obscurity is a bad idea useradd, passwd, groupadd use sed to echo whatever a script is doing (learn how) vulrnerability, risk level, likelihood, use color conciseness and confidence policies: social engineering awareness, email, software installation, password, remote access, encryption three phases - risk assessment, construction, implementation

4/18 hardening: updates, logging, password policy, harden remote access, disable/uninstall, unneeded services/accounts, setup backups, test vulnscan pentest GPO is modernly used in windows windows SCW security configuration wizard - can be used as a basis for hardening on windows there is a default admin disabled by default - ensure you enable and change password because that in itself is a vulnerability since hackers can create and modify that stuff with tools like chntpw to modify sen file rootport is what you use to get to root bridge facebook can get access to anyones data including private messages using facebook.com/records/inquiry - all you need is a badge # OPSEC - there is no patch for human stupidity - ramandeep anti-forensic tools on bootloader BIOS malware is popular now and highly effective






Additional Evolve Notes

Module 1: Networking Vocab Unicast - one-to-one Broadcast - one-to-all Multicast - one-to-many OSI Model - APSTNDP: Application - specifies protocols, ensures communication is possible Presentation - presents data in a standardized format Session - opens, closes, manages sessions Transport - end-to-end movement of data - includes TCP/UDP Network - provides logical data routing paths Data Link - transfers data between adjacent nodes Physical - electronic circuits, bit-level transmission APST are host, while NDP are media TCP/IP Model - ATIL: the fundamental protocols, more modern Application - includes TCP/UDP, and Application, Presentation, Session layers from OSI model Transport - end-to-end protocols (host-to-host) Internet - moving data across network boundaries Link - only operates on what the host is physically connected to IPv4 - connectionless, packet switched protocol Public/Private addresses - can be accessed over the internet(CLARIFY) Router - forwards data between networks Ethernet hub - connects devices into a segment Switch - connects devices using packet-switching NAT - remaps one IP space to another PAT - permits multiple devices to map to one IP UDP - used for streaming, data connections that do not require a connection or confirmation of receipt three-way-handshake - SYN, SYN/ACK, ACK DNS - domain name system TLD - .com, etc subdomain - __.x.com FQDN - fully qualified domain name - sub.domain.tld name server - application which provides information about a directory zone file - text file describing dns zone network segmentation - the act of splitting a computer network into subnets subnets - the number of IPs in a subnet is the number of bits taken ^ 2 subnet mask - decimal, binary, CIDR: /24 = 255.255.255.0 = 11111111.11111111.11111111.00000000 VLANs - only exist in layer 2: a virtual LAN for segmenting applications, etc in a network trunking - a specific transmission channel between 2 points layers - parts of model, which is a procedure that has an architecture VPN - layer 1-3, virtual private network

Module 2: Application Stack client-server model - server is a provider, client is a reqeustor application server - provides facilities, handles server environment for applications web server - only handles http relational - based on relationships between data index/primary key - a unique value for each row in a dataset secondary key - a unique value which is not neccessarily a primary key record - a row of data field/column - a certain part of data across rows table - rows and columns key - identifier RBAC - role based access control

Module 3: Security Domains and Amazon Web Services SDLC - systems development life cycle: analysis, design, implementation, maintenance, planning, back to analysis defense in depth - different lines of defense, a multi-layered structure where security is built in at each step to eliminate easy access CIA triad - confidentiality, integrity, availability domains - application, network, hardware, physical, mobile, operational security incident response - responding to escalated events, root cause analysis IAM - identity and access management GRC - governance, risk, compliance - includes managing audits, legal compliance, vendor risk management, internal audits, remediation from audits. disaster recovery business continuity AAA - identification, authentication, authorization, auditing, accounting NAC - can use 802.1x

Module 4: Threats and Vulnerabilities adversarial threat - someone trying to intentionally damage your operations non-adversarial threat - someone who might unintentionally damage your operations fraud/theft threat sources, events, actors APT - advanced persistent threats insider threats - someone within the organization who might cause harm cyber kill chain - reconaissance, weaponization, delivery, exploitation, installation, command and control, actions on objectives. comes from lockheed martin paper threat intelligence - a branch of cybersecurity which identifies and researches APTs, trends in cyber attacks, and other threat data TTPs threat intel levels - tactical, operational, strategic initial compromise, establish foothold, escalate privileges, internal recon, maintain presence, move laterally, complete mission
