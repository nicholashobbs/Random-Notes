# Unix/Linux Sysadmin Handbook

## Chapter 1

Duties of a sysadmin: access control, adding hardware, automating tasks, overseeing backups, installing and upgrading software, monitoring, troubleshooting, maintaining local documentation, security, performance, developing policies, working with vendors, firefighting

which filename, whereis filename, locate filename

sourcecode installation

## Chapter 2: Booting

boot finds, loads bootstrapping code, runs os kernel, runs startup scripts and system daemons,maintains process hygiene and manages state transitions

BIOS - basic io system, now called UEFI

MBR - master boot record

FAT - file allocation table

efi boot mgr - change boot order, select next configured option, change boot entries

GRUB - grand unified boot loader - grub.cfg in /boot/grub `grub-mkconfig` or `update-grub` in Debian or Ubuntu

`systemctl` defaults to list units, shows loaded and active services, sockets, devices, etc -it can and should be used to manage services and daemons

`journald` manages systemd logging, is stored in /run, `journalctl` displays all log entries, with oldest first

`rsyslog` does remote system logging

PID 1 is init, the system management daemon

units are entries managed by systemd, unit files manage behavior of units which live in many places

.targets are distinct classes of units to act as well known marks for common operating modes

`telinit` is used to change run levels once the system is booted

.conf files have the same format as unit files

use `halt`, `shutdown`, `poweroff` to turn off. Single user mode is also called rescue mode.

## Chapter 3: Access Control

Kernel APIs allow third party modules to augment or replace traditional UNIX access control. Access controls change functioning based on:
- which user attempts to perform an operation
- who owns the object, what the permissions of the object are
- the creator of an object owns it
- root can act as the owner

`ls -l` shows ownership of files. Change uid and gid with `setuid` and `setgid`. `mount nosuid` disables execution of the prior.

`su -id` substitutes user identity - stored in `/usr/bin/su` or `/bin/su`. `sudo` is the primary method of accessing the root, access controlled by `/etc/sudoers`

`pam` is pluggable authentication modules - kereberos is a specific authentication method, which uses pam as a wrapper

`acls` are access control lists, a more fine grained way of controlling access

`selinux` is made by NSA

`mac` is mandatory access control, `rbac` is role based access control

--------------------------------------------

`dns` - associates system to name, or ip to domain. nameservers do the work of dns.

`tld` top level domain `fqdn` fully qualified domain name

zone file is a simple text controlling mappings from domain to ip

tcp handshake - client to server: syn, server to client: syn ack, client to server: ack

`netstat` prints connections and networking statistics `-tulpn` tcp, udp, local, process associated, numerical `-r` shows routing table

`service name stop`

CIDR - # of 1s - 1s are unchangeable in the real ip

VLAN - virtual lan segments broadcast comains by tagging traffic on specified switching ports to be in the same group. types include data, default, native, management, voice - these reduce the physical hardware needed.

VLAN trunk is a point to point link between switch interface and another ethernet interface

packet crafting, tcp session hijacking, tcp flow, tcp injection

sniffer - a tool using networking facilities to process packets anything coming from memory

sockets - interface os provides which pakcet capture apps use - typically raw sockets

find a wireshark cheatsheet

a hub is a repeater, a router routes, a switch offers multiple interfaces

dark web often just refers to pages which don't have dns

ARP is address resolution protocol - allows you to discover link layer addresses, such as mac addresses

`ip addr` is a lower level version of ifconfig

`traceroute` shows the hops a packet has gone through

`nc -v` shows you netcat is working `-l` is a list, `-p` is a port - `nc <ip> <port>` opens a shell

`openssl` ??

`nslookup` and `whois` show information about the owner, etc of a domain

`dig` is another program to show information about domains

a sheep dip computer is a device specifically for malware

gns3 - an alternative to packettracer

make cheat sheets for sql, nginx, git

Application server - backend business logic, http, security, resource pooling, messaging

Web Server - providing, caching, serving for web access, convert requests to static content, serve only http content, use apache, nginx, msiis

Databases - relational - sql, table is mathematical relationships, examples are mysql, postgres, mssql, oraclesql. non-relational - mechanism for sstorage, retrieval is modeled in other than tabular ways - include mongodb, apache cassandra, redis. sqlite is relational dbms, not client server - it is embedded into end programs

netstat -tlpn shows pid and program name

pip - package management system for python, preinstalled with kali, isolated environments created with virtualenv name

HTTP status codes - 200, 400, 100, 300, etc

ORM object relational mapper helps to avoid sql injection

technical debt - prior apps relied upon and expensive to update create a high cost of updating

controller, model and view python

infosec:
supports mission of organization, integral to sound management, commensurate with risk, responsibilities, accountability made explicit, system owner share security responsibility outside own organizations, requires comprehensive, integrated approach, assessed regularly, constrained by society

CIA triad - confidentiality, integrity, availability

IAM - identity and access management

VPC gateways - vpn clients and servders

elastic ip addresses

ping sends icmp packets to host

in traceroute ttl is time to line reply - timestamp is latency

curl domain pulls information from a certain place on the internet

openssl connect domain:port

wireshark does live or historical network behavior - listening interface or open packet capture

arp/mac addresses
nat, pat, src ip, src prt, dst ip, dst prt

model is a rubric, architecture is the nitty gritty ie set of rules or compartmentalization of functions into layers

WLAN  wireless local area network

unicast, multicast, braodcast

dhcp - where do i get my ip

OSI model defined protocol suite which has been replaced with tcp/ip
application, presentation, session, transport, network, data link, physical

headers get added on and stripped off across different layers

tcp/ip - first three are application, then transport, then internet instead of network, data link is link






-------------------------------------------------------------
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

SYO501

1.0 Threats, Attacks and Vulnerabilities 1.1 Given a scenario, analyze indicators of compromise and determine the type of malware Viruses Crypto-malware Ransomware Worm Trojan Rootkit Keylogger Adware Spyware Bots RAT Logic Bomb Backdoor 1.2 Compare and contrast types of attacks Social Engineering Phishing Spear Phishing, Whaling, Vishing, Tailgating, Impersonation, Dumpster Diving, Shoulder Surfing, Hoax, Watering hole attack, Principles (Authority, Intimidation, Consensus, Scarcity, Familiarity, Trust, Urgency) Application/Service attacks Dos, DDoS, MITM, Buffer overflow, injection, XSS, XSRF, Privilege escalation, ARP poisoning, Domain hijacking, MITB, zero day, replay, pass the hash, hijacking and related attacks (Clickjacking, session hijacking, url hijacking, typo squatting), Driver manipulation (shimming, refactoring), MAC Spoofing, IP spoofing Wireless Attacks Replay, IV, Evil twin, Rogue AP, Jamming, WPS, Bluejacking, Bluesnarfing, RFID, NFC, Disassociation Cryptographic Attacks Birthday, Known plain text/cipher text, rainbow tables, dictionary, brute force, online vs offline, collision, downgrade, replay, weak implementations 1.3 Explain threat actor types and attributes Types of actors Script kiddies, hacktivist, organized crime, nation states/APT, insiders, competitors Attributes of actors internal/external, level of sophistication, resources/funding, intent/motivation, use of open source intelligence 1.4 Explain penetration testing concepts Active reconnaissance Passive reconnaisance Pivot Initial exploitation Persistence Escalation of privilege Black Box White Box Gray Box Penetration testing vs. vulnerability scanning 1.5 Explain vulnerability scanning concepts Passively test security controls Identify vulnerability Identify lack of security controls Identify common misconfigurations intrusive vs non-intrusive credentialed vs non-credentialed false positive 1.6 Explain the impact associated with types of vulnerabilities race conditions vulnerabilities due to end-of-life systems, embedded systems, lack of vendor support improper input handling improper error handling misconfiguration/weakk configuration default configuration resource exhaustion untrained users improperly configured accounts vulnerable business processes weak cipher suites and implementations memory/buffer vulnerabilities memory leak, integer overflow, buffer overflow, pointer deference, dll injection system sprawl/undocumented assets architecture/design weaknesses new threats/zero day improper certificate and key management 2.0 Technologies and Tools 2.1 Install and configure network components both hardware and software based, to support organizational security Firewall ACL, application based vs network based, stateful vs stateless, implicit deny VPN concentrator remote access vs site-to-site,IPSec (tunnel mode, transport mode, AH, ESP), Split tunnel vs full tunnel, TLS, always-on vpn NIPS/NIDS signature-based, heuristic/behavioral, anomaly, inline vs passive, in band vs out of band, rules, analytics (false positive, false negative) Router ACLs, Antispoofing Switch Port security, layer 2 vs layer 3, loop prevention, flood guard Proxy forward and reverse proxy, transparent, application/multipurpose Load Balancer scheduling(affinity, round-robin), active-passive, active-active, virtual IPs Access point SSID, MAC filtering, signal strength, band selection/width, antenna types and placement, fat vs thin, controller based vs standalone SIEM aggregation, correlation, automated alerting and trigers, time syncronization, event deduplication, logs/worm DLP usb blocking, cloud-based, email NAC dissolvable vs permanent, host health checks, agent vs agentless Mail gateway spam filter, DLP, encryption Bridge SSL/TLS accelerators SSL decryptors media gateway hardware security module 2.2 Given a scenario, use appropriate software tools to assess the security posture of an organization protocol analyzer network scanners rogue system detection, network mapping wireless scanners/cracker password cracker vulnerability scanner configuration compliance scanner exploitation frameworks data sanitization tools steganography tools honeypot backup utilities banner grabbing passive vs active command line tools ping, netstat, tracert, nslookup/dig, arp, ipconfig/ip/ifconfig, tcpdump, nmap, netcat 2.3 Given a scenario, troubleshoot common security issues Unencrypted credentials/clear text Logs and event anomalies Permission issues Access violations Certificate issues Data exfiltration Misconfigured devices firewall, content filter, access points weak security configurations personnel issues policy violation, insider threat, social engineering, social media, personal email unauthorized software baseline deviation license compliance violation (availability/integrity) asset management authentication issues 2.4 given a scenario, analyze and interpret output from security technologies HIDS/HIPS Antivirus File integrity check host-based firewall application whitelisting removable media control advanced malware tools patch management tools UTM DLP data execution prevention web application firewall 2.5 Given a scenario, deploy mobile devices securely Connection methods cellular, wifi, satcom, bluetooth, nfc, ant, infrared, usb Mobile device management concepts application management, content management, remote wipe, geofencing, geolocation, screen locks, push notification services, passwords and pins, biometrics, context aware authentication, containerization, storage segmentation, full device encryption Enforcement and monitoring for third-party app stores, rooting/jailbreaking, sideloading, custom firmware, carrier unlocking, firmware OTA updates, camera use, SMS/MMS, external media, USB OTG, recording microphone, GPS tagging, wifi direct/ad hoc, tethering, payment methods Deployment models BYOD, COPE, CYOD, corporate-owned, VDI 2.6 Given a scenario, implement secure protocols Protocols DNSSEC, SSH, S/MIME, SRTP, LDAPS,FTPS, SFTP, SNMPv3, SSL/TLS, HTTPS, Secure POP/IMAP Use cases voice and video, time syncronization, email and web, file transfer, directory services, remote access, domain name resolution, routing and switching, network address allocation, subscription services 3.0 Architecture and Design 3.1 Explain use cases and purpose for frameworks, best practices, and secure configuration guides Industry-standard frameworks and reference architectures regulatory, non-regulatory, national vs. international, industry-specific frameworks Benchmarks/secure configuration guides Platform/secure configuration guides (web server, operating system, application server, network infrastructure devices), General purpose guides Defense in depth/layered security vendor diversity, control diversity (administrative, technical), user training 3.2 Given a scenario, implement secure network architecture concepts zones/topologies dmz, extranet, intranet, wireless, guest, honeynets, nat, ad hoc segregation/segmentation/isolation physical, logical(VLAN), virtualization, air gaps tunneling/VPN site-to-site, remote access security device/technology placement sensors, collectors, correlation engines, filters, proxies, firewalls, vpn concentrators, ssl accelerators, load balancers, DDoS mitigator, aggregation switches, taps and port mirror SDN 3.3 Given a scenario, implement secure systems design Hardware/firmware security fde/sed, tpm, hsm, uefi/bios, secure boot and attestation, supply station, hardware root of trust, emi/emp operating systems types, network, server, workstation, appliance, kiosk, mobile os, patch management, disabling unnecessary ports and services, least functionality, secure configurations, trusted operating system, application whitelisting/blacklisting, disable default accounts/passwords peripherals wireless keyboards, wireless mice, displays, wifi-enabled microsd cards, printers/MFDs, external storage devices, digital cameras 3.4 Explain the importance of secure staging deployment concepts Sandboxing Environment development, test, staging, production secure baseline integrity measurement 3.5 Explain the security implications of embedded systems SCADA/ICS Smart Devices/IoT wearable technology, home automation HVAC SoC RTOS Printers/MFDs Camera Systems special purpose medical devices, vehicles, aircraft/uav 3.6 Summarize secure application development and deployment concepts Development life-cycle models waterfall vs agile Secure devops security automation, continuous integration, baselining, immutable systems, infrastructure as code version control and change management provisioning and deprovisioning secure coding techniques proper error handling, proper input validation, normalization, stored procedures, code signing, encryption, obfuscation/camouflage, code reuse/dead code, server side vs client side execution and validation, memory management, use of third party libraries and sdks, data exposure code quality and testing static code analyzers, dynamic analysis, stress testing, sandboxing, model verification compiled vs runtime code 3.7 Summarize cloud and virtualization concepts hypervisor type 1,2, application cells/containers vm sprawl avoidance vm escape protection cloud storage cloud deployment models saas, paas, iaas, private, public, hybrid, community on-premise vs hosted vs cloud vdi/vde cloud access security broker security as a service 3.8 Explain how resiliency and automation strategies reduce risk Automation/scripting automated courses of action, continuous monitoring, configuration validation templates master image non-persistence snapshots, revert to known state, rollback to known configuration, live boot media elasticity scalability distributive allocation redundancy fault tolerance high availability RAID 3.9 Explain the importance of physical security controls Lighting Signs Fencing/gate/cage security guards alarms safe secure cabinets/enclosures protected distribution/cabling airgap mantrap faraday cage lock types biometrics barricades/bollards tokens/cards environmental controls hvac, hot and cold aisles, fire suppression cable locks screen filters cameras motion detection logs infrared detection key management 4.1 Compare and contrast identity and access management concepts identification, authentication, authorization and accounting (AAA) multifactor authentication something you are, have, know, do, somewhere you are federation single sign-on transitive trust 4.2 Given a scenario, install and configure identity and access services ldap kerberos tacacs+ chap pap mschap radius saml openid connect oauth shibboleth secure token ntlm 4.3 Given a scenario, implement identity and access management controls access control models mac, dac, abac, role bac, rule bac physical acccess control proximity cards, smart cards biometric factors fingerprint scanner, retina scanner, iris scanner, voice recognition, facial recognition, false acceptance rate, false rejection rate, crossover error rate tokens hardware, software, hotp/totp certificate based authentication piv/cac/smart card file system security database security 4.4 given a scenario, differentiate common account management practices account types user account shared and generic accounts/credentials, guest accounts, service accounts, privileged accounts general concepts least privilege, onboarding/offboarding, permission auditing and review, usage auditing and review, time-of-day restrictions, recertification, standard naming convention, account maintenance, group-based access control, location-based policies account policy enforcement credential management, group policy, password complexity, expiration, recovery, disablement, lockout, password history, password reuse, password length 5.0 Risk Management 5.1 Explain the importance of policies, plans and procedures related to organizational security Standard operating procedure agreement types bpa, sla, isa, mou/moa personnel management mandatory vacations, job rotation, separation of duties, clean desk, background checks, exit interviews, role-based awareness training (data owner, system administrator, system owner, user, priveleged user, executive user), NDA, onboarding, continuing education, acceptable use policy/rules of behavior, adverse actions general security policies social media networks/applications, personal email 5.2 Summarize business impact analysis concepts RTO/RPO MTBF MTTR mission-essential functions identification of critical systems single point of failure impact life, property, safety, finance, reputation privacy impact assessment privacy threshold assessment 5.3 Explain risk management proccesses and concepts threat assessment environmental, manmade, internal vs external risk assessment sle, ale, aro, asset value, risk register, likelihood of occurrence, supply chainn assessment, impact, quantitative, qualitative, testing (penetration testing authorization, vulnerability testing authorization), risk response techniques (accept, transfer, avoid, mitigate) change management 5.4 Given a scenario, follow incident response procedures incident response plan documented incident types/category definitions, roles and responsibilities, reporting requirements/escalation, cyber-incident response teams, exercise incident response process preparation, identification, containment, eradication, recovery, lessons learned 5.5 Summarize basic concepts of forensics order of volatility chain of custory legal hold data acquisition capture system image, network traffic and logs, capture video, record time offset, take hashes, screenshots, witness interviews preservation recovery strategic intelligence/counterintelligence gathering active logging track man-hours 5.6 Explain disaster recovery and continuity of operation concepts recovery sites hot site, warm site, cold site order of restoration backup concepts differential, incremental, snapshots, full geographic considerations off-site backups, distance, location selection, legal implications, data sovereignty continuity of operation planning exercises/tabletop, after-action reports, failover, alternate processing sites, alternate business practices 5.7 Compare and contrast various types of controls deterrent, preventive, detective, corrective, compensating, technical, administrative, physical 5.8 Given a scenario, carry out data security and privacy practices data destruction and media sanitization burning, shredding, pulping, pulverizing, degaussing, purging, wiping data sensitivity labeling and handling confidential, private, public, proprietary, pii, phi data roles owner, steward/custodian, privacy officer data retention legal and compliance 6.0 Cryptography and PKI 6.1 Compare and contrast basic concepts of cryptography symmetric algorithms modes of operation asymmetric algorithms hashing salt, iv, nonce elliptic curve weak/deprecated algorithms key exhcange digital signatures diffusion confusion collision steganography obfuscation stream vs block key strength session keys ephemeral key secret algorithm data-in-transit data-at-rest data-in-use random/pseudo-random number generation key stretching implementation vs algorithm selection crypto service provider, crypto modules perfect forward secrecy security through obscurity common use cases low power devices, low latency, high resiliency, supporting confidentiality, supporting integrity, supporting obfuscation, supporting authentication, supporting non-repudiation, resource vs security constraints 6.2 Explain cryptography algorithms and their basic characteristics symmetric algorithms aes, des, 3des, rc4, blowfish, twofish cipher modes cbc, gcm, ecb, ctm, stream vs block assymetric algorithms rsa, dsa, diffie-hellman(groups, dhe, ecdhe), elliptic curve, pgp/gpg hashing algorithms md5, sha, hmac, ripemd key stretching algorithms bcrypt, pbkdf2 obfuscation xor, rot13, substitution ciphers 6.3 Given a scenario, install and configure wireless security settings cryptographic protocols wpa, wpa2, ccmp, tkip authentication protocols eap, peap, eap-fast, eap-tls, eap-ttls, ieee 802.1x, radius federation methods psk vs enterprise vs open, wps, captive portals 6.4 Given a scenario, implement public key infrastructure components ca, intermediate ca, crl, ocsp, csr, certificate, public key, private key, object identifiers concepts online vs offline ca, stapling, pinning, trust model, key escrow, certificate chaining types of certificates wildcard, san, code signing, self-signed, machine/computer, email, user, root, domain validation, extended validation certificate formats der, pem, pfx, cer, p12, p7b

Additional Evolve Notes

Module 1: Networking Vocab Unicast - one-to-one Broadcast - one-to-all Multicast - one-to-many OSI Model - APSTNDP: Application - specifies protocols, ensures communication is possible Presentation - presents data in a standardized format Session - opens, closes, manages sessions Transport - end-to-end movement of data - includes TCP/UDP Network - provides logical data routing paths Data Link - transfers data between adjacent nodes Physical - electronic circuits, bit-level transmission APST are host, while NDP are media TCP/IP Model - ATIL: the fundamental protocols, more modern Application - includes TCP/UDP, and Application, Presentation, Session layers from OSI model Transport - end-to-end protocols (host-to-host) Internet - moving data across network boundaries Link - only operates on what the host is physically connected to IPv4 - connectionless, packet switched protocol Public/Private addresses - can be accessed over the internet(CLARIFY) Router - forwards data between networks Ethernet hub - connects devices into a segment Switch - connects devices using packet-switching NAT - remaps one IP space to another PAT - permits multiple devices to map to one IP UDP - used for streaming, data connections that do not require a connection or confirmation of receipt three-way-handshake - SYN, SYN/ACK, ACK DNS - domain name system TLD - .com, etc subdomain - __.x.com FQDN - fully qualified domain name - sub.domain.tld name server - application which provides information about a directory zone file - text file describing dns zone network segmentation - the act of splitting a computer network into subnets subnets - the number of IPs in a subnet is the number of bits taken ^ 2 subnet mask - decimal, binary, CIDR: /24 = 255.255.255.0 = 11111111.11111111.11111111.00000000 VLANs - only exist in layer 2: a virtual LAN for segmenting applications, etc in a network trunking - a specific transmission channel between 2 points layers - parts of model, which is a procedure that has an architecture VPN - layer 1-3, virtual private network

Module 2: Application Stack client-server model - server is a provider, client is a reqeustor application server - provides facilities, handles server environment for applications web server - only handles http relational - based on relationships between data index/primary key - a unique value for each row in a dataset secondary key - a unique value which is not neccessarily a primary key record - a row of data field/column - a certain part of data across rows table - rows and columns key - identifier RBAC - role based access control

Module 3: Security Domains and Amazon Web Services SDLC - systems development life cycle: analysis, design, implementation, maintenance, planning, back to analysis defense in depth - different lines of defense, a multi-layered structure where security is built in at each step to eliminate easy access CIA triad - confidentiality, integrity, availability domains - application, network, hardware, physical, mobile, operational security incident response - responding to escalated events, root cause analysis IAM - identity and access management GRC - governance, risk, compliance - includes managing audits, legal compliance, vendor risk management, internal audits, remediation from audits. disaster recovery business continuity AAA - identification, authentication, authorization, auditing, accounting NAC - can use 802.1x

Module 4: Threats and Vulnerabilities adversarial threat - someone trying to intentionally damage your operations non-adversarial threat - someone who might unintentionally damage your operations fraud/theft threat sources, events, actors APT - advanced persistent threats insider threats - someone within the organization who might cause harm cyber kill chain - reconaissance, weaponization, delivery, exploitation, installation, command and control, actions on objectives. comes from lockheed martin paper threat intelligence - a branch of cybersecurity which identifies and researches APTs, trends in cyber attacks, and other threat data TTPs threat intel levels - tactical, operational, strategic initial compromise, establish foothold, escalate privileges, internal recon, maintain presence, move laterally, complete mission

Linux Notes

chroot - change root, allows you to operate on a new directory? UEFI - unified extensible firmware interface history - set in UEFI? ./bashrc? modular - linux kernel means many drivers are available as modules 192.168.1.1 - generally is the ip of home router SSID RSN systemctl drop-in file acpi - utility for battery life w3m - enter to input, q to quit hwclock --show - for time timedatectl uuid - unique ids for filesystems lsblk pacman - package manager for arch, like apt-get -Ss to search, -Rs to remove package and all dependencies wifi menu ip link set down wlp1s0 showconsolefont fstab - file used to define how disk partitions, other block devices, remote file systems should be mounted brightness - in arch, go to /sys/class/backlight/acpi_video and sudo tee brightness <<< value nmap netstat xorg - plasma desktop - sddm - kdc applications sudo needed for sddm to work df -h allows you to check for available space -i for ?

LINUX FROM SCRATCH PROJECT

Software Building How To

tar - archiving gzip - compressing together create .tar.gz or .tgz (tarball) to untar and gunzip, tar xzvf [filename] equivalent to gzip -cd filename | tar xvf - or gunzip -c filename | tar xvf - you might also see bzip2 or shar files, in this case look it up. makefile - a script for compiling or building the binaries, or executable portions of a package. makefile launches cc or gcc which turns the source code into binaries make - builds all the files for package in question. it can also install files in the right directory(install), remove stale object files (clean), or preview the build process (-n) imake - a template man makefile xmkmf - a shell script that is a front end for imake. normally use -a argument which makes makefiles, includes, depends, and sets variables, defines library locations sometimes there will be an install or configure script instead. make install - usually used to install freshly built binaries binaries go in /usr/bin, /usr/x11r6/bin, or /usr/local/bin, which is the prefered location for new packages to keep binaries separate which are not part of the original linux install ./configure fits in somewhere here installation procedure - readme, run xmkmf -a or install or configure, check the makefile, run make clean/makefiles/includes/depend if necessary, run make, check permissions, if necessary run make install rpm, deb, slp are package formats which are simpler than installing from binaries they must be installed as root, which is a security risk, so run signature checks there are packages to unpack these formats and to transfer them to other forms so they can be used on any computer. terminfo - a database describing terminals in some cases, it is useful to use a.out binaries if source code is not available or if it is not possible to build new ELF binaries from source ELF installations tend to have a.out binaries in /usr/i486-linuxaout/lib some distributions require a special compatibility package for a.out, such as debian's xcompat troubleshooting - check online section 7 of software building howto read software package to determine if certain environmental variables need setting in .bashrc or .cshrc, and if .Xdefaults or .Xresources need customizing sssh username@servername - standard port is 22 -p option to specify a port scp - a utility that uses an ssh connection to copy to another computer ctrl+d or logout to get out of a ssh connection

scp -r .ssh/id_rsa.pub cx@192.168.1.101:~/

learn to copy from terminal line into vim in /etc/ssh/sshd_config i changed to port 443, changed pam to no and password authentication to no

Linux From Scratch

[optional text] function(#) refers to a certain page in the man for the function. run man # function to get there - located at /usr/share/man/man#/function.# Overview: Ch 2: how to create a new linux native partition and file system - where lfs is compiled and installed Ch 3: which packages and patches need to be downloaded to build LFS, how to store them Ch 4: setup of working environment - important to read carefully Ch 5: installation of packages that will form basic development suite or toolchain - a complex process involving first and second pass toolchains Ch 6: the full LFS system is built - chroot program is used to enter virtual environment and start a new shell whose root is set to the LFS partition. Similar to rebooting and instructing kernel to mount LFS as the root partition. Chrooting allows using the host system as LFS is being built. Ch 7: system configuration is set up Ch 8: kernel and boot loader Ch 9: continuing LFS beyond this if something goes wrong with configure, check config.log get output from make and config for debugging

TOOLS

netcat ping traceroute curl netstat dhclient nslookup dig wireshark tcpdump whois nginx mysql virtualenv pip awscli vpc ec2 ami rds dynamo elasticache redshift s3 openIOC virustotal abuse.ch passive dns av/ids/fw/siem fireeye, threatconnect, crowdstrike, recorded future

----------------------------------------------------
PDSA - plan, do, study, act

Deming: design of products to imporve service, higher level of uniform quality, improvement of testing in workplace and research centers, greater sales through global markets

System of Profound Knowledge: Appreciating a System, Understanding variation, psychology, epistemology

Organizations should focus on quality=results of efforts/total costs

when people focus first and foremost on costs, they tend to rise and quality declines.

terraform provider is used as a reference to the target environment .tf

.ova is an instance with virtual files, whereas a .vmdk is just the virtual hard drive

PTES - pre engagement intelligence gathering, threat modeling, vulnerability analysis, exploitation, post-exploitation, reporting

Hacking Methodology

kubernetes can often be unsecured, and it is often used to manage multiple docker containers

everything nessus does, netmap is capable of

Breakdown labs step by step - use instructions, not commands - take the terminology and make a lab guide/cheatsheet

LAIR framework
