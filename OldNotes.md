


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


upload a php payload  - php reverse shell: http://pentestmonkey.net/tools/web-shells/php-reverse-shell


---------------------------------------------

bus topology, star topology

thinnet/thicknet - types of network cables with 10 Mbps transfer rate

rg-8,6 etc, mdi-x

802.3

cat3 - phone/voice cable standard

cat5/100BaseT - fast ethernet, rj-45, 100 Mbps, 100 meters

cat 5e - 1 Gbps, 802.3ab, rj-45, 100m

cat6/10GbaseT- 500 Mhz, 10 GBps,

1000BaseSX / 802.3z- gigabit ethernet over fiber, 1000 MBps multimode fiber

10GBaseSR - multimode fiber

.... way more types of cables to memorize or learn about

802.5 Token Ring - network nodes must wait for token before transmitting

NIS - network information services - a central list of net objects, users, groups, printers, etc

NetBEUI - netbios extended user interface - a non routable protocol for small netowkrs

segment - data at layer 4 (transport)

packet - data at layer 3 (network)

frame - data at layer 2 (data link)

bits/signal - data at layer 1 (physical)

TCP - transmission control protocol - layer 4

IP - layer 3

MAC - layer 2 address - 48 bits, 12 digit hexadecimal

IPX - internetwork packet exchange - routable protocol, unreliable and connectionless (layer 3)

SMTP - simple mail transfer protocol - port 25, tcp

802.11a - wireless network protocol, also 802.11b,g, n, ac

802.2 - logical link control

simplex - communication channel in one direction only

half-duplex - communication only one direction at a time

hub - layer 1 repeater - data sent to all ports on the hub

mau - multistation access units - token ring device to attach multiple network stations in star topology - cycle through ports in logical ring

bridge - splits network segments based on MAC address table creating separate collision domains

switch - there are a number of types on a number of layers

router - reads packet header to determine preferred route for data - layer 3 - it is a boundary where each port separates broadcast and collision domains - when the router doesnt have a route, it discards the packet.

HIDS - host based intrusion detection

NIDS - network intrusion detection system

CSU - channel service unit - converts serial signals into digital signals

ISDN - integrated services digital network BRI basic rate, PRI faste - TA terminal adapter used to connect computer to isdn network

punchdown block - electrical connection where copper wires are punched down into short open ended slots

patch panel - a number of jacks for connecting circuits in a flexible and convenient way

class a/b/c address - 1-126, 128-191, 192-223 default netmask for 255.0.0.0/255.255.0.0/255.255.255/0

ftp - port 20 for data, 21 for control

ssh - port 22

telnet - terminal sessions - port 23

dns - port 53

dhcp - port 67 server destination, 68 used by client

tftp - trivial ftp, udp port 69

http - port 80

pop3 - port 110

nntp - network news - port 119

ntp - network time protocol - port 123

IMAP4 - internet message application protocol v4 - port 143

secure HTTP - port 443

rdp - remote desktop protocol tcp and udp on port 3389

smb - server message block, a common internet file system - application layer protocol used to share access to files, printers, windows computers on port 445

CHAP - challenge handshake authentication protocol - lcp establishes ppp link, authenticator sends challenge, peer responds with value calculated using one-way hash to combine key with secret (password), authenticator checks hash value with secret and acknowledges the authentication if correct

DHCP scope - pool of IPs which dhcp can hand out to clients

mx - mail exchanger record

soa - start of authority record

hosts file - maps hostnames to ip addresses (predates dhcp)

samba - linux implementation of smb/cifs allows file and print sharing between windows and linux

hping - uses tcp packets to ping - can be used to test open ports and firewalls that would normally block icmp



5-4-3 rule - 10base2 and 10base5 collision domains - max of 5 network segments in total, joined by 4 repeaters, with only 3 segments containing active sending nodes

fiber optic cables - ST is straight tip, sc is subscriber

MPLS - multiprotocol label switching - avoids complex lookups in routing tables by assigning labels rather than analyzing packet headers

rfceditor.org
cymon.io - open source threat intelligence
risky business podcast
Awesome-Hacking on github
hack.me
arch linux wiki
overthewire.com
pentestmonkey
hacksplaining
pentestcloud


CSMA - carrier sense multiple access with collision detection allows systems to sense when the wire is free
