# Linux


# Conventions

To start, I am just going to regurgitate everything into this file in a somewhat organized fashion. Once I get all of my notes down here and have everything condensed, I can go back and make flashcards, find gaps, organize it, and put it into a hierarchy guiding how it should be learned.

Ultimately, the progression of materials should be built as follows - start hard and jump to easy, but also cover things progressively as you go. Start with a high level description of what something is, then move on to more detail as you go. First create a complete listing of the things which you now know and want to learn before the end of class, and then transform it into a complete lesson plan whereby students are initially introduced to everything and told the capabilities of different tools - as time goes by they will be introduced and gradually exposed to the deeper levels of these tools.

`[]` - refers to something that should be replaced by any user-specified value
`<>` - has other abstract things, such as buttons you should press to execute a command

# General Linux

## Basic Commands

`pwd` - print working directory (where are you in the filesystem)

`sudo` - do this action as the root user - use `sudo -i` to change your identity to sudo

`[command] !!` - prepend command to prior command - useful when you forget to `sudo` previous command with `sudo !!`

`cd [directory]` -  move to directory

`ls <-la>` - list files in current directory. Option l is for a 'long' listing, which shows permissions and other details, a shows all files, including those which begin with . which are usually hidden.

`Tab` - use tab-completion to complete a name based on what you have typed so far. If there are more than one option, tab twice to list available options

`ln /file/path /link/path` - creates a hard link from file path to link path

`mkdir [directory]` - create directory - `rmdir` to remove

`rm` - remove a file

`mv /file /here` - moves file to here. I must be missing something because it never seems to work properly for me

`cp /this/file /to/here` - copy this file to here

`touch file` - create file

`man program` - shows the manual for program

`head file` - shows the first 10 lines of a file

`tail` - shows the last 10 lines of a file

`echo text` - prints text to terminal

`chmod ###` - change permissions where #1 refers to owner, #2 refers to user's group, #3 refers to everyone, and possible values range from 0-7. Read permissions are 4, write permissions are 2, execute permissions are 1. Can be written as 7=rwx, 6=rw-, 5=r-x, 4=r--, 3=-wx, 2=-w-, 1=--x, 0=---.

`[user] passwd` - change user's password

`useradd` - create a user - `userdel` to delete

`top` - shows what processes are running and other details

`this | that` - 'pipes' the output from this into the command that

`>` - same as pipe??

`this >> file` - appends this to file

`<` - backwards pipe??

`1>` - redirects STDIN

`2>` - redirects STDOUT

`0>` - redirects STDERR

`this && that` does that iff this completes succesfully

`this || that` does this or that

`wc <-l>` - gives a word count, where the option l counts lines

`ip` - contains a variety of tools for information about internet connection - link for setting up/down interfaces, addr for displaying current setup, etc

`find / -name this` - a basic tool for finding things in linux file system, this syntax finds a file called name. Other options include `-wholename`, which searches for directories in addition to files themselves

`grep` - a much more powerful tool for searching - option -r allows you to recursively search a directory for files containing a string

`awk` - another utility for finding things in linux which in its simples form can print something , e.g. `awk {print} /this/file` prints this file, `awk /match/ /in/here` prints lines with match in here, `/^match/` prints lines which begin with match

`sed` - allows you to modify a file from command line automatically - more on this later

`kill process` - a utility for killing processes which are running - priority can be set with numbers - e.g. `kill 9 process` is the most harsh version which kills the process no matter what

`sort` - sorts things by lines or other ways depending on options

`less` - allows you to scroll through output longer than the screen - often used as `do this | less` so you can read all the output created by do this

`cat file` - outputs the contents from file

`clear` - clears the terminal so you can start at the top again rather than continually being pushed to the bottom

`history` - shows you the last 500 commands you have done - you can set this to more by:


## Terminal Hotkeys

`CTRL+A` - jump to beginning of line
`CTRL+E` - jump to the end of the line
`CTRL+L` - same as `clear`

## Filesystem

## vim

Vim is a version of vi with more features. Vi is useful because it is found on almost every distribution of linux and therefore on almost every server. One of the major differences between the two is that you can use arrow keys in vim, whereas vi requires h-left, j-down, k-up, l-right

Before anything else, realize that vim has an edit mode and a command mode. Edit modes are accessed by pressing a letter, most generally i for 'insert mode'. There is also v for visual mode. You can always go back to command mode by clicking `esc`. Commands always begin with `:`. `:x` exits and saves the file.`:w`writes the file, `:q` quits (exits the file). `:x` is the same as `:wq`. `:q!` allows you to quit without saving. Clicking `R` from navigation mode will let you replace text by overwriting it.

`:vsplit /path/to/doc` opens another document and splits the screen so you can see both.
`:y` copies, `:p` pastes, `:yy` copies a line, `:dd` cuts a line
In navigation/command mode, use x to delete the letter that the cursor is currently on.
Use A to skip to the end of the line and insert (append)
w lets you skip between words, and dw lets you delete the rest of the word your cursor is currently on. d$ lets you delete the rest of the current line.

press u to undo a command. and CTRL+R to redo once you have undone it
p puts previously deleted text - for example you can delete a line with dd and then replace it below the cursor with dd

r+[character] lets you replace the character the cursor is on with the character you type in

ce changes until the end of the word - this deletes the rest of the current word and puts you into edit mode.

CTRL+G shows you your current location in the file - line x out of total

gg returns you to the beginning of the file and # G returns you to the ##th line

/thisphrase searches the current file for thisphrase - once you have found it, use n to go to the next instance of the same thing

% allows you to find the matching parentheses - get your cursor to the opening parentheses and then it should skip to the matching closing bracket

:%s/old/new/g to replace old with new throughout the file - make it gc to ask for confirmation each time, and use #,# in place of % to only do it for lines # to #

:! allows you to execute any external shell commans

use v (visual selection) to select a number of lines - then do a command on these lines - eg, d for delete, y for yank, etc.

:r FILE will insert (retrieve) the contents of file below the cursor - use :r !command to output the result of command

o opens a line below the cursor and puts you in insert mode - O opens a line above the cursor and puts you in insert mode.

:set lets you set options - for example, with /findthis, you can :set ic to ignorecase or hls (highlight search). Prepend no to shut off the option

set options for vim in ~/.vimrc

## Searching

### regex

#### Characters

`\d \D` digit/nondigit character

`\w \W` word/nonword character

`\s \S` space/nonspace character

#### Quantifiers

`+` one or more of preceding character

{x} exactly x times

{x,y} x to y times

`{x,}` x or more times

`*` more than once

`?` once or none

#### Logical

`|` OR

`(...)` capturing group?

`(?:...)` noncapturing group?

`\1` contents of group 1

`[...]` one of the characters in the brackets

`-` range indicator

`[x-y]` one of the characters in the range

`[^x-y]` one of the characters not in the range

#### Anchors

`^` start of string or start of line

`$` end of string or end of line

`\b` word boundary

### grep

Stands for global regex print

Options - `-i` case insensitive, `-w` whole word (not part of larger word), `-r` recursively through subfolders, `-v` inverse search (prints everything but what you searched for),

### find

`-name` lets you look for files by name, `-wholename` includes directories in this search.

## Hard Drive Utilities, Partitioning and Other Stuff

`umount` unmounts a filesystem

`fsck` filesystem check is used to check a drive for inconsistencies

`badblocks`is used to find bad sectors on a hard disk

`dd if=/from/here of=/to/here bs=1M` is used to convert and copy files - especially copying

`shred` is used for overwriting a hard disk with random data - this is useful for preventing forensic analysis and file-carving, for instance.

## Compiling and Installing

## Updates

## Backups

## Network Tools

### TCP/IP

### Physical Networking

### IP Routing

### DNS

### SSO

### Email

### Web Hosting

### Cloud Computing

### Security

### Performance Analysis

### Monitoring

### Virtualization

## tmux

Ctrl + b +

	% vertical " horizontal split
	o switch pane
	x kill pane
	+ make pane into window
	Hold Ctrl + b + [arrow key] to resize pane

	c create window
	, name window
	& kill window
	[#] switch to window #



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





	Linux Notes

	chroot - change root, allows you to operate on a new directory? UEFI - unified extensible firmware interface history - set in UEFI? ./bashrc? modular - linux kernel means many drivers are available as modules 192.168.1.1 - generally is the ip of home router SSID RSN systemctl drop-in file acpi - utility for battery life w3m - enter to input, q to quit hwclock --show - for time timedatectl uuid - unique ids for filesystems lsblk pacman - package manager for arch, like apt-get -Ss to search, -Rs to remove package and all dependencies wifi menu ip link set down wlp1s0 showconsolefont fstab - file used to define how disk partitions, other block devices, remote file systems should be mounted brightness - in arch, go to /sys/class/backlight/acpi_video and sudo tee brightness <<< value nmap netstat xorg - plasma desktop - sddm - kdc applications sudo needed for sddm to work df -h allows you to check for available space -i for ?
