

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

# Web App Hacking

## OWASP Top 10

## OTGv4

## Info Gathering

`dirb http://ip`

wpscan - `wpscan --url http://testhere --enumerate u`


## Mapping Application

## Organization Tools and Techniques

## Types of Attack

### Open Redirect

### HTTP Parameter Pollution

### Cross Site Request Forgery

### HTML Injection

### CRLF Injection

### XSS

### Template Injection

### SQLi

### SSRF

### XXE

### Remote Code Execution

### Buffer Overflow

### Subdomain Takeover

### Race Conditions

### IDOR

### OAuth

### Application Logic Vulnerabilities

# Security+

## Security Basics

## Identity and Access Management

## Networking

## Securing Networks

## Securing Hosts and Data

## Threats and Vulnerabilities

## Advanced Attacks

## Risk Management

## Controls to Protect Assets

## Cryptography and PKI

## Policies

# Map of Bug Bounty Methodology

# Web Architecture Section

# Ippsec Notes

# Next Steps

## Automation

## Machine Learning Applications
