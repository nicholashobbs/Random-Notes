UBOS:
 don't edit iptables.rules as it will be overwriten on every setnetconfig

iptables

Based on the code for filtering ipv4 packets, which is already built into the kernel. These rules are organized in a collection of tables, each of which has a specific purpose. Tables are made up of predefined chains, which are sets of rules traversed in order. Each rule has an action (called a target) which is executed if the 'predicate' is true.

This picture https://www.frozentux.net/iptables-tutorial/images/tables_traverse.jpg is the core of how iptables works - lowercase is the table and uppercase is the chain. Every ip packet that comes in on any interface passes through this flow from top to bottom. Most of the time, you don't need to use the raw, mangle or security tables at all.

there are five tables in iptables:
1. `raw` is used for configuring packets
2. `filter` is the default table, where most firewalling occurs
3. `nat` is used for network address translation
4. `mangle` is used for specialized packet alterations
5. `security` is used for MAC (mandatory access control) networking rules, such as selinux.

Normally, you will just use filter and nat.

`filter`, which is the default table, contains three built-in chains: `INPUT`, `OUTPUT`, `FORWARD`. `nat` includes the chains `PREROUTING`, `POSTROUTING`, and `OUTPUT`.


Packet filtering is all based on rules, where a packet has to match conditions and then a target (action taken when the packet matches) is applied. in rules, targets are specified using `-j` or `--jump`

As with other services (put this elsewhere)

if you want iptables to be loaded automatically on boot, you must enable it. If you edit the configuration file manually, you have to reload iptables.

`-S` shows the rules currently activated, `-L` is the same with more detail.

the `LOG` target is used to log packets that hit a rule. Unlike other targets, the packet will continue moving after hitting LOG. `logdrop` prevents hackers or poorly configured services from filling the logs - you can limit with `-m limit`, setting an average rate with `--limit #/m`

logged packets are visible as kernel messages in the systemd journal.


iptables will use /var/log/messages by default, if you want to change this you can change it in `/etcsyslog.conf` from `kern.warning /var/log/messages` to wherever you would like them to go.

----------------------------------------------------------

Install ipt-netflow - but first we have to install yaourt (or build packages manually..)

Ping isn't working after shorewall start. It works again after shorewall clear, but messages are still coming up. I tried shorewall show log and apparently I haven't set up the logs either. I guess this is to be expected when I threw on the sample config and expected that to work. I will go back and read through my notes again and see if i can change some configurations to get it working.


Finally, after installing UBOS instead of Arch Arm, i got it working. It was ridiculously simple after all the issues I have had with arch. The hardest part was setting up my sd card as a SATA device in Virtualbox so I could edit it from my Kali vm. Once I went through a basic installation procedure, all I had to do was put in `ubos-admin setnetconfig gateway`, and everything is automatically setup. Clearly there will still be some changes to be made, but I alos have the option of setting it up as a container, or a variety of other preconfigured devices. I had issues shutting down the espressobin for a little while once I got it working. Just run `systemctl shutdown`.

----------------------------------------------------------------

I will refer to files in `/etc/shorewall/` as just `/file`

Shorewall requires iproute

Configuration files for shorewall are contained in `/etc/shorewall`

Find shorewall documentation directory using fgrep - in this directory are samples under two-interfaces or three-interfaces for 5.0.14 or later

Type man `shorewall-zones` to check `shorewall/zones` file functionality

Shorewall views the network as composed of a set of zones - `fw`, `net`, and `loc` - these are defined in `shorewall/zones`

The name of the firewall zone is stored in a shell variable `$FW`

Rules about what traffic to accept and deny are expressed in terms of zones

The default policy is stored in `shorewall/policy`, exceptions to the policy are defined in `shorewall/rules`

For each connection entering the firewall, the request is checked against `/rules` - if no rule matches the connection, then the first policy that matches in `/policy` is applied.

If there is a common action defined in `/actions` or `/usr/share/shorewall/actions.std` then that action is performed first. The common action silently drops/rejects harmless common traffic, such as broadcasts, which might clutter your log. It also ensures that critical traffic, such as ICMP fragmentation-needed, is allowed through the firewall.

In the two interface sample, the `/policy` file has `loc->net ACCEPT`, `net->all DROP info` and `all->all REJECT info`. If you want firewall to have full access to servers on the internet, uncomment `$FW->net ACCEPT`

Shorewall policies refer to connections, not packet flow. e.g. loc can connect to net even though loc cannot connect to `$FW`.

If you want to consider the firewall part of the local network from a security perspective, add the policies `loc -> $FW ACCEPT` and vice versa

`eth0` is the external interface - if you use point-to-point protocol over ethernet or point-to-point tunneling protocol, the external interface will be `ppp0`. If you use ISDN, the external interface will be `ippp0`. If your external interface is `ppp0` or `ippp0`, you will want to set `CLAMPMSS=yes` in `/shorewall.conf`

Type `ip route ls` to find out the external interface - it will be the default (last) route listed

The internal interface will be an ethernet adapter `eth0` or `eth1`, connected to a hub or switch (or your computer) - be sure to never connect internal and external interfaces to the same hub or switch as this creates a bridge over the firewall. The firewall should have exactly one default route via the ISP's router, and you should not try to configure a default route on your internal interface.

If the internal interface is a bridge created with `brctl`, you must add the routeback option to the option list. Specify options in `/interfaces` - you can also change configuration of interfaces here.

The external address is assigned via DHCP - in very rare cases the ISP might give you a static IP

Assign your own addresses in the internal network on the IP ranges defined in RFC 1918 (10/8, 172.16/12, 192.168/16). Convention is to assign the internal interface the first or last usable address in the subnet. Computers in the subnet should be configured with their default gateway as the IP address of the firewall's internal interface. These addresses are sometimes called non-routable.

Computers can communicate directly with other computers in the subnet, whereas they must send packets through a gateway to communicate with computers outside.

If your ISP assigns your external interface an RFC 1918 address, you must select a different subnet for your local network.

When a local system sends a connection request to an internet host, the firewall must perform NAT - rewriting the source address in the packet to be the address of the firewall's external interface. This allows the destination host to send packets back to the firewall, which forwards them to their correct desination on the internal network. This is refered to as IP masquerading.

SNAT (source NAT) is where you specify the source address that you want outbound packets from the local network to use. Masquerading is where the firewall system automatically detects the external interface address.

Masquerading is for dynamic external ip and configured in `/masq`. SNAT is for static external ip and configured in `/snat`.

Shorewall relies on netfilter system logs. shorewall show log displays last 20 netfilter messages, logwatch polls log at settable interval, dump produces an extensive report for problem reports. When you encounter connection problems with shorewall running, the first thing to do is to look at the netfilter log. Find where netfilter logs are stored based on the distribution you are running. To change this, modify the LOGFILE setting in `/shorewall.conf`.

Port Forwarding or Destination NAT is the process by which the firewall rewrites destination address to forward packets coming into the internal network. When the server responds, the firewall then performs SNAT.

A simple port forwarding rule for connections from net to loc is `DNAT net loc: protocol port`

Shorewall has macros for popular settings such as this. Look at shorewall show macros to see what is available. Macros supply the protocol and port.

Shorewall assumes that the service is using a standard port. You must test rules from outside the local network. Many ISPs block incoming connection requests to port 80. If you have problems connecting to a web server, try connecting to a different port.

DNS resolver is automatically configured when connecting to ISP (`/etc/resolv.conf` is written). You can either configure internal systems to use ISP name servers, or you can configure a Caching Name Server - this configures internal systems to use the firewall itself as the primary (and only) name server. Use the internal IP of the firewall for the name server address. To allow local systems to communicate with caching name server, you must open port 53 for both UDP and TCP from the local network to the firewall in `/rules`.

Using coded rules is slightly faster than using invoked macros.
ADDITIONAL:

ip addresses are properties of systems, not interfaces.

All ip addresses configured on firewall interfaces are in the firewall `$FW` zone.

Reply packets do not automatically follow the same path the arrived by.

Installation configures your system to start shorewall at system boot, but startup is disabled until you set `STARTUP_ENABLED=Yes` in `/shorewall.conf`. This is so your system doesnt start shorewall before configuration is complete.

The firewall is started using `shorewall start` and stopped using `shorewall stop`. Routing is enabled when the firewall is stopped on hosts with an entry in /routestopped and /stoppedrules. A running firewall can be restarted with `shorewall reload`.  If you want to remove any trace of shorewall from netfilter config, use `shorewall clear`.

If you are connected to the firewall from the internet, do not issue `shorewall stop` unless you have set `ADMINABSENTMINDED=Yes` in `/shorewall.conf`, or added an entry for the IP you are connected from to `/routestopped`. `shorewall reload` is not recommended, it is better to create alternative configuration and test with `shorewall try`.

I had to reconfigure to use Serial Port on windows - just making a quick note here that what I had to do was shut down the kali virtualbox, go into settings, enable PORT 3 and call it COM3, then go into linux and use it as `/dev/ttyS2`. If you have to shut down the serial port, for whatever reason you must reboot the virtual machine after. *note* I have had a difficult time with the device working properly on every machine I have used it with. The text gets jarbled and seems to overwrite itself and not write correctly to the console for whatever reason.

copy sample files by cding into `/usr/share/doc/shorewall/Samples/two-interface` and using `cp (file, file) /etc/shorewall`.

Edit the files according to your preferences after reading prior document.

Before changing settings in shorewall,

- assign the LAN interface a static IP and enable IP forwarding, masquerading in `etc/systemd/network/br0.network`

- confirm that the WAN facing interface will request an address from the ISP in `/etc/systemd/network/wan.network`

I only made a few simple changes, including adding `DNS(ACCEPT) loc $FW` to `/rules` and adding `wan ipv4` and `br0 local` to `/zones`

After I tried `shorewall start`, I started getting some very confusing messages. My espressobin seems to have some connection issue where text occasionally gets garbled. This was happening along with the following messages:

`IPv4: martian source 192.168.1.114 from 192.168.1.1, on dev wan`

A martian packet is a packet which comes from an impossible source - for example something from an RFC 1918 address which is routed accross the internet, or any packet with localnet IP on an interface which is not the loopback.

`nf_conntrack: default automatic helper assignment has been turned off for security reasons and CT-based  firewall rule not found. Use the iptables CT target to attach helpers instead.`
