Install ipt-netflow - but first we have to install yaourt (or build packages manually..)

Ping isn't working after shorewall start. It works again after shorewall clear, but messages are still coming up. I tried shorewall show log and apparently I haven't set up the logs either. I guess this is to be expected when I threw on the sample config and expected that to work. I will go back and read through my notes again and see if i can change some configurations to get it working.


Finally, after installing UBOS instead of Arch Arm, i got it working. It was ridiculously simple after all the issues I have had with arch. The hardest part was setting up my sd card as a SATA device in Virtualbox so I could edit it from my Kali vm. Once I went through a basic installation procedure, all I had to do was put in `ubos-admin setnetconfig gateway`, and everything is automatically setup. Clearly there will still be some changes to be made, but I alos have the option of setting it up as a container, or a variety of other preconfigured devices. I had issues shutting down the espressobin for a little while once I got it working. Just run `systemctl shutdown`.
