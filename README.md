# HoneyWRT Intrusion Detection System

This Honeypot is a low interaction Python honeypot that is designed to mimic a TON of services that might get targeted by attackers.
These services include:

    Remote Desktop Protocol (RDP) (TCP/3389)
    Virtual Network Computer (VNC) (TCP/5900)
    Fake Shoutcast Server (TCP/8000)
    Tomcat Admin Page /manage/html (TCP/8080)
    Microsoft SQL Server (MSSQL) (TCP/1433)
    Fake Telnet Server (TELNET) (TCP/23)

(For a full listing of ports this will listen on please see honeywrt.cfg.dist)

This Honeypot listens on specified ports for communication related to these services.
When an attacker attempts to access one of these services, an alert is generated in the honeypot.log file.

Since This Honeypot is just a Python script, all you need to do to run it is install the prerequisite
(the Python Twisted module) and then use Python to run it.

The following command will install the prerequisite in Debian based distro:
sudo apt-get install python-twisted

If you don’t want to run a particular service, simple place a pound symbol at the beginning of that services line. (honeywrt.cfg.dist)
This will cause the Python interpreter to skip this line and forgo starting a listener on the ports tied to these services. 

## YT Video Demo

Placeholder for Youtube Video

## Features

Some interesting features:
* Designed in a way that users can create their own fake services (see createservice.txt)

## Requirements

Software required:

* An operating system (tested on Debian, CentOS, FreeBSD)
* Python 2.5+
* Twisted 8.0+
* PyCrypto
* Zope Interface

Software optional:

* TCPDUMP
* Wireshark
* BasicAuth (pip install basicauth)

## How to run it?

Copy honeywrt.cfg.dist to honeywrt.cfg (so you have original as a backup)
Edit honeywrt.cfg to your liking

It can be executed by running the following command:
python honeypot.py >> honeypot.log
or ./start.sh

start.sh is a simple shell script that runs Honeywrt in the background using twistd. Detailed startup options can be given by running twistd manually.

## Meh

Files of interest:

* dl/ - malware packets will get saved here
* log/honeywrt.log - log/debug output

## Is it secure?

This is designed (by default) to emulate ALOT of services including ports <1024 which require root.

If you do not wish to run this as root you will need to comment out the lower ports or move them to higher ports
and port forward in your router

See FAQ

## I have some questions!

I ~~am~~ _might be_ reachable via e-mail: *djcanadianjeff* at *gmail* dot *com*, or as *djjeff* on the *#honeypots* channel in the *freenode* IRC network.

## Credit

HoneyWRT is inspired, but not based on [Kippo (Github)](https://github.com/desaster/kippo).
HoneyWRT is inspired, and Based on [Tom's honeypot](http://labs.inguardians.com/tomshoneypot.html).
