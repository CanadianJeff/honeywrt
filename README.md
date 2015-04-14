# HoneyWRT Intrusion Detection System

HoneyWRT is a low interaction Python honeypot that is designed to mimic services or ports that might get targeted 
by attackers.

These include but are not limited to:

    Remote Desktop Protocol (RDP) (TCP/3389)
    Virtual Network Computer (VNC) (TCP/5900)
    Fake Shoutcast Server (TCP/8000)
    Tomcat Admin Page /manage/html (TCP/8080)
    Microsoft SQL Server (MSSQL) (TCP/1433)
    Fake Telnet Server (TELNET) (TCP/23)

(For a full listing of included ports this will listen on please see honeywrt.cfg.dist)

HoneyWRT listens on specified ports for communication related to these services.
When an attacker attempts to access one of these services or ports, it gets added in the log file.

The following command will install the prerequisite in Debian based distro:
sudo apt-get install python-twisted python-pcapy

If you don’t want to run a particular service or port, place a pound symbol (#) at the beginning of that line.
This will cause the Python interpreter to skip the line and forgo starting a listener on the port. 

## YT Video Demo

Placeholder for Youtube Video

## Features

Some interesting features:
* Designed in a way that users can create their own fake services (see doc/createservice.txt)

## Requirements

Software required:

* Linux operating system (tested on Debian, CentOS, FreeBSD)
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
twistd -u 0 -g 0 -y honeywrt/core/honeypot.py --pidfile /var/run/honeywrt.pid
or just ./start.sh

start.sh is a simple shell script that runs Honeywrt in the background using twistd.
Detailed startup options can be given by running twistd manually.

using (twistd -n) for example will run in the foreground for debugging

## Extra

Folders/Files of interest:

* /data - packets will get saved here (soon)
* /log - log/debug output

## Is it secure?

This is designed (by default) to emulate ALOT of services including ports <1024 which require root.

If you do not wish to run this as root you will need to comment out the lower ports or move them to higher ports
and port forward in your router

## I still have some questions!

I ~~am~~ or _might be_ reachable via e-mail: *djcanadianjeff* at *gmail* dot *com*, or as *djjeff* on 
the *freenode* IRC network.

## Support and more information

Try our website: http://www.honeywrt.org/

## Work In Progress

- use python to check for pcapy and twisted warn user and exit if not found
- switch to pcapy from tcpdump method
- start setting up for database logging (sqlite? mysql?)
- get .tac file to work properly
- if pcapy does not work go for raw sockets and dump data that way
- log data hits to logfile with port number in its name (data/TCP_5900.log)

## Credit

HoneyWRT is inspired, but not based on [Kippo (Github)](https://github.com/desaster/kippo).
HoneyWRT is inspired, and Based on [Tom's honeypot](http://labs.inguardians.com/tomshoneypot.html).
