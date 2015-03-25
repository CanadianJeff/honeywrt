#!/usr/bin/python
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  

import twisted
from twisted.conch.insults import insults
#from twisted.application import service, internet
from twisted.internet import reactor, protocol, defer
from twisted.python import log
from zope.interface import implements
import sys, os, random, time, socket, thread, binascii, struct, unicodedata
from datetime import datetime

###
from twisted.internet.protocol import Protocol, Factory, ServerFactory, DatagramProtocol
from twisted.protocols import basic
from twisted.protocols.basic import LineReceiver
###

from honeywrt.core.config import config

# uncomment these if you want to use the tweeting functionality
#gi = GeoIP.open("/usr/share/GeoIP/GeoLiteCity.dat",GeoIP.GEOIP_STANDARD)
#import tweepy
#import GeoIP

myid = ''

Auth_String = binascii.unhexlify('417574686f72697a6174696f6e')
Basic_String = binascii.unhexlify('4261736963')

def logprint(x):
	now = datetime.now()
	t = now.strftime("%Y-%m-%d %H:%M:%S.%f") + " "
	print(t + x)

def logprint2(x):
	now = datetime.now()
	t = now.strftime("\n%Y-%m-%d %H:%M:%S.%f") + " "
	print(t + x)

def twitter_it(x, ip):
	#remove the "return" line and get OAUTH values from Twitter (http://dev.twitter.com) if you want to have this tweet
	return
	global myid
	wait = random.randint(60,600) + random.randint(60,600)
	time.sleep(wait)
	# necessary auth values
	CONSUMER_KEY = '<YOU NEED TO REPLACE THIS>'
	CONSUMER_SECRET = '<YOU NEED TO REPLACE THIS>'
	ACCESS_KEY = '<YOU NEED TO REPLACE THIS>'
	ACCESS_SECRET = '<YOU NEED TO REPLACE THIS>'
	# end auth values
	gir = gi.record_by_addr(ip)
	if gir != None:
		if gir['region_name'] != None:
			region = unicodedata.normalize('NFKD', unicode(gir['region_name'], 'iso-8859-1')).encode('ascii','ignore')
		else:
			region = 'N/A'
		if gir['city'] != None:
			city = unicodedata.normalize('NFKD', unicode(gir['city'], 'iso-8859-1')).encode('ascii','ignore')
		else:
			city = 'N/A'
	else:
		city = 'N/A'
		region = 'N/A'
	auth = tweepy.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
	auth.set_access_token(ACCESS_KEY, ACCESS_SECRET)
	api = tweepy.API(auth)
	if(gir != None):
		msg = x % (ip, gir['country_code'], region, city)
	else:
		msg = x % (ip, 'N/A', region, city)
	if myid != '':
		msg = msg + " " + myid
	api.update_status(msg)
	logprint("Tweeted: " + msg)

def geoip_it(x, ip):
#	return
	global myid
#	wait = random.randint(60,600) + random.randint(60,600)
#	time.sleep(wait)
	gir = gi.record_by_addr(ip)
	if gir != None:
		if gir['region_name'] != None:
			region = unicodedata.normalize('NFKD', unicode(gir['region_name'], 'iso-8859-1')).encode('ascii','ignore')
		else:
			region = 'N/A'
		if gir['city'] != None:
			city = unicodedata.normalize('NFKD', unicode(gir['city'], 'iso-8859-1')).encode('ascii','ignore')
		else:
			city = 'N/A'
	else:
		city = 'N/A'
		region = 'N/A'

	if(gir != None):
		msg = x % (ip, gir['country_code'], region, city)
	else:
		msg = x % (ip, 'N/A', region, city)
	if myid != '':
		msg = msg + " " + myid

	logprint(msg)

def basicauth_decode(x):
	from basicauth import decode
	encoded_str = '%s' % (basicauth_string)
	username, password = decode(encoded_str)

def basicauth_encode(x):
	from basicauth import encode
	username, password = '%s', '%s' % (basicauth_user, basicauth_pass)
	encoded_str = encode(username, password)

def _get_func(fullFuncName):
    """Retrieve a function object from a full dotted-package name."""

    # Parse out the path, module, and function
    lastDot = fullFuncName.rfind(u".")
    funcName = fullFuncName[lastDot + 1:]
    modPath = fullFuncName[:lastDot]

    aMod = __import__(modPath, globals(), locals(), ['*'])
    aFunc = getattr(aMod, funcName)

    # Assert that the function is a *callable* attribute.
    assert callable(aFunc), u"%s is not callable." % fullFuncName

    # Return a reference to the function itself,
    # not the results of the function.
    return aFunc

def _get_class(fullClassName, parentClass=None):
    """Load a module and retrieve a class (NOT an instance).

    If the parentClass is supplied, className must be of parentClass
    or a subclass of parentClass (or None is returned).
    """
    aClass = _get_func(fullClassName)

    # Assert that the class is a subclass of parentClass.
    if parentClass is not None:
        if not issubclass(aClass, parentClass):
            raise TypeError(u"%s is not a subclass of %s" %
                            (fullClassName, parentClass))

    # Return a reference to the class itself, not an instantiated object.
    return aClass

#class flushfile(object):
#	def __init__(self, f):
#		self.f = f
#	def write(self, x):
#		self.f.write(x)
#		self.f.flush()

class PotFactory:
	dbpool = None

	def __init__(self, logfile=None, dburl=None):
		self.logfile = logfile

class tDUMP(Protocol):
	def connectionMade(self):
		logprint("[honeypot.HoneyPotDUMPFactory] New connection: %s:%s (%s:%s) [Session: %d]" % \
		(self.transport.getPeer().host, self.transport.getPeer().port, self.transport.getHost().host, self.transport.getHost().port, self.transport.sessionno))
	def dataReceived(self, data):
#		logprint("[HoneyPotTransport.DUMPER,%s,%s] RAW DATA: \n(%s)" % (self.transport.sessionno, self.transport.getPeer().host, binascii.hexlify(data)))
		self.transport.loseConnection()

class tPROXY(Protocol):
	def connectionMade(self):
		logprint("[honeypot.HoneyPotDUMPFactory] New connection: %s:%s (%s:%s) [Session: %d]" % \
		(self.transport.getPeer().host, self.transport.getPeer().port, self.transport.getHost().host, self.transport.getHost().port, self.transport.sessionno))
		
		reactor.connectTCP(self.transport.getPeer().host, self.transport.getPeer().port, factory)
	def dataReceived(self, data):
#		logprint("[HoneyPotTransport.DUMPER,%s,%s] RAW DATA: \n(%s)" % (self.transport.sessionno, self.transport.getPeer().host, binascii.hexlify(data)))
		self.transport.write(data)
		self.transport.loseConnection()

class uDUMP(DatagramProtocol):
	def connectionMade(self):
		logprint("[honeypot.HoneyPotDUMPFactory] New connection: %s:%s (%s:%s) [Session: %d]" % \
		(self.transport.getPeer().host, self.transport.getPeer().port, self.transport.getHost().host, self.transport.getHost().port, self.transport.sessionno))
	def datagramReceived(self, data, (host, port)):
		self.transport.loseConnection()


random.seed()
#sys.stdout = flushfile(sys.stdout)

logprint("[INFO] Checking Ports...")

import ConfigParser

cfg = config()
if cfg.has_option('honeypot_listen', 'listen_addr'):
    interface = cfg.get('honeypot_listen', 'listen_addr')
else:
    interface = '0.0.0.0'

### TCP SECTION

logprint("[INFO] Checking TCP...")

for section in cfg.sections():
	if section == ('honeypot_tcp_ports'):
		for option in cfg.options(section):
			if cfg.has_option('honeypot_tcp_ports', option):
				port = cfg.get(section, option)
				
				module = '%s' % (port,)
#				logprint("Init Port: %s" % (port))
				
				file = 'honeywrt/core/services/tcp/%s.py' % (port)
				
				if os.path.isfile(file):
					with open(file, 'r') as filename:
						execfile(file)
#						f = protocol.Factory()
#						logprint("Factory TCP: %s" % (f))
						
						try:
							c = ('%s.tcp%s' % (__name__, port))
						except ImportError:
							print 'Import Error'
						
#						f.protocol = c
#						logprint("Factory Protocol: %s" % (f.protocol))
						
						s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						result = s.connect_ex(('0.0.0.0', int(cfg.get(section,option))))
						
						if result == 0:
							logprint("[CRIT] TCP Port %s - Socket In Use... SKIPPING" % (port))
						s.close
						
						if result == 111:
							reactor.listenTCP(
								int(cfg.get(section,option)),
								f,
								interface = interface
							)
				
				else:
					logprint("[WARN] TCP Port %s - Starting Listener (Default Settings)" % (port))
					f = Factory()
					f.protocol = tDUMP
					reactor.listenTCP(
						int(cfg.get(section,option)),
						f,
						interface = interface
					)

### UDP SECTION

logprint("[INFO] Checking UDP...")

for section in cfg.sections():
	if section == ('honeypot_udp_ports'):
		for option in cfg.options(section):
			if cfg.has_option('honeypot_udp_ports', option):
				port = cfg.get(section, option)
				
				module = '%s' % (port,)
#				logprint("Init Port: %s" % (port))
				
				file = 'honeywrt/core/services/udp/%s.py' % (port)
				
				if os.path.isfile(file):
					with open(file, 'r') as filename:
						execfile(file)
#						f = protocol.Factory()
#						logprint("Factory TCP: %s" % (f))
						
						try:
							c = ('%s.tcp%s' % (__name__, port))
						except ImportError:
							print 'Import Error'
						
#						f.protocol = c
#						logprint("Factory Protocol: %s" % (f.protocol))
#						
#						reactor.listenTCP(
#							int(cfg.get(section,option)),
#							f,
#							interface = interface
#						)
#				else:
#					logprint("Dumping Raw TCP %s" % (strport))
#					f = Factory()
#					f.protocol = tDUMP
#					reactor.listenTCP(
#						int(cfg.get(section,option)),
#						f,
#						interface = interface
#					)

if cfg.has_option('honeypot', 'tcpdump_enabled'):
	logprint("[INFO] TCPDUMP Is Enabled...")
	if cfg.has_option('honeypot', 'tcpdump_iface'):
		tcpdump_iface = cfg.get('honeypot', 'tcpdump_iface')
		logprint("[INFO] Listen Interface Set To %s" % (tcpdump_iface))
		if cfg.has_option('honeypot', 'tcpdump_pcap_folder'):
			tcpdump_pcap = cfg.get('honeypot', 'tcpdump_pcap_folder')
			tcpdump_pcap = ('%s/%s.pcap' % (tcpdump_pcap, time.strftime("%m%d%Y%H%M%S")))
			logprint("[INFO] Using PCAP File: %s" % (tcpdump_pcap))
		else:
			tcpdump_pcap = '/tmp/honeypot.pcap'
			logprint("[INFO] Using PCAP File: %s" % (tcpdump_pcap))
		if interface != '0.0.0.0':
			logprint("[INFO] Starting TCPDUMP on %s..." % (tcpdump_iface))
			os.system("tcpdump -s0 -U -i %s -w %s '(host %s) and (tcp or udp)' 1>/dev/null 2>/dev/null &" % (tcpdump_iface, tcpdump_pcap, interface))
			tcpdump = 'running'
		else:
			logprint("[WARN] Listen Address Is 0.0.0.0 Capturing All Data!!")
			os.system("tcpdump -s0 -U -i %s -w %s '(tcp or udp)' 1>/dev/null 2>/dev/null &" % (tcpdump_iface, tcpdump_pcap))
			tcpdump = 'running'
else:
	logprint("[INFO] TCPDUMP Is Disabled...")

if tcpdump == 'running':
	if cfg.has_option('honeypot', 'wireshark_enabled'):
		logprint("[INFO] Opening Wireshark...")
		os.system("sleep 3")
		os.system("tail -f %s 2>/dev/null | wireshark -k -i - 1>/dev/null 2>/dev/null &" % (tcpdump_pcap))
	else:
		logprint("[INFO] Wireshark Disabled")
else:
	logprint("")


logprint("[INFO] Starting reactor...")

reactor.run()

logprint2("[INFO] Cleaning up...")
os.system("killall tcpdump 2>/dev/null")
logprint("[INFO] Removing *.pyc Crap...")
os.system("find . -name *.pyc -type f -exec rm -rf {} \;")

logprint("[INFO] Shutting down...")
quit()
