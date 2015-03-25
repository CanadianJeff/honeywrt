from twisted.conch.telnet import TelnetTransport, TelnetProtocol
from twisted.conch import telnet
lastTELNET = ''

telnet_protocol_version = binascii.unhexlify('fffb01fffb03fffd18fffd1f') # Cisco router telnetd
#telnet_protocol_version = binascii.unhexlify('fffe1ffffe20fffe18fffe27fffc01fffe03fffc03') #

class tcp23(Protocol):
	def connectionMade(self):
		logprint("[honeypot.HoneyPotFactory] New connection: %s:%s (%s:%s) [Session: %d]" % \
		(self.transport.getPeer().host, self.transport.getPeer().port, self.transport.getHost().host, self.transport.getHost().port, self.transport.sessionno))

def processLine(self, line):
# I call a method that looks like 'telnet_*' where '*' is filled
# in by the current mode. telnet_* methods should return a string which
# will become the new mode. If None is returned, the mode will not change.
	mode = getattr(self, "telnet_"+self.mode)(line)
	if mode is not None:
		self.mode = mode

	def enableRemote(self, option):
		return False
	def disableRemote(self, option):
		pass
	def enableLocal(self, option):
		return False
	def disableLocal(self, option):
		pass

	def welcomeMessage(self):
		logprint("[HoneyPotTransport.TELNET,%s,%s] Sending MOTD: " % (self.transport.sessionno, self.transport.getPeer().host))
		self.writeln(self.fs.file_contents('/etc/motd'))

	def displayBANNER(self):
		logprint("[HoneyPotTransport.TELNET,%s,%s] Sending BANNER: " % (self.transport.sessionno, self.transport.getPeer().host))
		if self.displayBANNER:
			return
			cfg = config()
			if not cfg.has_option('honeypot', 'banner_file'):
				return
			try:
				self.writeln(self.fs.file_contents('/etc/banner'))
			except IOError:
				logprint("Banner file %s does not exist!" % cfg.get('honeypot', 'banner_file'))
				return
				if not data or not len(data.strip()):
					return
					data = '\r\n'.join(data.splitlines() + [''])
					self.transport.sendPacket(
					userauth.MSG_USERAUTH_BANNER, NS(data) + NS('en'))
					self.bannerSent = True

	def dataReceived(self, data):
		global gi
		global last
		logprint("[HoneyPotTransport.TCP%s,%s,%s] Data (%s bytes)" % \
		(self.transport.getHost().port, self.transport.sessionno, self.transport.getPeer().host, len(data)))
		self.transport.loseConnection()
	def connectionLost(self, reason):
		self.state = 0

#class PotTelnetFactory(protocol.ServerFactory, PotFactory):
	#protocol = lambda a: TelnetTransport(TelnetPotProtocol)
	#proto = 'telnet'

#internet.TCPServer(23, PotTelnetFactory).setServiceParent(serviceCollection)

f = Factory()
f.protocol = tcp23
