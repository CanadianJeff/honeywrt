class tcp27015(Protocol):
	def connectionMade(self):
		logprint("[honeypot.HoneyPotFactory] New connection: %s:%s (%s:%s) [Session: %d]" % \
		(self.transport.getPeer().host, self.transport.getPeer().port, self.transport.getHost().host, self.transport.getHost().port, self.transport.sessionno))
	def dataReceived(self, data):
		global gi
		self.state = (self.state) + 1
		logprint("[HoneyPotTransport.STEAM,%s,%s] STATE %s DATA:           (%s)" % (self.transport.sessionno, self.transport.getPeer().host, self.state, binascii.hexlify(data)))
	def connectionLost(self, reason):
		self.state = 0

f = Factory()
f.protocol = tcp27015
