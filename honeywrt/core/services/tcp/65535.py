class tcp65535(Protocol):
	def connectionMade(self):
		logprint("[honeypot.HoneyPotFactory] New connection: %s:%s (%s:%s) [Session: %d]" % \
		(self.transport.getPeer().host, self.transport.getPeer().port, self.transport.getHost().host, self.transport.getHost().port, self.transport.sessionno))
	def dataReceived(self, data):
		global gi
		global last65535
		logprint("[HoneyPotTransport.TCP%s,%s,%s] Data (%s)" % \
		(self.transport.getHost().port, self.transport.sessionno, self.transport.getPeer().host, data.strip('0a')))
		self.transport.loseConnection()
	def connectionLost(self, reason):
		self.state = 0

f = Factory()
f.protocol = tcp65535
