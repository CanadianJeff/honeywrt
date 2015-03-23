class tcp5977(Protocol):
	def connectionMade(self):
		logprint("[honeypot.HoneyPotFactory] New connection: %s:%s (%s:%s) [Session: %d]" % \
		(self.transport.getPeer().host, self.transport.getPeer().port, self.transport.getHost().host, self.transport.getHost().port, self.transport.sessionno))
	def dataReceived(self, data):
		global gi
		global last5977
		logprint("[HoneyPotTransport.TCP%s,%s,%s] Data (%s bytes)" % \
		(self.transport.getHost().port, self.transport.sessionno, self.transport.getPeer().host, len(data)))
		self.transport.loseConnection()
	def connectionLost(self, reason):
		self.state = 0

f = Factory()
f.protocol = tcp5977
