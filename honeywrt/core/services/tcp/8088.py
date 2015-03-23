class tcp8088(Protocol):
	def connectionMade(self):
		logprint("[honeypot.HoneyPotFactory] New connection: %s:%s (%s:%s) [Session: %d]" % \
		(self.transport.getPeer().host, self.transport.getPeer().port, self.transport.getHost().host, self.transport.getHost().port, self.transport.sessionno))
	def dataReceived(self, data):
		if data[:14] == binascii.unhexlify('474554202F20485454502F312E31'): # HTTP 1.1
			logprint("[HoneyPotTransport.8088,%s,%s] Sending HTML Page" % (self.transport.sessionno, self.transport.getPeer().host))
#			self.transport.write(binascii.unhexlify('\
#485454502f312e302034303320466f7262696464656e0d0a436f6e74656e742d4c656e6774683a2032390d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a5768617420646f20796f752077616e\
#7420746f2073656520686572653f')
	def connectionLost(self, reason):
		self.state = 0

f = Factory()
f.protocol = tcp8088
