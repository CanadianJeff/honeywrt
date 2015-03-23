class tcp3306(Protocol):
	def connectionMade(self):
		logprint("[honeypot.HoneyPotFactory] New connection: %s:%s (%s:%s) [Session: %d]" % \
		(self.transport.getPeer().host, self.transport.getPeer().port, self.transport.getHost().host, self.transport.getHost().port, self.transport.sessionno))
		# MySQL Protocol
		self.transport.write(binascii.unhexlify('5b0000')) # Packet Length: 91
		self.transport.write(binascii.unhexlify('00')) # Packet Number: 0
		# Server Greeting
		self.transport.write(binascii.unhexlify('0a')) # Protocol: 10
		self.transport.write(binascii.unhexlify('352e352e33382d307562756e7475302e31342e30342e3100')) # MySQL Version String
		self.transport.write(binascii.unhexlify('40000000')) # Thread ID: 64
		self.transport.write(binascii.unhexlify('237c6b257336507200')) # Salt: <Generated>
		self.transport.write(binascii.unhexlify('fff7')) # Server Capabilities: 0xf7ff
		self.transport.write(binascii.unhexlify('08')) # Server Language: latin1
		self.transport.write(binascii.unhexlify('0200')) # Server Status: 0x0002
		self.transport.write(binascii.unhexlify('0f801500000000000000000000')) # Unused:
		self.transport.write(binascii.unhexlify('6a3f3c4f56432d54422f607800')) # Salt: <Generated>
		self.transport.write(binascii.unhexlify('6d7973716c5f6e61746976655f70617373776f726400')) # Payload
		self.transport.loseConnection()
	def dataReceived(self, data):
		global gi
		global last
		logprint("[HoneyPotTransport.TCP%s,%s,%s] Data (%s bytes)" % \
		(self.transport.getHost().port, self.transport.sessionno, self.transport.getPeer().host, len(data)))
		self.transport.loseConnection()
	def connectionLost(self, reason):
		self.state = 0

f = Factory()
f.protocol = tcp3306
