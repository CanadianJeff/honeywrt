class tcp4899(Protocol):
	def connectionMade(self):
		logprint("[honeypot.HoneyPotFactory] New connection: %s:%s (%s:%s) [Session: %d]" % \
		(self.transport.getPeer().host, self.transport.getPeer().port, self.transport.getHost().host, self.transport.getHost().port, self.transport.sessionno))
	def dataReceived(self, data):	
		global gi
		global lastRAdmind
		global RAdmindInit
		global RAdmindIHasPW
		if(data == RAdmindInit):
			logprint("[HoneyPotTransport.RADMIN,%s,%s] CONNECT" % (self.transport.sessionno, self.transport.getPeer().host))
			self.transport.write(binascii.unhexlify('01000000250800011008010008080000000000000000000000000000000000000000000000000000000000000000'))
			if(lastRAdmind != self.transport.getPeer().host):
				lastRAdmind = self.transport.getPeer().host
				thread.start_new_thread(twitter_it, ("A host at %s (%s, %s - %s) wants to use my honeypot's fake RAdmind... #netmenaces", lastRAdmind))
			self.transport.loseConnection()
		else:
			if(data == RAdmindIHasPW):
				logprint("[HoneyPotTransport.RADMIN,%s,%s] PASSWORD?" % (self.transport.sessionno, self.transport.getPeer().host))
				self.transport.write(binascii.unhexlify('01000000217BA977521B3BF0F3E2DCC7917B5A41C4FC0A92FF2251B16D3689417060F4170AB02A134A76'))
			else:
				logprint("[HoneyPotTransport.RADMIN,%s,%s] RAdmind data" % (self.transport.sessionno, self.transport.getPeer().host))
				self.transport.write(binascii.unhexlify('01000000010000000B0B0D0A0D0A'))	
				self.transport.loseConnection()
	def connectionLost(self, reason):
		self.state = 0

f = Factory()
f.protocol = tcp4899
