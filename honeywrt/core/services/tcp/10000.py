class tcp10000(Protocol):
	def connectionMade(self):
		logprint("[honeypot.HoneyPotFactory] New connection: %s:%s (%s:%s) [Session: %d]" % \
		(self.transport.getPeer().host, self.transport.getPeer().port, self.transport.getHost().host, self.transport.getHost().port, self.transport.sessionno))
	def dataReceived(self, data):
		if data[:14] == binascii.unhexlify('474554202F20485454502F312E30'): # HTTP 1.0
			logprint("[HoneyPotTransport.WEBMIN,%s,%s] NMAP SCAN DETECTED HTTP/1.0" % (self.transport.sessionno, self.transport.getPeer().host))
			self.transport.write(binascii.unhexlify('485454502f312e302032303020446f63756d656e7420666f6c6c6f77730d0a'))
			self.transport.write(binascii.unhexlify('5365727665723a204d696e69536572762f312e3639300d0a'))
			self.transport.write(binascii.unhexlify('446174653a205475652c20352041756720323031342030383a30303a323520474d540d0a436f6e74656e742d747970653a20746578742f68746\
d6c3b20436861727365743d69736f2d383835392d310d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a3c68313e4572726f72202d20446f63756d656e7420666f6c6c6f77733c2f68313e0a'))
			self.transport.write(binascii.unhexlify('\
3C7072653E5468697320776562207365727665722069732072756E6E696E6720696E2053534C206D6F64652E20547279207468652055524C203C6120687265663D2768747470733A2F2F6C6F63616C686F73742E\
6C6F63616C646F6D61696E3A31303030302F273E68747470733A2F2F6C6F63616C686F73742E6C6F63616C646F6D61696E3A31303030302F3C2F613E20696E73746561642E3C62723E3C2F7072653E0A'))
			self.transport.loseConnection()
		elif data[:4] == binascii.unhexlify('0d0a0d0a'):
#			logprint("[HoneyPotTransport.WEBMIN,%s,%s] NMAP" % (self.transport.sessionno, self.transport.getPeer().host))
			self.transport.loseConnection()
		elif data[:14] == binascii.unhexlify('474554202F20485454502F312E31'): # HTTP 1.1
			logprint("[HoneyPotTransport.WEBMIN,%s,%s] Sending Webmin HTML Page" % (self.transport.sessionno, self.transport.getPeer().host))
			self.transport.write(binascii.unhexlify('485454502f312e302032303020446f63756d656e7420666f6c6c6f77730d0a'))
			self.transport.write(binascii.unhexlify('5365727665723a204d696e69536572762f312e3639300d0a'))
			self.transport.write(binascii.unhexlify('446174653a205475652c20352041756720323031342030383a30303a323520474d540d0a436f6e74656e742d747970653a20746578742f68746\
d6c3b20436861727365743d69736f2d383835392d310d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a3c68313e4572726f72202d20446f63756d656e7420666f6c6c6f77733c2f68313e0a'))
			self.transport.write(binascii.unhexlify('\
3C7072653E5468697320776562207365727665722069732072756E6E696E6720696E2053534C206D6F64652E20547279207468652055524C203C6120687265663D2768747470733A2F2F6C6F63616C686F73742E\
6C6F63616C646F6D61696E3A31303030302F273E68747470733A2F2F6C6F63616C686F73742E6C6F63616C646F6D61696E3A31303030302F3C2F613E20696E73746561642E3C62723E3C2F7072653E0A'))
			self.transport.loseConnection()
	def connectionLost(self, reason):
		self.state = 0

f = Factory()
f.protocol = tcp10000
