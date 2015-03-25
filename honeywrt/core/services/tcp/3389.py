lastTS = ''

class tcp3389(Protocol):
	def connectionMade(self):
		logprint("[honeypot.HoneyPotFactory] New connection: %s:%s (%s:%s) [Session: %d]" % \
		(self.transport.getPeer().host, self.transport.getPeer().port, self.transport.getHost().host, self.transport.getHost().port, self.transport.sessionno))
	def dataReceived(self, data):
		global lastTS
		global gi
		tpkt_data = data[:4]
		x224_data = data[4:]
		v, junk, total_len = struct.unpack('!BBH', tpkt_data)		
#		logprint("[HoneyPotTransport.RDP,%s,%s] TPKT (v.%d and length %d)" % (self.transport.sessionno, self.transport.getPeer().host, v, total_len))
		if(len(data) == total_len):
			l, c = struct.unpack('BB',x224_data[:2])
			if c == 0xe0:
				x224 = struct.unpack('!HHBH', x224_data[2:9])
				logprint("[HoneyPotTransport.RDP,%s,%s] X224 Connection Request." % (self.transport.sessionno, self.transport.getPeer().host))
				self.transport.write(struct.pack('!BBHBBHHB', v, 0, 11, 6, 0xd0, x224[1], 0x1234, x224[2]))
#				logprint("[HoneyPotTransport.RDP,%s,%s] Login: (%s)" % (self.transport.sessionno, self.transport.getPeer().host, x224_data[6:33]))
				self.transport.loseConnection()
				if(lastTS != self.transport.getPeer().host):
					lastTS = self.transport.getPeer().host
					thread.start_new_thread(twitter_it, ("A host at %s (%s, %s - %s) tried to log into my honeypot's fake Terminal Services server... #netmenaces", lastTS))
			else:
#				logprint("[HoneyPotTransport.RDP,%s,%s] X224 Unrecognized code: " % (self.transport.sessionno, self.transport.getPeer().host))
#				print binascii.hexlify(data)
				self.transport.loseConnection()
				if(lastTS != self.transport.getPeer().host):
					lastTS = self.transport.getPeer().host
					thread.start_new_thread(twitter_it, ("A host at %s (%s, %s - %s) connected to my honeypot's fake Terminal Services server... #netmenaces", lastTS))	
		else:
#			logprint("[HoneyPotTransport.RDP,%s,%s] Data inconsistent... dropping connection." % (self.transport.sessionno, self.transport.getPeer().host))
#			print binascii.hexlify(data)
			self.transport.loseConnection()
			if(lastTS != self.transport.getPeer().host):
				lastTS = self.transport.getPeer().host
				thread.start_new_thread(twitter_it, ("A host at %s (%s, %s - %s) connected to my honeypot's fake Terminal Services server... #netmenaces", lastTS))
	def connectionLost(self, reason):
		self.state = 0

f = Factory()
f.protocol = tcp3389
