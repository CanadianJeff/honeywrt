class tcp1433(Protocol):
	def connectionMade(self):
		logprint("[honeypot.HoneyPotFactory] New connection: %s:%s (%s:%s) [Session: %d]" % \
		(self.transport.getPeer().host, self.transport.getPeer().port, self.transport.getHost().host, self.transport.getHost().port, self.transport.sessionno))
	def dataReceived(self, data):
		global lastMSSQL
		tds_type, size = struct.unpack('!BxH', data[:4])
		if(size == len(data)):
			p1 = 8
			nexttoken = 0
			if(tds_type == 0x12):
				tds_response_created = 0
				p2 = p1 + 6;
#				logprint("TDS 7/8 Prelogin packet on port %d from: %s (%d/TCP):" % (self.transport.getHost().port, self.transport.getPeer().host, self.transport.getPeer().port))
				while nexttoken != 0xff:
					tokentype, p, l, nexttoken = struct.unpack('!BHHB', data[p1:p2])
					if tokentype == 0:
						maj, minor = struct.unpack('!LH', data[p + 8:p + l + 8])
						tds_response = tds_response_a + binascii.hexlify(data[p + 8:p + l + 8]) + '0200'
						tds_response_created = 1
#						print "\tVersion:\n\t\tMaj: %s\n\t\tMin: %s" % (hex(socket.ntohl(maj)), hex(socket.ntohl(minor)))
					if tokentype == 1:
						enc, = struct.unpack('!B', data[p + 8:p + l + 8])
#						print "\tEncryption: ", enctype[enc]
					if (tokentype == 2) & (l > 1):
						logprint("")
#						print "\tInstance: ", data[p + 8:p + l + 8]
					if tokentype == 3:
						threadid, = struct.unpack('!L', data[p + 8:p + l + 8])
#						print "\tThread ID: ", threadid
					if tokentype == 4:
						mars, = struct.unpack('!B', data[p + 8:p + l + 8])
#						print "\tMARS: ", marstype[mars]
					p1 = p2 - 1
					p2 = p1 + 6
				if tds_response_created == 0:
					tds_response = tds_response_a + '080002fe00000200' 
				self.transport.write(binascii.unhexlify(tds_response))
			elif(tds_type == 0x10):
				p2 = p1 + 36
				logprint("[HoneyPotTransport,%s,%s] Login packet: (TDS 7/8)" % (self.transport.sessionno, self.transport.getPeer().host))
				if len(data) > p2:
					l, v, ps, cv, pid, cid, o1, o2, o3, r, tz, lc = struct.unpack('=LLLLLLBBBBLL', data[p1:p2])
					logprint("[HoneyPotTransport,%s,%s] Len: %s " % (self.transport.sessionno, self.transport.getPeer().host, l))
					logprint("[HoneyPotTransport,%s,%s] Version: %s " % (self.transport.sessionno, self.transport.getPeer().host, hex(socket.ntohl(v))))
					logprint("[HoneyPotTransport,%s,%s] Packet Size: %s " % (self.transport.sessionno, self.transport.getPeer().host, ps))
					logprint("[HoneyPotTransport,%s,%s] Client Version: %s " % (self.transport.sessionno, self.transport.getPeer().host, socket.ntohl(cv)))
					logprint("[HoneyPotTransport,%s,%s] Client PID: %s " % (self.transport.sessionno, self.transport.getPeer().host, pid))
					logprint("[HoneyPotTransport,%s,%s] Connection ID: %s " % (self.transport.sessionno, self.transport.getPeer().host, cid))
					logprint("[HoneyPotTransport,%s,%s] Option Flag 1: %s " % (self.transport.sessionno, self.transport.getPeer().host, o1))
					logprint("[HoneyPotTransport,%s,%s] Option Flag 2: %s " % (self.transport.sessionno, self.transport.getPeer().host, o2))
					logprint("[HoneyPotTransport,%s,%s] Option Flag 3: %s " % (self.transport.sessionno, self.transport.getPeer().host, o3))
					logprint("[HoneyPotTransport,%s,%s] Type Flag: %s " % (self.transport.sessionno, self.transport.getPeer().host, r))
					logprint("[HoneyPotTransport,%s,%s] Client TZ: %s " % (self.transport.sessionno, self.transport.getPeer().host, tz))
					logprint("[HoneyPotTransport,%s,%s] Client Language Code: %s " % (self.transport.sessionno, self.transport.getPeer().host, lc))
					p1 = p2
					p2 = p1 + 4
					for n in logindata:
						o, l = struct.unpack('=HH', data[p1:p2])
						if l > 0:
							if n == 'Password':
								pw = ''
								p = data[o + 8:o + (2 * l) + 8]
								for byte in p:
									b = ord(byte) ^ 0xa5
									reverse_b = (b & 0xf) << 4 | (b & 0xf0) >> 4
									pw = pw + chr(reverse_b)
#								print '\t%s: %s' % (n, pw.encode("utf-8"))
							else:
								s = data[o + 8:o + (2 * l) + 8]
								logprint("[HoneyPotTransport,%s,%s] %s: %s" % (self.transport.sessionno, self.transport.getPeer().host, n, s.encode("utf-8")))
						p1 = p2
						p2 = p1 + 4
					logprint("[HoneyPotTransport,%s,%s] Client ID: %s " % (self.transport.sessionno, self.transport.getPeer().host, binascii.hexlify(data[p1:p1+6])))
					self.transport.loseConnection()
					if(lastMSSQL != self.transport.getPeer().host):
						lastMSSQL = self.transport.getPeer().host
						thread.start_new_thread(twitter_it, ("A host at %s (%s, %s - %s) tried to log into my honeypot's fake MSSQL Server... #netmenaces", lastMSSQL))	
			else:
				logprint("[HoneyPotTransport.MSSQL,%s,%s] RAW DATA: \n(%s)" % (self.transport.sessionno, self.transport.getPeer().host, binascii.hexlify(data)))
				self.transport.loseConnection()
	def connectionLost(self, reason):
		self.state = 0

f = Factory()
f.protocol = tcp1433
