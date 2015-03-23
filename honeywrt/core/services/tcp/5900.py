vnc_version_003 = binascii.unhexlify("524642203030332e3030330a") # RFB 003.003
vnc_version_004 = binascii.unhexlify("524642203030332e3030340a") # RFB 003.004
vnc_version_005 = binascii.unhexlify("524642203030332e3030350a") # RFB 003.005
vnc_version_006 = binascii.unhexlify("524642203030332e3030360a") # RFB 003.006
vnc_version_007 = binascii.unhexlify("524642203030332e3030370a") # RFB 003.007
vnc_version_008 = binascii.unhexlify("524642203030332e3030380a") # RFB 003.008
vnc_server_version = (vnc_version_008)
vnc_auth_challenge = binascii.unhexlify('00112233445566778899AABBCCDDEEFF')

class tcp5900(Protocol):
	def connectionMade(self):
		global vnc_server_version
		global lastVNC
		clientIP = self.transport.getPeer().host
		logprint("[honeypot.HoneyPotFactory] New connection: %s:%s (%s:%s) [Session: %d]" % \
		(self.transport.getPeer().host, self.transport.getPeer().port, self.transport.getHost().host, self.transport.getHost().port, self.transport.sessionno))
#		logprint("[HoneyPotTransport.VNC,%s,%s] Our Local VNC Version:  (%s)" % (self.transport.sessionno, self.transport.getPeer().host, binascii.b2a_qp(vnc_server_version[:11])))
#		logprint("[HoneyPotTransport.VNC,%s,%s] Our Local VNC Version:  (%s)" % (self.transport.sessionno, self.transport.getPeer().host, binascii.hexlify(vnc_server_version)))
		self.transport.write(vnc_server_version)
		self.state = 0
	def packetReceived(self, packet):
		logprint("[HoneyPotTransport.VNC,PACKET] MMMMMM PACKETS")
	def dataReceived(self, data):
		global gi
		global lastVNC
		self.state = (self.state) + 1
#		logprint("[HoneyPotTransport.VNC,%s,%s] STATE %s DATA:           (%s)" % (self.transport.sessionno, self.transport.getPeer().host, self.state, binascii.hexlify(data)))
		if self.state == 0:
#			logprint("[HoneyPotTransport.VNC,%s,%s] Didnt get any data: " % (self.transport.sessionno, self.transport.getPeer().host))
			self.transport.loseConnection()
		if self.state == 1:
			rfb_check = data[:4]
			if rfb_check != binascii.unhexlify('52464220'):
				os.system("espeak 'VNC CLIENT FAILED!'")
				logprint("[HoneyPotTransport.VNC,%s,%s] RFB CLIENT:             (FAIL)" % (self.transport.sessionno, self.transport.getPeer().host))
				logprint("[HoneyPotTransport.TCP%s,%s,%s] Data (%s bytes)" % \
				(self.transport.getHost().port, self.transport.sessionno, self.transport.getPeer().host, len(data)))
				self.state = 0
				self.transport.loseConnection()
			else:
				vnc_client_version = data[:12]
				logprint("[HoneyPotTransport.VNC,%s,%s] Got Remote VNC Version: (%s)" % (self.transport.sessionno, self.transport.getPeer().host, binascii.b2a_qp(vnc_client_version[:11])))
#				logprint("[HoneyPotTransport.VNC,%s,%s] Got Remote VNC Version: (%s)" % (self.transport.sessionno, self.transport.getPeer().host, binascii.hexlify(vnc_client_version)))
				if(lastVNC != self.transport.getPeer().host):
					lastVNC = self.transport.getPeer().host
					thread.start_new_thread(twitter_it, ("A host at %s (%s, %s - %s) connected to my honeypot's fake VNC server... #netmenaces", lastVNC))
				if binascii.hexlify(vnc_client_version) == binascii.hexlify(vnc_version_008):
					self.transport.write(binascii.unhexlify('0102'))
#					logprint("[HoneyPotTransport.VNC,%s,%s] Sending security types: (0102)" % (self.transport.sessionno, self.transport.getPeer().host))
				else:
					self.transport.write(binascii.unhexlify('00000002'))
#					logprint("[HoneyPotTransport.VNC,%s,%s] Sending security types: (00000002)" % (self.transport.sessionno, self.transport.getPeer().host))
					self.transport.write(vnc_auth_challenge)
					logprint("[HoneyPotTransport.VNC,%s,%s] Sending auth challange: (%s)" % (self.transport.sessionno, self.transport.getPeer().host, binascii.hexlify(vnc_auth_challenge)))
		if self.state == 2:
			if data == binascii.unhexlify('02'):
#				logprint("[HoneyPotTransport.VNC,%s,%s] Client Wants Security:  (%s)" % (self.transport.sessionno, self.transport.getPeer().host, binascii.hexlify(data)))
				self.transport.write(vnc_auth_challenge)
				logprint("[HoneyPotTransport.VNC,%s,%s] Sending auth challange: (%s)" % (self.transport.sessionno, self.transport.getPeer().host, binascii.hexlify(vnc_auth_challenge)))
				self.state = 1
			elif data == binascii.unhexlify('01'):
				logprint("[HoneyPotTransport.VNC,%s,%s] Client Want Encryption: (01)" % (self.transport.sessionno, self.transport.getPeer().host))
				self.transport.loseConnection()
			else:
				vnc_auth_response = data
				logprint("[HoneyPotTransport.VNC,%s,%s] We got auth response:   (%s)" % (self.transport.sessionno, self.transport.getPeer().host, binascii.hexlify(vnc_auth_response)))
				if binascii.hexlify(vnc_auth_challenge) == binascii.hexlify(vnc_auth_response):
					logprint("[HoneyPotTransport.VNC,%s,%s] Sending auth results:   (00000000)" % (self.transport.sessionno, self.transport.getPeer().host))
					self.transport.write(binascii.unhexlify('00000000'))
					lastVNC = self.transport.getPeer().host
#					thread.start_new_thread(geoip_it, ("[HoneyPotTransport.VNC,0,%s] GeoIP Lookup Info:      (%s, %s - %s)", lastVNC))
					self.transport.loseConnection()
				else:
					logprint("[HoneyPotTransport.VNC,%s,%s] Sending auth results:   (00000001)" % (self.transport.sessionno, self.transport.getPeer().host))
					self.transport.write(binascii.unhexlify('00000001'))
#					logprint("[HoneyPotTransport.VNC,%s,%s] Password Check:         (FAILED!)" % (self.transport.sessionno, self.transport.getPeer().host))
#					self.transport.write(binascii.unhexlify('0000001670617373776f726420636865636b206661696c656421'))
					self.transport.write(binascii.unhexlify('000000166675636B20796F75722073686974206E696767657221'))
					lastVNC = self.transport.getPeer().host
#					thread.start_new_thread(geoip_it, ("[HoneyPotTransport.VNC,0,%s] GeoIP Lookup Info:      (%s, %s - %s)", lastVNC))
					self.transport.loseConnection()
		if self.state == 3:
			if data == binascii.unhexlify('01'):
				logprint("[HoneyPotTransport.VNC,%s,%s] We got data:            (%s) " % (self.transport.sessionno, self.transport.getPeer().host, binascii.hexlify(data)))
#				self.transport.write(binascii.unhexlify('043a02ff2018000100ff00ff00ff1008000000000000000d4745525449452d445747445747'))
#				logprint("[HoneyPotTransport.VNC,%s,%s] Sending framebuffer parameters: " % (self.transport.sessionno, self.transport.getPeer().host))
				self.transport.loseConnection()
	def connectionLost(self, reason):
		self.state = 0

f = Factory()
f.protocol = tcp5900
