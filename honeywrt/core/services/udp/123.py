flags_16 = binascii.unhexlify("16")
flags_17 = binascii.unhexlify("17")
mon_getlist = binascii.unhexlify('2a')

class udp123(DatagramProtocol):
	def datagramReceived(self, data, (host, port)):
		logprint("[HoneyPotTransport.NTP,%s:%s] NTP PING" % (host, port))
		if data[:1] == flags_16:
			logprint("[HoneyPotTransport.NTP,%s:%s] Flags: 0x%s" % (host, port, binascii.hexlify(data[:1])))
			logprint("[HoneyPotTransport.NTP,%s:%s] Flags 2: 0x%s" % (host, port, binascii.hexlify(data[1:2])))
			logprint("[HoneyPotTransport.NTP,%s:%s] Sequence: %s" % (host, port, binascii.hexlify(data[2:4])))
			logprint("[HoneyPotTransport.NTP,%s:%s] Status %s" % (host, port, binascii.hexlify(data[4:6])))
			logprint("[HoneyPotTransport.NTP,%s:%s] AssociationID: %s" % (host, port, binascii.hexlify(data[6:8])))
			logprint("[HoneyPotTransport.NTP,%s:%s] Offset: %s" % (host, port, binascii.hexlify(data[8:10])))
			logprint("[HoneyPotTransport.NTP,%s:%s] Count: %s" % (host, port, binascii.hexlify(data[10:12])))
		elif data[:1] == flags_17:
			logprint("[HoneyPotTransport.NTP,%s:%s] Flags: 0x%s" % (host, port, binascii.hexlify(data[:1])))
			logprint("[HoneyPotTransport.NTP,%s:%s] Auth sequence: %s" % (host, port, binascii.hexlify(data[1:2])))
			logprint("[HoneyPotTransport.NTP,%s:%s] Implementation: XNTPD (%s)" % (host, port, binascii.hexlify(data[2:3])))
			if data[3:4] == mon_getlist:
				logprint("[HoneyPotTransport.NTP,%s:%s] Request Code: MON_GETLIST_1 (42)" % (host, port))
			else:
				logprint("[HoneyPotTransport.NTP,%s:%s] Request Code: Unknown (%s)" % (host, port, binascii.hexlify(data[3:4])))

reactor.listenUDP(123, udp123(), interface = interface)
