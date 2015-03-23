name_query = binascii.unhexlify("0000")

class udp137(DatagramProtocol):
	def datagramReceived(self, data, (host, port)):
		logprint("[HoneyPotTransport.NBNS,%s:%s] Netbios PING" % (host, port))
		logprint("[HoneyPotTransport.NBNS,%s:%s] Transaction ID: 0x%s" % (host, port, binascii.hexlify(data[:2])))
		if data[2:4] == name_query:
			logprint("[HoneyPotTransport.NBNS,%s:%s] Flags: 0x%s (Name query)" % (host, port, binascii.hexlify(data[2:4])))
			logprint("[HoneyPotTransport.NBNS,%s:%s] Questions: %s" % (host, port, binascii.hexlify(data[4:6])))
			logprint("[HoneyPotTransport.NBNS,%s:%s] Answer RRs: %s" % (host, port, binascii.hexlify(data[6:8])))
			logprint("[HoneyPotTransport.NBNS,%s:%s] Authority RRs: %s" % (host, port, binascii.hexlify(data[8:10])))
			logprint("[HoneyPotTransport.NBNS,%s:%s] Additional RRs: %s" % (host, port, binascii.hexlify(data[10:12])))
			logprint("[HoneyPotTransport.NBNS,%s:%s] Queries %s" % (host, port, binascii.hexlify(data[12:])))
		else:
			logprint("[HoneyPotTransport.NBNS,%s:%s] Flags: 0x%s (Unknown)" % (host, port, binascii.hexlify(data[2:4])))

reactor.listenUDP(137, udp137(), interface = interface)
