m-search = binascii.unhexlify('4d2d534541524348202a20485454502f312e31')

class udp1900(DatagramProtocol):
	def datagramReceived(self, data, (host, port)):
		logprint("[HoneyPotTransport.UDP1900,%s:%s] SSDP PING" % (host, port))
		if data[:20] == m-search:
			logprint("[HoneyPotTransport.UDP1900,%s:%s] M-SEARCH" % (host, port))

reactor.listenUDP(1900, udp1900(), interface = interface)
