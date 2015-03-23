class udp5632(DatagramProtocol):
	def datagramReceived(self, data, (host, port)):
		logprint("[HoneyPotTransport.UDP5632,%s:%s] PCANYWHERE PING" % (host, port))

reactor.listenUDP(5632, udp5632(), interface = interface)
