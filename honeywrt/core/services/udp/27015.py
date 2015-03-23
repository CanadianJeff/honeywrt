class udp27015(DatagramProtocol):
	def datagramReceived(self, data, (host, port)):
		logprint("[HoneyPotTransport.STEAM,%s:%s] STEAM PING" % (host, port))
		logprint("STEAM Data from: %s (%d/UDP):\n%s" % (host, port, data))

reactor.listenUDP(27015, udp27015(), interface = interface)
