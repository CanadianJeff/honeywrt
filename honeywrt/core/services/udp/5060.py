lastSIPPER = ''

class udp5060(DatagramProtocol):
	def datagramReceived(self, data, (host, port)):
		global lastSIPPER
		global gi
		logprint('[HoneyPotTransport.SIP,%s:%s] SIP Connect' % (host, port))
		if(lastSIPPER != host):
			lastSIPPER = host
			thread.start_new_thread(twitter_it, ('A host at %s (%s, %s - %s) wants to talk SIP to my honeypot... #netmenaces', lastSIPPER))
		logprint("[HoneyPotTransport.SIP,%s:%s] SIP Data" % (host, port))

reactor.listenUDP(5060, udp5060(), interface = interface)
