from twisted.internet.protocol import ServerFactory
from twisted.internet import reactor
from twisted.words.protocols.irc import IRC


class IRCServer(IRC):
    def connectionMade(self):
        print "client connected"

    def handleCommand(self, command, prefix, params):
        print "handle comm"
        IRC.handleCommand(self, command, prefix, params)

    def dataReceived(self, data):
        print "data: %s" % data
        IRC.dataReceived(self, data)

    def irc_unknown(self, prefix, command, params):
        print "%s, %s, %s, IRC UNKNOWN" % (prefix, command, params)

    def irc_USER(self, prefix, params):
        print "USER: %s, %s" % (prefix, params)

    def irc_NICK(self, prefix, params):
        print "NICK: %s, %s" % (prefix, params)



class IRCServerFactory(ServerFactory):
    protocol = IRCServer

#factory = IRCServerFactory()
#reactor.listenTCP(6667, factory, interface = interface)
