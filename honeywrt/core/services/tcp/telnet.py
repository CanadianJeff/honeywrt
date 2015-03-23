    from zope.interface import Interface, implements
    from twisted.internet.protocol import ServerFactory, Protocol
    from twisted.conch.telnet import AuthenticatingTelnetProtocol, StatefulTelnetProtocol, ITelnetProtocol
    from twisted.cred import portal, checkers, credentials, error as credError
    from twisted.protocols import basic
    from twisted.internet import protocol, reactor, defer
    from zope.interface import Interface, implements
    class PasswordDictChecker(object):
    implements(checkers.ICredentialsChecker)
    credentialInterfaces = (credentials.IUsernamePassword,)
    ## credentialInterfaces = (ITelnetProtocol,)
    def __init__(self, passwords):
    "passwords: a dict-like object mapping usernames to passwords"
    print "DEBUG - PasswordDictChecker - __init__"
    self.passwords = passwords
    print "DEBUG - PasswordDictChecker - self.passwords", self.passwords
    def requestAvatarId(self, credentials):
    print "DEBUG - PasswordDictChecker - requestAvatarId - credentials", credentials
    username = credentials.username
    if self.passwords.has_key(username):
    if credentials.password == self.passwords[username]:
    return defer.succeed(username)
    else:
    return defer.fail(
    credError.UnauthorizedLogin("Bad password"))
    else:
    return defer.fail(
    credError.UnauthorizedLogin("No such user"))
    class INamedUserAvatar(Interface):
    "should have attributes username and fullname"
    print "DEBUG - INamedUserAvatar :", Interface
    class NamedUserAvatar:
    implements(INamedUserAvatar)
    def __init__(self, username, fullname):
    self.username = username
    self.fullname = fullname
    print "DEBUG - NamedUserAvatar - __init__ :", username, fullname
    class INamedUserAvatar2(ITelnetProtocol):
    "should have attributes username and fullname"
    #print "DEBUG - INamedUserAvatar :", Interface
    class NamedUserAvatar2:
    implements(INamedUserAvatar2)
    def __init__(self, username, fullname):
    self.username = username
    self.fullname = fullname
    print "DEBUG - NamedUserAvatar - __init__ :", username, fullname
    class TestRealm:
    print "DEBUG - class TestRealm"
    implements(portal.IRealm)
    print "DEBUG - class TestRealm - after implements"
    def __init__(self, users):
    print "DEBUG - class TestRealm - __init__ users", users
    self.users = users
    def requestAvatar(self, avatarId, mind, *interfaces):
    print "DEBUG - class TestRealm - requestAvatar"
    print "*interfaces", interfaces
    if INamedUserAvatar in interfaces:
    print "DEBUG: requestAvatar - avatarId :", avatarId
    print "DEBUG: requestAvatar - self.users[avatarId] :", self.users[avatarId]
    fullname = self.users[avatarId]
    logout = lambda: None
    print "DEBUG: INamedUserAvatar :",INamedUserAvatar
    print "DEBUG: NamedUserAvatar(avatarId, fullname) :", NamedUserAvatar(avatarId, fullname)
    return (INamedUserAvatar,
    NamedUserAvatar(avatarId, fullname),
    logout)
    elif INamedUserAvatar2 in interfaces:
    print "DEBUG2: requestAvatar - avatarId :", avatarId
    print "DEBUG2: requestAvatar - self.users[avatarId] :", self.users[avatarId]
    fullname = self.users[avatarId]
    logout = lambda: None
    print "DEBUG2: INamedUserAvatar :",ITelnetProtocol
    print "DEBUG2: NamedUserAvatar(avatarId, fullname) :", TelnetProtocol(avatarId, fullname)
    return (INamedUserAvatar2, NamedUserAvatar2(avatarId, fullname), logout)
    else:
    print "DEBUG: requestAvatar - requestAvatar -else :", avatarId
    raise KeyError("None of the requested interfaces is supported")
    class LoginTestProtocol000(basic.LineReceiver):
    def lineReceived(self, line):
    cmd = getattr(self, 'handle_' + self.currentCommand)
    cmd(line.strip( ))
    def connectionMade(self):
    self.transport.write("User Name: ")
    self.currentCommand = 'user'
    def handle_user(self, username):
    self.username = username
    self.transport.write("Password: ")
    self.currentCommand = 'pass'
    def handle_pass(self, password):
    creds = credentials.UsernamePassword(self.username, password)
    self.factory.portal.login(creds, None, INamedUserAvatar).addCallback(
    self._loginSucceeded).addErrback(
    self._loginFailed)
    def _loginSucceeded(self, avatarInfo):
    avatarInterface, avatar, logout = avatarInfo
    self.transport.write("Welcome %s!\r\n" % avatar.fullname)
    defer.maybeDeferred(logout).addBoth(self._logoutFinished)
    def _logoutFinished(self, result):
    self.transport.loseConnection( )
    def _loginFailed(self, failure):
    self.transport.write("Denied: %s.\r\n" % failure.getErrorMessage( ))
    self.transport.loseConnection( )
    class LoginTestProtocol(AuthenticatingTelnetProtocol):
    print "DEBUG: LoginTestProtocol"
    class LoginTestFactory(protocol.ServerFactory):
    protocol = LoginTestProtocol
    def __init__(self, portal):
    print "DEBUG: LoginTestFactory - __init__ - portal:"
    self.portal = portal
    print "DEBUG: LoginTestFactory - __init__ - portal after", repr(self.portal)
    users = {
    'admin': 'Admin User',
    'user1': 'Joe Smith',
    'user2': 'Bob King',
    }
    passwords = {
    'admin': 'aaa',
    'user1': 'bbb',
    'user2': 'ccc'
    }
    if __name__ == "__main__":
    p = portal.Portal(TestRealm(users))
    p.registerChecker(PasswordDictChecker(passwords))
    factory = LoginTestFactory(p)
    reactor.listenTCP(23, factory)
    reactor.run( )
