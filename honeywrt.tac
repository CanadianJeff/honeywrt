# Copyright (c) 2014 Jeffery Wilkins <djcanadianjeff@gmail.com>
# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import sys, os
if sys.platform == 'win32':
    import os, inspect
    # this is when just running on win32
    sys.path.insert(0, os.path.abspath(os.getcwd()))
    # and this is when running as a service
    #os.chdir(os.path.dirname(inspect.getfile(inspect.currentframe())))

#from twisted.internet import reactor, defer
from twisted.application import internet, service

if not os.path.exists('honeywrt.cfg'):
    print 'ERROR: honeywrt.cfg is missing!'
    sys.exit(1)

from honeywrt.core import honeypot
from honeywrt.core.config import config

#factory = honeypot.HoneyPotSSHFactory()
#factory.portal = portal.Portal(honeypot.HoneyPotRealm())

cfg = config()

#application = service.Application('honeypot')
#for i in ssh_addr.split():
#    service = internet.TCPServer(
#        int(cfg.get('honeypot', 'ssh_port')), factory,
#        interface=i)
#    service.setServiceParent(application)

#if cfg.has_option('honeypot', 'interact_enabled') and \
#        cfg.get('honeypot', 'interact_enabled').lower() in \
#        ('yes', 'true', 'on'):
#    iport = int(cfg.get('honeypot', 'interact_port'))
#    from kippo.core import interact
#    from twisted.internet import protocol
#    service = internet.TCPServer(iport, interact.makeInteractFactory(factory))
#    service.setServiceParent(application)
