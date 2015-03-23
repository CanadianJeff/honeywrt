import ConfigParser, os

def config():
    cfg = ConfigParser.ConfigParser()
    for f in ('honeywrt.cfg', '/etc/honeywrt/honeywrt.cfg', '/etc/honeywrt.cfg'):
        if os.path.exists(f):
            cfg.read(f)
            return cfg
    return None
