#!/bin/bash

### Background
cd $(dirname $0)
twistd -u 0 -g 0 -y honeywrt/core/honeypot.py --pidfile /var/run/honeywrt.pid

### Forground
#cd $(dirname $0)
#twistd -y honeywrt.tac -n
