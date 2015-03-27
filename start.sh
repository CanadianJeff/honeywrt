#!/bin/sh

### Background
cd $(dirname $0)
twistd -y honeywrt.tac --pidfile honeywrt.pid

### Forground
#cd $(dirname $0)
#twistd -y honeywrt.tac -n
