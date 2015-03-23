#!/bin/sh

#date '+%Y-%m-%d %H:%M:%S%z' | awk '{print $1,$2" [-] Starting honeywrt IDS in the background..."}'
#cd $(dirname $0)
#twistd -y honeywrt.tac -l log/honeywrt.log --pidfile honeywrt.pid

date '+%Y-%m-%d %H:%M:%S%z' | awk '{print $1,$2" [-] Starting honeywrt IDS in the foreground..."}'
cd $(dirname $0)
twistd -y honeywrt.tac -n
