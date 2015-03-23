#!/bin/sh

PIDFILE=honeywrt.pid

cd $(dirname $0)

PID=$(cat $PIDFILE 2>/dev/null)

if [ -n "$PID" ]; then
  echo "Stopping honeywrt IDS...\n"
  kill -TERM $PID
fi
