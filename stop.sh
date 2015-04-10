#!/bin/bash

PIDFILE=/var/run/honeywrt.pid

PID=$(cat $PIDFILE 2>/dev/null)

if [ -n "$PID" ]; then
  echo "Stopping honeywrt IDS...\n"
  kill -TERM $PID
fi
