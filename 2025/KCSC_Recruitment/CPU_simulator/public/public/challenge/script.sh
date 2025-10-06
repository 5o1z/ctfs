#!/bin/sh
socat \
-T60 \
TCP-LISTEN:6666,reuseaddr,fork \
EXEC:"timeout 60 python3 /home/jail/run.py"