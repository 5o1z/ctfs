#!/bin/bash

docker build -t ctf .
docker run --rm -p 1337:1337 \
  --cap-add=SYS_ADMIN \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  ctf
