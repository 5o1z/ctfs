FROM ubuntu:24.04@sha256:4f1db91d9560cf107b5832c0761364ec64f46777aa4ec637cca3008f287c975e

RUN apt update && apt install -y socat
COPY chall /chall
COPY ./flag.txt /flag.txt
RUN RANDOM_HEX=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n') && mv /flag.txt /flag-${RANDOM_HEX}.txt

ENTRYPOINT ["/bin/sh", "-c", "timeout 999 /chall"]

