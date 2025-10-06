FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y curl socat bash && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -md /home/challenge challenge && \
    echo "challenge:challenge" | chpasswd

WORKDIR /challenge
COPY ./chall .

RUN chmod 755 ./chall && \
    chmod 644 ./flag.txt || true && \
    chown -R challenge:challenge /challenge

USER challenge


EXPOSE 9090
CMD socat TCP-LISTEN:9090,reuseaddr,fork EXEC:./chall,stderr
