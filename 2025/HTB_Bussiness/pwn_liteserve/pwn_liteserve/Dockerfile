FROM ubuntu:22.04
# Update
RUN apt update --fix-missing && \
    apt install -y socat && \
    rm -rf /var/lib/apt/lists/*
# Create ctf-user
RUN groupadd -r ctf && useradd -r -g ctf ctf
ADD challenge/ /home/ctf/
RUN chmod 444 /home/ctf/flag.txt
RUN chmod 777 /home/ctf/server
USER ctf
WORKDIR /home/ctf
ENV TESTING_MODE=ON
EXPOSE 1337
ENTRYPOINT ["./server"]
#ENTRYPOINT ["socat", "tcp-l:1337,reuseaddr,fork", "EXEC:./server"]
