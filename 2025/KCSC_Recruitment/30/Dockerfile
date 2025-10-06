FROM ubuntu:22.04

MAINTAINER anonymous
RUN apt-get update

RUN useradd -m m

RUN apt-get update --fix-missing -y

RUN apt-get install -y apt-utils software-properties-common

RUN apt-get install -y build-essential \
        socat \
        netcat 

WORKDIR /home/m

ADD ./flag /home/m
ADD ./30 /home/m

ENTRYPOINT ["sh", "-c", "exec socat -s TCP-LISTEN:1337,reuseaddr,fork EXEC:/home/m/30,stderr"]

EXPOSE 1337