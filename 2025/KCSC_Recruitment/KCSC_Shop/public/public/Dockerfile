FROM ubuntu@sha256:7185d738658e31c96b3ba0f9deaae1df46a5c405dc82025094a51e5e2072212a
ENV DEBIAN_FRONTEND noninteractive
RUN rm /var/lib/dpkg/info/libc-bin.*
RUN apt-get clean
RUN apt-get update --fix-missing -y
RUN apt-get install libc-bin
RUN apt-get install -y ncat
RUN useradd -m ctf

COPY ./flag.txt /home/ctf
COPY ./shop /home/ctf
RUN chown -R root:ctf /home/ctf

RUN chmod 755 /home/ctf/shop
RUN chmod 444 /home/ctf/flag.txt

WORKDIR /home/ctf
EXPOSE 6969
USER ctf
CMD ["ncat", "-lnvp", "6969", "-e", "/home/ctf/shop", "-k"]