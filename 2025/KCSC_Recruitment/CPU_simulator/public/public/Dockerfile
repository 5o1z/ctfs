FROM ubuntu:24.04
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update --fix-missing -y && apt-get -y upgrade
RUN apt-get install -y ncat 
RUN apt-get install -y python3
RUN useradd -m ctf

COPY ./challenge/emulator /home/ctf
COPY ./challenge/flag.txt /home/ctf
COPY ./challenge/input.txt /home/ctf
COPY ./challenge/run.py /home/ctf
COPY ./challenge/script.sh /home/ctf

RUN chown -R root:ctf /home/ctf
RUN chmod 755 /home/ctf/run.py
RUN chmod 755 /home/ctf/emulator
RUN chmod 664 /home/ctf/input.txt
RUN chmod 644 /home/ctf/flag.txt
WORKDIR /home/ctf
EXPOSE 6666
USER ctf
CMD ["ncat", "-lnvp", "6666", "-e", "/home/ctf/run.py", "-k"]


