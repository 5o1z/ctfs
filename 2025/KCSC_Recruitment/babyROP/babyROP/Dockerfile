FROM ubuntu:22.04
# FROM ubuntu:22.04@sha256:0e5e4a57c2499249aafc3b40fcd541e9a456aab7296681a3994d631587203f97

# set up
ENV user babyrop
ENV prob_port 13371

# install 
RUN apt-get update && apt-get install -y socat

RUN chmod 1733 /tmp /var/tmp /dev/shm 

RUN adduser --disabled-password --gecos "" $user 
ADD ./chall /home/$user/chall
ADD ./flag.txt /home/$user/flag.txt

RUN chown -R root:$user /home/$user/
RUN chown root:$user /home/$user/chall
RUN chown root:$user /home/$user/flag.txt

RUN chmod 1755 /home/$user/chall
RUN chmod 440 /home/$user/flag.txt

WORKDIR /home/$user
CMD socat -T 15 TCP-LISTEN:$prob_port,reuseaddr,fork EXEC:/home/$user/chall,su=$user
EXPOSE 13371
