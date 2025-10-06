FROM ubuntu:22.04@sha256:0e5e4a57c2499249aafc3b40fcd541e9a456aab7296681a3994d631587203f97

RUN apt update
RUN apt install -y socat

COPY ./submission /app
RUN chmod -R 744 /app
WORKDIR /app

EXPOSE 8000
CMD socat TCP-LISTEN:8000,reuseaddr,fork EXEC:./prob