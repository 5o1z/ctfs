# Dockerfile
FROM ubuntu:latest

# Install dependencies
RUN apt-get update && apt-get install -y \
    g++ \
    cmake \
    libmysqlcppconn-dev \
    mysql-client \
    telnet \
    netcat-openbsd

# Set the working directory
WORKDIR /usr/src/app3

# Copy the current directory contents into the container
COPY . .

# Copy the wait-for-it script
COPY wait-for-it.sh /usr/src/app3/

# Make the wait-for-it script executable
RUN chmod +x /usr/src/app3/wait-for-it.sh

# Expose port 1334
EXPOSE 1336

## Command to run the C++ app with the wait-for-it script
CMD ["./wait-for-it.sh", "mysql", "3306", "--", "./market"]


