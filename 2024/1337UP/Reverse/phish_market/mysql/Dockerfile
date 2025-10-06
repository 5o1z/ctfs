# Dockerfile for MySQL
FROM mysql:latest

# Copy the init-db.sql file into the container
COPY init-db.sql /docker-entrypoint-initdb.d/

# Optional: Set permissions if needed
RUN chmod 644 /docker-entrypoint-initdb.d/init-db.sql
