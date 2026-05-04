# ============================================================
# Sample Infrastructure — Dockerfile
# Application container
# Note: contains intentional issues for pipeline testing
# ============================================================

# SECURITY ISSUE: using a very old base image version
FROM ubuntu:20.04

# SECURITY ISSUE: no maintainer label / metadata
LABEL version="1.0"

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV APP_PORT=8080
# SECURITY ISSUE: hardcoded secret in environment variable
ENV DB_PASSWORD=Password123!
ENV APP_SECRET=mysecretkey12345

# SECURITY ISSUE: running apt-get without pinning versions
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    # SECURITY ISSUE: installing unnecessary tools (attack surface)
    netcat \
    telnet \
    && rm -rf /var/lib/apt/lists/*

# SECURITY ISSUE: not creating a non-root user early
WORKDIR /app

# Copy application files
COPY requirements.txt .

# SECURITY ISSUE: pip install without hash checking
RUN pip3 install -r requirements.txt

COPY . .

# SECURITY ISSUE: copying everything including .env and secrets
# Should use .dockerignore

# SECURITY ISSUE: wide open permissions
RUN chmod -R 777 /app

# SECURITY ISSUE: not specifying a non-root USER
# Container will run as root

EXPOSE ${APP_PORT}
# SECURITY ISSUE: also exposing debug port
EXPOSE 5678

# SECURITY ISSUE: using shell form instead of exec form
CMD python3 app.py
