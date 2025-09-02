
# WebLinksLab - URL Security Analysis Platform

## Overview

WebLinksLab is a comprehensive security analysis tool that provides:
- Malicious URL detection powered by VirusTotal API
- Safe URL interaction through isolated Docker environments
- Remote container deployment capabilities with NoVNC web-based Chrome access

## Key Features

1. **URL Threat Analysis**  
   Instant scanning using VirusTotal's threat intelligence database

2. **Secure Sandbox Environment**  
   Docker-based isolation with:
   - NoVNC web interface
   - Chromium browser
   - Remote container deployment

3. **API Integration**  
   FastAPI backend for scalable operations

## System Requirements

### Core Requirements
- Linux host system (Recommended: Ubuntu 20.04/22.04 LTS)
- Docker Engine 24.0+ 
- Python 3.8+
- Virtual environment (recommended)

### Remote Machine Requirements
- Ubuntu Server 22.04 LTS
- Docker Engine 24.0+
- SSH server access
- Minimum 2GB RAM (4GB recommended)

## Installation Guide

### 1. Docker Installation

```bash
# Remove old Docker versions
sudo apt-get remove docker docker-engine docker.io containerd runc

# Set up repository
sudo apt-get update
sudo apt-get install \
    ca-certificates \
    curl \
    gnupg

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Verify installation
sudo docker run hello-world

# add your user to docker group
sudo usermod -aG docker $USER

# reboot your system 

sudo reboot -f 
```

### 2. Project Setup

```bash
git clone [Your-Repository-URL]
cd WebLinksLab

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Configuration

1. Obtain VirusTotal API key from [VirusTotal Portal](https://www.virustotal.com/)
2. Configure `.env` file:

```env
VIRUSTOTAL_API_KEY=your_api_key_here
REMOTE=remote_machine_ip
```

### 4. Remote Machine Setup

```bash
# Copy project files to remote
scp -r novnc-chrome user@remote_ip:/path/to/destination

# SSH into remote machine
ssh user@remote_ip

# Build Docker image
cd novnc-chrome
docker build -t dev-chrome1 .
```

### 5. SSH Key Configuration

```bash
# Generate SSH key pair 
ssh-keygen -t rsa -b 4096

# Copy public key to remote
ssh-copy-id -i ~/.ssh/id_rsa.pub user@remote_ip
```

## Application Execution

### Start Services

**Terminal 1 (Backend):**
```bash
source venv/bin/activate
python3 backend.py
```

**Terminal 2 (API Server):**
```bash
source venv/bin/activate
cd API
uvicorn api:app --reload
```

## Usage Instructions

1. Access web interface at `http://localhost:8000`
2. Enter target URL for analysis
3. Select isolation mode for container deployment:
   - Local analysis: Basic scanning
   - Remote isolation: Deploys secure container with web-based Chrome access

## Security Considerations

1. **API Key Protection**  
   Never commit `.env` file to version control

2. **SSH Key Management**  
   Use passphrase-protected keys and rotate regularly

3. **Container Security**  
   Regularly update Docker images and apply security patches

## Troubleshooting

**Docker Permission Issues:**
```bash
sudo usermod -aG docker $USER
newgrp docker
```


---

