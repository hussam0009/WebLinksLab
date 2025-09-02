# Use Ubuntu 20.04 base
FROM ubuntu:20.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    DISPLAY=:0 \
    USER=app

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    xvfb \
    x11vnc \
    fluxbox \
    novnc \
    websockify \
    chromium-browser \
    net-tools \
    xterm \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libatspi2.0-0 \
    libcairo2 \
    libcups2 \
    libgbm1 \
    libglib2.0-0 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libpango-1.0-0 \
    libxcomposite1 \
    libxkbcommon0 \
    xdg-utils \
    git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -U -u 1000 -s /bin/bash ${USER}

# Clone noVNC
RUN git clone https://github.com/novnc/noVNC.git /opt/noVNC && \
    git clone https://github.com/novnc/websockify.git /opt/noVNC/utils/websockify


RUN wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O /tmp/google-chrome-stable_current_amd64.deb


RUN dpkg -i /tmp/google-chrome-stable_current_amd64.deb && rm /tmp/google-chrome-stable_current_amd64.deb
    
# Copy start script and set permissions as root


COPY start.sh /home/${USER}/start.sh
COPY websocket.py /opt/noVNC/utils/websockify/websockify/websocket.py

RUN chown ${USER}:${USER} /home/${USER}/start.sh && \
    chmod 755 /home/${USER}/start.sh

   
# Switch to non-root user
USER ${USER}
WORKDIR /home/${USER}

# Expose ports
#EXPOSE 6080

# # Healthcheck
# HEALTHCHECK --interval=30s --timeout=5s \
#     CMD netstat -an | grep 6080 > /dev/null || exit 1

# Start command
CMD ["./start.sh"]