#!/bin/bash

# Start X server
Xvfb :0 -screen 0 1920x1080x24 +extension GLX &


# Start window manager
fluxbox &

# Start VNC server without password
x11vnc -forever -shared -nopw -display :0 -noxrecord -noxfixes -noxdamage -geometry 1920x1080 &

# Start noVNC with a specific index page (vnc.html)
# Specify the path to the vnc.html in noVNC's web directory
sed -i '/# self.send_header("X-Frame-Options", "DENY")/a \        self.send_header("Content-Security-Policy", "frame-ancestors *;")' /opt/noVNC/utils/websockify/websockify/websocket.py

/opt/noVNC/utils/novnc_proxy --vnc localhost:5900 --listen 6080 --web /opt/noVNC/ &


# Start Chrome with security flags
export CHROME_LOG_FILE=/dev/null
google-chrome-stable \
  --no-sandbox \
  --disable-gpu \
  --disable-dev-shm-usage \
  --disable-software-rasterizer \
  --start-maximized \
  --no-first-run \
  --disable-background-networking \
  --disable-sync \
  --no-service-autorun \
  --disable-default-apps \
  --disable-infobars \
  --disable-logging \
  https://google.com
  2>/dev/null


# Keep container alive
# python3 /redirect.py

tail -f /dev/null
