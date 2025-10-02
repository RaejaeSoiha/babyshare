#!/bin/bash
# ===========================
# BabyShare Start Script
# ===========================

# Detect LAN IP automatically
LAN_IP=$(ipconfig getifaddr en0)

# Update .env file with LAN_IP
if grep -q "LAN_IP=" .env; then
  sed -i '' "s/^LAN_IP=.*/LAN_IP=$LAN_IP/" .env
else
  echo "LAN_IP=$LAN_IP" >> .env
fi

echo ""
echo "🌐 Using LAN_IP=$LAN_IP"
echo ""

# Restart Docker
docker compose down
docker compose up -d

# ===========================
# Show Access Information
# ===========================
echo ""
echo " BabyShare is running!"
echo ""
echo "Localhost (HTTP):  http://localhost:3000"
echo "LAN (HTTP):        http://$LAN_IP:3000"

# Check for self-signed certs
if [ -f "./certs/selfsigned.crt" ] && [ -f "./certs/selfsigned.key" ]; then
  echo "🔒 HTTPS (LAN self-signed): https://$LAN_IP"
fi

# Check if domain vars exist in .env
DOMAIN=$(grep "VIRTUAL_HOST=" .env | cut -d '=' -f2)
if [ ! -z "$DOMAIN" ] && [[ "$DOMAIN" != "localhost" ]]; then
  echo "🔒 HTTPS (Domain, Let's Encrypt): https://$DOMAIN"
fi

echo ""
echo "Access your BabyShare from any device on the same LAN."
echo ""
