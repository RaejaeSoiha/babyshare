#!/bin/bash
# ===========================
# BabyShare Status Script
# ===========================

echo "📊 Checking BabyShare status..."
echo ""

# Show running containers
docker ps --filter "name=babyshare" --filter "name=nginx-proxy"

# Get LAN IP
LAN_IP=$(ipconfig getifaddr en0)

# Read domain from .env (if set)
DOMAIN=$(grep "VIRTUAL_HOST=" .env | cut -d '=' -f2)

echo ""
echo "🌐 LAN_IP: $LAN_IP"
echo ""
echo "👉 Localhost (HTTP):  http://localhost:3000"
echo "👉 LAN (HTTP):        http://$LAN_IP:3000"

# Self-signed certs check
if [ -f "./certs/selfsigned.crt" ] && [ -f "./certs/selfsigned.key" ]; then
  echo "🔒 HTTPS (LAN self-signed): https://$LAN_IP"
fi

# Domain check
if [ ! -z "$DOMAIN" ] && [[ "$DOMAIN" != "localhost" ]]; then
  echo "🔒 HTTPS (Domain, Let's Encrypt): https://$DOMAIN"
fi

echo ""
echo "✅ Status check complete."
