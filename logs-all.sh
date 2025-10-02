#!/bin/bash
# ===========================
# BabyShare + Nginx + SSL Logs
# ===========================

echo "📜 Streaming ALL logs (press Ctrl+C to stop)"
echo ""

# Logs from babyshare, nginx, and letsencrypt
docker compose logs -f babyshare nginx-proxy nginx-letsencrypt
