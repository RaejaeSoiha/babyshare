#!/bin/bash
# ===========================
# BabyShare Logs Script
# ===========================

echo "📜 Streaming logs (press Ctrl+C to stop)"
echo ""

# Show logs for both babyshare + nginx-proxy
docker compose logs -f babyshare nginx-proxy
