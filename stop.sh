#!/bin/bash
# ===========================
# BabyShare Stop Script
# ===========================

echo "🛑 Stopping BabyShare..."
docker compose down
echo "✅ All containers stopped."
