#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

echo "=== ContainArmor Demonstration Fleet ==="
echo "Starting vulnerable & baseline container fleet..."
docker compose -f "$DIR/docker-compose.vuln.yml" up -d

echo ""
echo "Fleet deployed successfully!"
echo "Check ContainArmor Blazor UI at http://localhost:5200 or SOC Dashboard to view real-time detections."
echo "To tear down demo fleet run: docker compose -f $DIR/docker-compose.vuln.yml down"
