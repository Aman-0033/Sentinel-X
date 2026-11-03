#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "==============================================================================="
echo "               SENTINEL-X AI-POWERED INTRUSION DETECTION SOC"
echo "==============================================================================="

# 1. Detect Python & Virtualenv
if [ -d ".venv" ]; then
    if [ -f ".venv/bin/python" ]; then
        PYTHON=".venv/bin/python"
        ALEMBIC=".venv/bin/alembic"
        UVICORN=".venv/bin/uvicorn"
    elif [ -f ".venv/Scripts/python.exe" ]; then
        PYTHON=".venv/Scripts/python.exe"
        ALEMBIC=".venv/Scripts/alembic.exe"
        UVICORN=".venv/Scripts/uvicorn.exe"
    fi
else
    PYTHON="python3"
    ALEMBIC="alembic"
    UVICORN="uvicorn"
fi

# 2. Check .env
if [ ! -f ".env" ]; then
    echo "[!] Creating development .env from .env.example..."
    cp .env.example .env
fi

# 3. Migrations & Seeding
export PYTHONPATH="sentinel-x/backend:$PYTHONPATH"
echo "[*] Running Alembic migrations to head..."
$ALEMBIC -c sentinel-x/backend/alembic.ini upgrade head

# 4. Populate roles, administrator, and realistic telemetry (idempotent)
echo "[*] Ensuring database telemetry and accounts are populated..."
$PYTHON scripts/seed_database.py
$PYTHON scripts/create_admin.py
$PYTHON scripts/demo_data.py

# 4. Start backend & frontend
echo "[*] Starting FastAPI Backend on http://localhost:8000..."
$UVICORN app.main:app --app-dir sentinel-x/backend --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

echo "[*] Starting Vite Frontend on http://localhost:5173..."
npm run dev --prefix sentinel-x/frontend -- --port 5173 --host 0.0.0.0 &
FRONTEND_PID=$!

echo ""
echo "==============================================================================="
echo "                SENTINEL-X LIVE DEMONSTRATION READY!"
echo "==============================================================================="
echo "  * Frontend Dashboard:   http://localhost:5173"
echo "  * Backend Swagger Docs: http://localhost:8000/docs"
echo ""
echo "  --- DEMO CREDENTIALS ---"
echo "  * Administrator: admin@sentinel.internal   / SentinelAdmin2026!"
echo "  * Security Analyst: analyst@sentinel.internal / SentinelAnalyst2026!"
echo "  * Auditor / Viewer: viewer@sentinel.internal  / SentinelViewer2026!"
echo "==============================================================================="
echo "Press Ctrl+C to stop servers."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null" EXIT
wait

