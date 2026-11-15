#!/bin/bash
set -e

echo "================================================================="
echo "       SENTINEL-X PRODUCTION CLOUD DEPLOYMENT STARTUP"
echo "================================================================="

# Wait for PostgreSQL to be ready if DATABASE_URL is set
if [ -n "$DATABASE_URL" ]; then
    echo "[*] Verifying database connectivity..."
    python -c "
import sys, time, os
from sqlalchemy import create_engine

url = os.getenv('DATABASE_URL', '')
if url.startswith('postgres://'):
    url = url.replace('postgres://', 'postgresql+psycopg2://', 1)
elif url.startswith('postgresql://') and '+psycopg2' not in url and '+asyncpg' not in url:
    url = url.replace('postgresql://', 'postgresql+psycopg2://', 1)

for attempt in range(1, 31):
    try:
        engine = create_engine(url, pool_pre_ping=True)
        with engine.connect() as conn:
            print('[+] Database connection established successfully.')
            sys.exit(0)
    except Exception as exc:
        print(f'[-] Database not ready yet (attempt {attempt}/30): {exc.__class__.__name__}. Retrying in 2s...')
        time.sleep(2)
print('[!] Warning: Database pre-ping timeout; proceeding with startup.')
" || true
fi

# Run database migrations
echo "[*] Executing Alembic database migrations (upgrade head)..."
if [ -f "alembic.ini" ]; then
    alembic upgrade head
elif [ -f "backend/alembic.ini" ]; then
    (cd backend && alembic upgrade head)
elif [ -f "sentinel-x/backend/alembic.ini" ]; then
    (cd sentinel-x/backend && alembic upgrade head)
fi

# Seed database roles, admin, and demo telemetry idempotently
echo "[*] Seeding default roles, administrator, and telemetry data..."
if [ -f "scripts/seed_database.py" ]; then
    python scripts/seed_database.py || echo "[!] Role seeding skipped."
    python scripts/create_admin.py || echo "[!] Admin creation skipped."
    python scripts/demo_data.py || echo "[!] Demo data seeding skipped."
elif [ -f "sentinel-x/scripts/seed_database.py" ]; then
    python sentinel-x/scripts/seed_database.py || echo "[!] Role seeding skipped."
    python sentinel-x/scripts/create_admin.py || echo "[!] Admin creation skipped."
    python sentinel-x/scripts/demo_data.py || echo "[!] Demo data seeding skipped."
fi

# Launch backend
APP_PORT="${PORT:-8000}"
echo "[*] Launching Uvicorn production server on port ${APP_PORT}..."
exec uvicorn app.main:app --host 0.0.0.0 --port "${APP_PORT}"
