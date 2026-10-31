.PHONY: help install test test-unit test-integration test-security docker-up docker-down start migrate seed backend frontend

PYTHON ?= .venv/Scripts/python
PYTEST ?= .venv/Scripts/pytest
ALEMBIC ?= .venv/Scripts/alembic
UVICORN ?= .venv/Scripts/uvicorn

help:
	@echo "Sentinel-X Root Makefile"
	@echo "  start            - Launch both backend and frontend servers for live demonstration"
	@echo "  migrate          - Run Alembic database migrations to head"
	@echo "  seed             - Seed database with roles, admin, and realistic SOC telemetry"
	@echo "  backend          - Run FastAPI backend on http://localhost:8000"
	@echo "  frontend         - Run React/Vite frontend on http://localhost:5173"
	@echo "  install          - Install backend dependencies in .venv"
	@echo "  test             - Run all automated backend tests"
	@echo "  docker-up        - Start Docker services"
	@echo "  docker-down      - Stop Docker services"

start: migrate seed
	@echo "Starting Sentinel-X Backend and Frontend servers..."
	cmd /c start.bat

migrate:
	$(ALEMBIC) -c sentinel-x/backend/alembic.ini upgrade head

seed:
	$(PYTHON) scripts/seed_database.py
	$(PYTHON) scripts/create_admin.py
	$(PYTHON) scripts/demo_data.py

backend:
	$(UVICORN) app.main:app --app-dir sentinel-x/backend --host 0.0.0.0 --port 8000 --reload

frontend:
	npm run dev --prefix sentinel-x/frontend -- --port 5173 --host 0.0.0.0

install:
	$(PYTHON) -m pip install -r sentinel-x/backend/requirements.txt -r sentinel-x/backend/requirements-dev.txt
	npm install --prefix sentinel-x/frontend

test:
	$(PYTHON) -m pytest sentinel-x/backend/tests -v

docker-up:
	docker compose up -d

docker-down:
	docker compose down -v
