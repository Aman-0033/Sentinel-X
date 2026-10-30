.PHONY: help install test test-unit test-integration test-security lint format docker-up docker-down migrate run-dev

PYTHON ?= python
PYTEST ?= pytest

help:
	@echo "Sentinel-X Development Makefile"
	@echo "Targets:"
	@echo "  install          - Install backend dependencies"
	@echo "  test             - Run all automated backend tests with coverage"
	@echo "  test-unit        - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  test-security    - Run security tests only"
	@echo "  lint             - Check formatting and linting"
	@echo "  docker-up        - Start Postgres, Redis, Backend, and Celery via Docker"
	@echo "  docker-down      - Stop all Docker containers"
	@echo "  migrate          - Run database migrations"
	@echo "  run-dev          - Start FastAPI backend with reload"

install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt

test:
	$(PYTHON) -m $(PYTEST) backend/tests -v --cov=backend/app --cov-report=term-missing

test-unit:
	$(PYTHON) -m $(PYTEST) backend/tests/unit -v

test-integration:
	$(PYTHON) -m $(PYTEST) backend/tests/integration -v

test-security:
	$(PYTHON) -m $(PYTEST) backend/tests/security -v

docker-up:
	docker compose up -d

docker-down:
	docker compose down -v

run-dev:
	cd backend && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

