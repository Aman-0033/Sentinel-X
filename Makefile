.PHONY: help install test test-unit test-integration test-security docker-up docker-down

PYTHON ?= .venv/Scripts/python
PYTEST ?= .venv/Scripts/pytest

help:
	@echo "Sentinel-X Root Makefile"
	@echo "  install          - Install backend dependencies in .venv"
	@echo "  test             - Run all automated backend tests"
	@echo "  docker-up        - Start Docker services"
	@echo "  docker-down      - Stop Docker services"

install:
	$(PYTHON) -m pip install -r sentinel-x/backend/requirements.txt -r sentinel-x/backend/requirements-dev.txt

test:
	$(PYTHON) -m pytest sentinel-x/backend/tests -v

docker-up:
	docker compose up -d

docker-down:
	docker compose down -v

