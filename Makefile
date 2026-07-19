.PHONY: help install dev-db migrate seed run api test lint fmt typecheck analyzer-image clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

install: ## Install the package + dev tooling into the current venv
	pip install -e ".[dev]"

dev-db: ## Start just Postgres in Docker
	docker compose up -d db

migrate: ## Apply DB migrations
	pkintel db migrate

seed: ## Seed the feed sources table
	pkintel db seed

run: ## Run every pipeline stage once
	pkintel run all --once

api: ## Serve the public API on :8000
	uvicorn pkintel.api.app:app --reload --port 8000

analyzer-image: ## Build the hardened analyzer sandbox image
	docker build -t pkintel-analyzer:latest -f analyzer_container/Dockerfile .

test: ## Run the test suite
	pytest

lint: ## Ruff lint
	ruff check src tests

fmt: ## Ruff format
	ruff format src tests

typecheck: ## mypy
	mypy src

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
