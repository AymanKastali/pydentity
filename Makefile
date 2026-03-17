.DEFAULT_GOAL := help

.PHONY: help ensure-uv setup sync lint format format-check type-check test test-cov check clean dev diagrams diagrams-svg diagrams-clean migrate migrate-new migrate-down migrate-history migrate-current env-setup infra docker-up docker-down docker-build docker-logs docker-ps release release-patch release-minor release-major generate-keys

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

ensure-uv: ## Install uv if not present
	@command -v uv >/dev/null 2>&1 || curl -LsSf https://astral.sh/uv/install.sh | sh

setup: ensure-uv sync ## Set up the full dev environment
	@if command -v git >/dev/null 2>&1; then \
		git rev-parse --git-dir >/dev/null 2>&1 || git init -b main; \
		uv run pre-commit install; \
	else \
		echo "Warning: git not found, skipping pre-commit install"; \
	fi

sync: ## Sync all dependencies
	uv sync --all-groups

lint: ## Run ruff linter
	uv run ruff check .

format: ## Auto-format code with ruff
	uv run ruff format .

format-check: ## Check code formatting without modifying
	uv run ruff format --check .

type-check: ## Run mypy type checker
	uv run mypy .

test: ## Run tests
	uv run pytest

test-cov: ## Run tests with coverage report
	uv run pytest --cov=src/pydentity --cov-report=term-missing

check: lint format-check type-check test ## Run all checks (lint + format + types + tests)

clean: ## Remove build artifacts and caches
	rm -rf dist/ build/ .venv/ .ruff_cache/ .pytest_cache/ .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

migrate: ## Apply all pending migrations
	uv run alembic upgrade head

migrate-new: ## Generate a new migration (use: make migrate-new MSG="description")
	uv run alembic revision --autogenerate -m "$(MSG)"

migrate-down: ## Rollback one migration step
	uv run alembic downgrade -1

migrate-history: ## Show migration history
	uv run alembic history

migrate-current: ## Show current migration revision
	uv run alembic current

dev: ## Start the app (infra assumed running via devcontainer or make infra)
	uv run python -m pydentity

COMPOSE      := docker compose -f docker/docker-compose.yml
COMPOSE_PROD := $(COMPOSE) -f docker/docker-compose.prod.yml

env-setup: ## Create .env from .env.example if it does not exist
	@test -f .env || (cp .env.example .env && echo "Created .env from .env.example — fill in required secrets before starting.")

infra: env-setup ## Start infrastructure only (postgres, redis, mailhog)
	$(COMPOSE) up -d

docker-up: env-setup ## Start app + infrastructure (detached)
	$(COMPOSE_PROD) up -d

docker-build: env-setup ## Build and start app + infrastructure
	$(COMPOSE_PROD) up --build -d

docker-down: ## Stop and remove containers
	$(COMPOSE_PROD) down

docker-logs: ## Tail logs for all services
	$(COMPOSE_PROD) logs -f

docker-ps: ## Show running service status
	$(COMPOSE_PROD) ps

release: ## Tag and push a release (use: make release V=1.0.0)
	@test -n "$(V)" || (echo "Usage: make release V=1.0.0" && exit 1)
	git tag -a "v$(V)" -m "Release v$(V)"
	git push origin "v$(V)"

release-patch: ## Bump patch version and release (use: make release-patch V=1.0.1)
	@$(MAKE) release V=$(V)

release-minor: ## Bump minor version and release (use: make release-minor V=1.1.0)
	@$(MAKE) release V=$(V)

release-major: ## Bump major version and release (use: make release-major V=2.0.0)
	@$(MAKE) release V=$(V)

generate-keys: ## Generate a new RSA 2048-bit signing key in keys/
	@mkdir -p keys
	openssl genrsa -out keys/$$(date +%Y-%m-%d).pem 2048
	chmod 600 keys/*.pem

diagrams: ## Render PlantUML diagrams to PNG
	plantuml -tpng docs/diagrams/*.puml

diagrams-svg: ## Render PlantUML diagrams to SVG
	plantuml -tsvg docs/diagrams/*.puml

diagrams-clean: ## Remove rendered diagram images
	rm -f docs/diagrams/*.png docs/diagrams/*.svg
