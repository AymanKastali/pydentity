.DEFAULT_GOAL := help

# --- Environment ---

.PHONY: help ensure-uv setup sync install-shell-completion configure-git

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

ensure-uv:
	@command -v uv >/dev/null 2>&1 || curl -LsSf https://astral.sh/uv/install.sh | sh

setup: ensure-uv sync install-shell-completion configure-git ## Set up the full dev environment

sync: ## Sync all dependencies
	uv sync --all-groups

install-shell-completion:
	@dpkg -s bash-completion >/dev/null 2>&1 || \
		(apt-get update && apt-get install -y bash-completion && rm -rf /var/lib/apt/lists/*)
	@grep -q 'bash_completion' ~/.bashrc 2>/dev/null || \
		printf '\nif [ -f /etc/bash_completion ]; then\n  . /etc/bash_completion\nfi\n' >> ~/.bashrc

configure-git:
	@if ! git rev-parse --git-dir >/dev/null 2>&1; then \
		git init -b main; \
	fi
	git config core.hooksPath .githooks

# --- Quality ---

.PHONY: lint format format-check type-check test test-cov security check

lint: ## Run ruff linter
	uv run ruff check src/ tests/

format: ## Auto-format code with ruff
	uv run ruff format src/ tests/

format-check: ## Check code formatting without modifying
	uv run ruff format --check src/ tests/

type-check: ## Run mypy type checker
	uv run mypy src/

test: ## Run tests
	uv run pytest

test-cov: ## Run tests with coverage report
	uv run pytest --cov=src --cov-report=term-missing

security: ## Run bandit security scan
	uv run bandit -c pyproject.toml -r src/

check: lint format-check type-check security test ## Run all checks

# --- Infrastructure ---

.PHONY: dev infra docker-up docker-build docker-down docker-logs docker-ps

COMPOSE      := docker compose -f docker/docker-compose.yml
COMPOSE_PROD := $(COMPOSE) -f docker/docker-compose.prod.yml

dev: ## Start the app (infra assumed running)
	uv run python -m pydentity

infra: ## Start infrastructure only (postgres, redis, mailhog)
	$(COMPOSE) up -d

docker-up: ## Start app + infrastructure (detached)
	$(COMPOSE_PROD) up -d

docker-build: ## Build and start app + infrastructure
	$(COMPOSE_PROD) up --build -d

docker-down: ## Stop and remove containers
	$(COMPOSE_PROD) down

docker-logs: ## Tail logs for all services
	$(COMPOSE_PROD) logs -f

docker-ps: ## Show running service status
	$(COMPOSE_PROD) ps

# --- Release ---

.PHONY: release generate-keys

release: ## Tag and push a release (use: make release V=1.0.0)
	@test -n "$(V)" || (echo "Usage: make release V=1.0.0" && exit 1)
	git tag -a "v$(V)" -m "Release v$(V)"
	git push origin "v$(V)"

generate-keys: ## Generate RSA 2048-bit signing key in keys/
	@mkdir -p keys
	openssl genrsa -out keys/$$(date +%Y-%m-%d).pem 2048
	chmod 600 keys/*.pem

# --- Diagrams ---

.PHONY: diagrams diagrams-svg diagrams-clean

diagrams: ## Render PlantUML diagrams to PNG
	plantuml -tpng docs/diagrams/*.puml

diagrams-svg: ## Render PlantUML diagrams to SVG
	plantuml -tsvg docs/diagrams/*.puml

diagrams-clean: ## Remove rendered diagram images
	rm -f docs/diagrams/*.png docs/diagrams/*.svg

# --- Cleanup ---

.PHONY: clean

clean: ## Remove build artifacts and caches
	rm -rf dist/ build/ .ruff_cache/ .pytest_cache/ .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
