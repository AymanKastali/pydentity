# pydentity

An enterprise-grade authentication and identity microservice built with Python 3.14+, FastAPI, and PostgreSQL.

![Python 3.14+](https://img.shields.io/badge/Python-3.14%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-asyncpg-4169E1)
![Redis](https://img.shields.io/badge/Redis-5%2B-DC382D)

## Features

- **RS256 JWT Authentication** -- asymmetric signing with key rotation and a `/.well-known/jwks.json` discovery endpoint
- **RBAC** -- roles and fine-grained permissions, assignable per user
- **Device Tracking & Session Management** -- per-device sessions with configurable limits and absolute TTLs
- **Password Policy Enforcement** -- min length, complexity rules, password history, account lockout after failed attempts
- **Email Verification & Password Reset** -- token-based flows with configurable TTLs, delivered via SMTP
- **Event-Driven Architecture** -- domain events published over Redis pub/sub
- **Rate Limiting** -- Redis-backed, per-endpoint (general and auth-specific windows)
- **Security Headers** -- HSTS, CSP, X-Frame-Options, Trusted Host validation
- **Audit Trail** -- composite logging + persistence for security-relevant actions

## Architecture

The project follows **Hexagonal Architecture** and **Evans DDD**. Dependencies flow inward only: `adapters` -> `application` -> `domain`.

```
src/pydentity/
  domain/           # Aggregates, entities, value objects, domain events, ports
    models/         #   User, Role, Session, Device
    services/       #   Domain services (registration, password change, etc.)
    events/         #   Domain events (user, session, device, role)
    ports/          #   Repository & infrastructure contracts
  application/      # Use cases, DTOs, event handlers, application ports
    use_cases/      #   Organized by subdomain: auth, account, email, password, role
    ports/          #   Token signer/verifier, notification, event publisher
  adapters/         # Framework & infrastructure wiring
    inbound/api/    #   FastAPI routes, schemas, middleware, dependencies
    outbound/       #   PostgreSQL repos, Redis events, SMTP, JWT, security
    config/         #   Settings (Pydantic Settings, env-driven)
```

## Getting Started

### Prerequisites

- Python 3.14+
- [uv](https://docs.astral.sh/uv/)
- Docker & Docker Compose

### Quick Start (DevContainer)

Open the repo in VS Code with the Dev Containers extension -- everything is pre-configured.

### Quick Start (Docker)

```bash
make docker-build     # builds and starts app + infra (postgres, redis, mailhog)
```

The API will be available at `http://localhost:8000`. MailHog UI at `http://localhost:8025`.

### Local Development

```bash
make setup            # install deps, set up pre-commit hooks
make infra            # start postgres, redis, mailhog via docker compose
make migrate          # apply database migrations
make dev              # start the app
```

## Configuration

All settings are read from environment variables with the `PYDENTITY_` prefix. Nested keys use `__` as a separator.

Copy the example file and fill in required values:

```bash
cp .env.example .env
```

| Section | Prefix | Key Settings |
|---------|--------|--------------|
| PostgreSQL | `PYDENTITY_POSTGRES__` | `DSN`, `POOL_SIZE`, `MAX_OVERFLOW` |
| Security | `PYDENTITY_SECURITY__` | `JWT_KEY_DIRECTORY`, `TOKEN_ISSUER`, `TOKEN_AUDIENCES`, `ACCESS_TOKEN_TTL_SECONDS`, lockout & password policy |
| SMTP | `PYDENTITY_SMTP__` | `HOST`, `PORT`, `SENDER`, TLS settings |
| Redis | `PYDENTITY_REDIS__` | `URL`, `EVENT_CHANNEL` |
| FastAPI | `PYDENTITY_FASTAPI__` | `HOST`, `PORT`, `IS_PRODUCTION` |
| Middleware | `PYDENTITY_MIDDLEWARE__` | CORS origins, trusted hosts, rate limit windows |
| Logging | `PYDENTITY_LOGGING__` | `LEVEL`, `JSON_FORMAT` |
| Super Admin | `PYDENTITY_SUPER_ADMIN__` | `EMAIL`, `PASSWORD` (both required if seeding; omit both to skip) |

See [`.env.example`](.env.example) for the full list with defaults and descriptions.

## API Endpoints

### Auth (`/auth`)

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/auth/register` | Register a new user | No |
| POST | `/auth/login` | Authenticate and get tokens | No |
| POST | `/auth/refresh` | Refresh access token | No |
| POST | `/auth/logout` | Logout and invalidate session | Yes |

### Account (`/account`)

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| PATCH | `/account/email` | Change email address | Yes |
| POST | `/account/suspend` | Suspend a user | `USERS_SUSPEND` |
| POST | `/account/reactivate` | Reactivate a user | `USERS_REACTIVATE` |
| POST | `/account/deactivate` | Deactivate a user | `USERS_DEACTIVATE` |

### Email (`/email`)

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/email/verify` | Verify email with token | No |
| POST | `/email/resend-verification` | Resend verification email | No |

### Password (`/password`)

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/password/reset-request` | Request a password reset | No |
| POST | `/password/reset` | Reset password with token | No |
| POST | `/password/change` | Change password | Yes |

### Roles (`/roles`)

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/roles` | Create a role | `ROLES_CREATE` |
| PATCH | `/roles/{role_name}/description` | Update role description | `ROLES_UPDATE` |
| POST | `/roles/{role_name}/permissions` | Add permission to role | `ROLES_UPDATE` |
| DELETE | `/roles/{role_name}/permissions` | Remove permission from role | `ROLES_UPDATE` |
| POST | `/roles/{role_name}/assign` | Assign role to user | `ROLES_ASSIGN` |
| POST | `/roles/{role_name}/revoke` | Revoke role from user | `ROLES_REVOKE` |

### Well-Known

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/.well-known/jwks.json` | Public key set (JWKS) | No |

## Development Commands

| Command | Description |
|---------|-------------|
| `make setup` | Install deps and set up pre-commit hooks |
| `make sync` | Sync all dependencies |
| `make check` | Run all checks (lint + format + types + tests) |
| `make lint` | Run ruff linter |
| `make format` | Auto-format code |
| `make type-check` | Run mypy |
| `make test` | Run tests |
| `make test-cov` | Run tests with coverage |
| `make dev` | Start the app locally |
| `make infra` | Start infrastructure (postgres, redis, mailhog) |
| `make docker-build` | Build and start app + infrastructure |
| `make docker-down` | Stop and remove containers |
| `make docker-logs` | Tail logs for all services |
| `make clean` | Remove build artifacts and caches |

## Database Migrations

```bash
make migrate                          # apply all pending migrations
make migrate-new MSG="description"    # generate a new auto migration
make migrate-down                     # rollback one step
make migrate-history                  # show migration history
make migrate-current                  # show current revision
```

## Key Generation

Generate RSA 2048-bit signing keys for JWT:

```bash
make generate-keys
```

Keys are written to `keys/` with the current date as filename. The app loads all `.pem` files from the configured `JWT_KEY_DIRECTORY` and signs with the most recent key, enabling zero-downtime key rotation.

---

*Generated by [devstart](https://github.com/AymanKastali/DevStart)*
