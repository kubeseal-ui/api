# kubeseal-ui-api

Go backend for kubeseal-ui

## Repository Structure

- `api/` - Go backend source code
- `cmd/server/` - Entry point for the API server
- `internal/` - Private packages organized by functionality
- `go.mod` - Go module definition
- `Dockerfile` - Container image build definition
- `.github/workflows/ci.yml` - GitHub Actions CI/CD pipeline
- `.gitignore` - Files to exclude from version control

## Key Components

### API Endpoints

- `/api/v1/healthz` - Liveness probe
- `/api/v1/readyz` - Readiness probe
- `/api/v1/auth/*` - Authentication endpoints (OIDC)
- `/api/v1/config` - Configuration endpoint
- `/api/v1/namespaces` - List namespaces
- `/api/v1/secrets` - List secrets
- `/api/v1/secrets/{namespace}/{name}` - Get individual secret
- `/api/v1/secrets/{namespace}/{name}/yaml` - Get secret YAML (encrypted)
- `/api/v1/secrets/encrypt` - Create new sealed secret
- `/api/v1/secrets/{namespace}/{name}/reveal` - Reveal one key
- `/api/v1/secrets/{namespace}/{name}/values/{key}` - Patch one key value
- `/api/v1/gitops/dry-run` - Dry run for GitOps delivery
- `/api/v1/gitops/deliver` - Deliver encrypted secret to Git

### Authentication

Uses OIDC Authorization Code flow with PKCE. Authentik is the recommended OIDC provider.

### Deployment

- API service runs in a container with port 8080
- Frontend service runs in a container with port 80
- Both services communicate via internal network
- GitOps delivery through platform-agnostic go-git transport

## Development

### Prerequisites

- Go 1.27
- Node.js 26 (LTS) (for frontend)
- Docker
- Kubernetes cluster with Sealed Secrets controller

### Running Locally

#### API Server
```bash
cd api
go run ./cmd/server
```

#### Frontend
```bash
cd frontend
npm run dev
```

### Building Images

#### API Image
```bash
docker build -f Dockerfile -t kubeseal-api:dev .
```

#### Frontend Image
```bash
docker build -f Dockerfile -t kubeseal-ui:dev .
```

## Security

- All secrets are encrypted at rest and in transit
- No plaintext secrets in browser or logs
- OIDC authentication with PKCE
- Structured security events for auditability

## License

MIT License

## Contact

For support or questions, please open an issue on GitHub.