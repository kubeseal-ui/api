# kubeseal-ui-api

Go backend for kubeseal-ui. The Vue frontend is a separate repository (`kubeseal-ui-frontend`).

## Repository Structure

- `cmd/server/` - Entry point and the chi router: the route table, the middleware chain, and the boot
  that withholds the authenticated tree when OIDC or a session signing key is missing
- `internal/` - Private packages: `auth` (OIDC, sessions, CSRF), `crypto` (sealing, decryption, key
  cache), `gitops` (delivery transports and proposal adapters), `kubernetes` (read-only cluster
  access), `policy` (capability decisions and namespace mappings), `handlers`, `config`,
  `middleware`, `metrics`, `observability`, `certprovider`
- `go.mod` - Go module definition
- `Dockerfile` - Container image build definition
- `version.txt` - Build version, stamped into the image
- `.env.example` - Every environment variable, with defaults and reasons
- `.golangci.yml` - Linter configuration
- `.github/workflows/ci-cd.yml` - GitHub Actions CI/CD pipeline
- `.github/dependabot.yml` - Dependency update configuration
- `.gitignore` - Files to exclude from version control

## Key Components

### API Endpoints

Unauthenticated, at the root:

- `GET /healthz` - Liveness probe
- `GET /readyz` - Readiness probe
- `GET /metrics` - Prometheus exposition; answers 503 when metrics are disabled, so a ServiceMonitor
  reads the target as down rather than scraping an empty page

Under `/api/v1`:

- `GET /auth/login`, `GET /auth/callback` - OIDC Authorization Code flow with PKCE
- `POST /auth/logout`, `GET /auth/me`, `GET /auth/csrf` - Session, and the CSRF token the SPA echoes
  in `X-CSRF-Token` on state-changing requests
- `GET /namespaces` - List the namespaces the caller can read, each with its delivery mode
- `GET /secrets` - List Secrets, each with its drift status
- `GET /secrets/{namespace}/{name}` - Secret detail, including its encrypted manifest and Git status
- `POST /secrets/encrypt` - Create a new SealedSecret, from a typed manifest or a pasted live one
- `POST /secrets/{namespace}/{name}/reveal` - Reveal one key
- `POST /secrets/{namespace}/{name}/diff` - Review a batch of key changes as an encrypted before/after pair
- `PATCH /secrets/{namespace}/{name}/values` - Apply a reviewed batch of key changes
- `GET /gitops/paths` - List the Git paths mapped for the caller's namespaces
- `POST /gitops/dry-run` - Dry run for a GitOps delivery
- `POST /gitops/deliver` - Deliver the encrypted manifest to Git
- `GET /gitops/sync` - Read drift status
- `POST /gitops/sync` - Reconcile a live Secret into its mapped Git file

The whole `/api/v1` tree is mounted only when OIDC is configured and a session signing key is set.
Without them the server boots fail-closed with every route above absent, and says so in the log.

### Authentication

OIDC Authorization Code flow with PKCE, run server-side: the browser never receives a token, a client
id, or the provider URL. Sessions ride in HttpOnly cookies, and state-changing requests carry a CSRF
token. Authentik is the recommended OIDC provider.

### GitOps delivery

Delivery is server-mapped: clients never choose the repository, branch, path, or mode. The namespace
mapping fixes all four, the typed credential reference selects the go-git authentication, and a
proposal namespace additionally needs an adapter declared in `GITOPS_PROPOSAL_ADAPTERS`.

### Documentation

Architecture contracts, deployment, and operator documentation live in the project's `internal-docs/`
tree, which is a sibling of this repository rather than part of it. `architecture/api.md` carries the
endpoint contract, `deployment/` the Helm, RBAC, and ingress shapes, `operations/` the runbook,
troubleshooting, and user guide, and `decisions/` the ADRs. Configuration is documented in
[.env.example](.env.example), the in-repo reference for every variable, its default, and why.

### Deployment

- API service runs in a container on port 8080
- Frontend service runs in a container on port 80
- Both services communicate over the cluster's internal network
- GitOps delivery through a platform-agnostic go-git transport

## Development

### Prerequisites

- Go 1.27
- Docker
- Kubernetes cluster with a Sealed Secrets controller

### Running Locally

Run from the repository root:

```bash
go run ./cmd/server
```

The server takes `-port` (8080), `-log-level` (`info`), `-cert-url`, and `-fake-k8s`; every
environment variable and its default is documented in [.env.example](.env.example). Reveal/decrypt and
GitOps delivery are both off by default — `ENABLE_DECRYPT=true` and `GITOPS_ENABLED=true` turn them on.

The frontend is a separate repository; start it there with `npm run dev` and it will proxy `/api`
here.

### Building Images

#### API Image

```bash
docker build -f Dockerfile -t kubeseal-api:dev .
```

#### Frontend Image

Built from the `kubeseal-ui-frontend` repository, not this one: its own `Dockerfile` runs
`npm run build` and serves `dist/` through nginx.

## Security

- The cluster client is read-only: the API reads Secrets and namespaces and writes only to Git, so a
  delivery reaches the cluster through reconciliation and never through this service.
- Reveal decrypts server-side, with the controller's private keys read from the labelled Secrets under the
  API's own RBAC. Editing needs only the public certificate: new values are sealed, untouched entries are
  carried through as they are, and no existing plaintext is read. Plaintext is scoped to the request that
  carries it and is never persisted.
- Reveal is opt-in per deployment (`ENABLE_DECRYPT`), and a namespace's grant must still permit it.
  Create and edit work without it.
- No value ever reaches a log or a security event: an event names the Secret, the operation, and the
  result, and nothing more.
- OIDC authentication with PKCE, HttpOnly session cookies, and CSRF protection on state-changing
  requests.

## License

MIT License

## Contact

Open an issue on GitHub. Community support only: no hosted service, no availability SLO. Report
vulnerabilities privately through the repository's Security tab rather than in a public issue.
