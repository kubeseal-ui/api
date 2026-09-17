# Proposal adapters

Git delivery in kubeseal-ui is platform-agnostic: fetch, branch, commit, and push go through a go-git
transport that works with any compatible remote. Only the review object (pull request, merge request) is host
specific, and that is the sole job of a proposal adapter.

## Contract

```go
type ProposalProvider interface {
    OpenProposal(ctx context.Context, request ProposalRequest) (ProposalResult, error)
}
```

A proposal delivery does exactly this:

1. read the namespace mapping (repository, base branch, path template, auth reference, fixed mode)
2. push the change to a server-derived branch, `kubeseal-ui/<namespace-path>`
3. call the configured adapter with the pushed branch and commit
4. return `mode`, `branch`, `commit_sha`, `proposal_url`, and `argocd_sync_verified: false`

The branch name is deterministic, so retrying a delivery reconciles onto the same branch. An adapter failure
after the push returns `502 PROPOSAL_FAILED`; the branch is left in place and the retry with a fresh
`Idempotency-Key` tries the host call again.

Direct delivery never invokes an adapter, and a namespace cannot switch modes: policy fixes `direct` or
`proposal`.

## Configuration

Adapters are declared as `name:type:token_file[:base_url]` entries, comma separated:

```text
GITOPS_PROPOSAL_ADAPTERS=github-pr:github:/var/run/secrets/git/proposal/token
```

In the Helm chart:

```yaml
api:
  gitops:
    enabled: true
    proposalAdapters:
      - name: github-pr
        type: github
        tokenFile: /var/run/secrets/git/proposal/token
        # baseUrl: https://github.example.com/api/v3   # GitHub Enterprise Server
    proposalCredentialSecretName: kubeseal-ui-proposal
    namespaces:
      - namespace: staging
        repository: org/platform-repo
        branch: main
        pathTemplate: clusters/{namespace}/{name}.yaml
        authRef: platform-repo
        mode: proposal
        proposalAdapter: github-pr
```

Fail-closed rules:

- a namespace that names an adapter which is not declared stops the API from booting
- an unknown adapter `type` stops the API from booting
- a malformed entry (missing name, type, or token file) or a duplicate name stops the API from booting
- an empty adapter list is valid only while every mapped namespace is `direct`

## GitHub adapter (`type: github`)

- Endpoint: `POST <base>/repos/<owner>/<repo>/pulls`, `Accept: application/vnd.github+json`,
  `X-GitHub-Api-Version: 2022-11-28`, `Authorization: Bearer <token>`.
- Token: a fine-grained personal access token with Contents read/write and Metadata read, stored in a
  Kubernetes Secret and mounted as a file. The file is read on every call, so rotating the Secret takes effect
  without a restart. Tokens never appear in configuration, logs, or responses.
- Base URL: empty means `https://api.github.com`; set `baseUrl` for GitHub Enterprise Server
  (`https://<host>/api/v3`).
- The repository identifier must be exactly `owner/repo`. Anything else fails before the host is called.
- Non-2xx responses fail the delivery. The error carries the status and a truncated host response; the token
  never does.

## Adding a host adapter

1. Implement `ProposalProvider` in a package under `internal/gitops`.
2. Read credentials from a mounted file per call rather than from configuration.
3. Add the type to the registry switch in `cmd/server/main.go` and fail closed on unknown types.
4. Add contract tests for request shape, success, host error, transport error, missing credential, and bad
   repository shape. The GitHub adapter tests in `internal/gitops/github_test.go` are the reference.

GitLab merge requests, Gitea/Forgejo, and Bitbucket adapters are follow-on work; generic direct delivery does
not depend on any of them.
