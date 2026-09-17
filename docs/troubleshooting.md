# Troubleshooting kubeseal-ui

Failure modes operators hit in practice, with the check that decides each one. The API logs one structured
JSON line per request with a `request_id`; quote it when asking for help and remember that security events
carry identity and resource fields only, never values.

## Login loop

The API and the identity provider disagree about the session. Check, in order:

1. OIDC discovery: `curl $OIDC_ISSUER/.well-known/openid-configuration` returns the issuer you configured.
2. The registered redirect URI matches `OIDC_REDIRECT_URL` byte for byte, including scheme and trailing path.
3. `SESSION_SIGNING_KEY` is set and stable across restarts. A rotated key invalidates every session, so the
   browser is redirected to login again immediately.
4. `CSRF_TRUSTED_ORIGINS` contains the browser origin that sends the request. State-changing requests from an
   unlisted origin are rejected with 403, which the UI surfaces as a failed action rather than a login loop.
5. Cookie flags: `COOKIE_DOMAIN` must cover the host serving the UI, and the UI must be reached over HTTPS
   because cookies are `Secure` and `HttpOnly`.

## Namespace or action missing

The API filters namespace and secret lists by capability, so an empty list is usually authorization, not an
outage.

1. Confirm the user's OIDC groups claim (`OIDC_GROUPS_CLAIM`) actually contains the groups your policy maps.
2. Confirm the group maps to a role that holds the capability the action needs. The API checks capabilities,
   never role names, so a custom role must list every capability it needs.
3. Confirm a namespace Git mapping exists. Without a mapping, delivery resolves `mapping not found` and no
   repository, branch, path, or mode can be derived.

## Existing secret cannot be edited

Editing an existing secret requires exactly one mapped Git file whose canonical SealedSecret content equals
the live resource. The error code tells you which side is wrong:

- `GIT_SOURCE_MISSING`: no file at the derived path on the mapped branch.
- `GIT_LIVE_DRIFT`: the Git and live content differ. Reconcile first, then edit.
- identity mismatch (`namespace`/`name` inside the manifest does not match the route): fix the manifest.
- pending ArgoCD reconciliation: the commit landed but the controller has not applied it yet.
- out-of-band cluster mutation: someone edited the live SealedSecret; restore one side first.

## Reveal unavailable

Reveal needs `ENABLE_DECRYPT=true` and the `secret:decrypt` capability, and the API must be able to read the
controller's active key.

1. `ENABLE_DECRYPT` is false by default; "true" is the only value that enables it.
2. The controller key RBAC must be rendered (`api.enableDecrypt=true` in the chart) and the active key label
   (`KUBESEAL_ACTIVE_KEY_LABEL`) must match a key Secret in `KUBESEAL_CONTROLLER_NAMESPACE`.
3. Every attempt emits a security event with operation, actor, scope, result, and request ID. A missing event
   means the request never reached the handler (check auth and CSRF middleware first).

Reveal returns exactly one requested value. It never serializes the whole decrypted object.

## Patch unavailable

Patching one key requires both `secret:seal` and `secret:decrypt`, because the server decrypts the complete
Secret internally to preserve unrelated values. A role with only `secret:seal` can create secrets but cannot
patch them.

## Wrong delivery action

Namespace policy fixes the delivery mode, and the client cannot override it.

- direct namespaces require `gitops:push`
- proposal namespaces require `gitops:propose` plus a configured proposal adapter

An adapter must be declared in `GITOPS_PROPOSAL_ADAPTERS` (chart: `api.gitops.proposalAdapters`). A namespace
naming an adapter that is not declared fails startup, which is deliberate: an unserviceable proposal namespace
must not boot.

## Generic Git authentication failure

Check the mapping's `authRef` against the typed credential list (`GITOPS_CREDENTIAL_REFS`).

- `https-token`: the configured username with the token as the HTTP Basic password. Verify the token file path
  is mounted and non-empty; the file is read on every call, so a rotated Secret needs no restart.
- `ssh-agent`: the agent socket must be reachable from the container.
- `none`: only valid for remotes that accept anonymous pushes.

An unknown `authRef` is an error, never an implicit anonymous push.

## Proposal adapter failure

A proposal delivery pushes a server-derived branch (`kubeseal-ui/<namespace-path>`) and then asks the host to
open the review object. If the host call fails you get `502 PROPOSAL_FAILED` and the branch already exists.

1. Retry with a fresh `Idempotency-Key`. The branch name is deterministic, so the retry reconciles onto the
   same branch instead of creating duplicates.
2. Verify the token file: a missing file fails with `read github token`, an empty file with
   `github token file is empty`.
3. Verify scopes. A GitHub fine-grained PAT needs Contents read/write and Metadata read.
4. Verify the API root. For GitHub Enterprise Server set the adapter `baseUrl` (`https://<host>/api/v3`);
   otherwise calls go to `api.github.com`.
5. Confirm the repository identifier is exactly `owner/repo`. The adapter rejects anything else before
   calling the host.

## ArgoCD has not applied delivery

A verified commit or a merged proposal does not mean ArgoCD synchronized. The delivery response always carries
`argocd_sync_verified: false` because the API never talks to ArgoCD. Check repository refresh, Application
health, SealedSecret events, and controller logs separately, and keep ArgoCD and SealedSecret health as two
independent checks.

## NetworkPolicy blocks traffic

The chart's policy refuses to guess egress destinations because the Kubernetes API, OIDC issuer, Git remotes,
and proposal APIs are environment specific. Provide `networkPolicy.egress.cidrs` or
`networkPolicy.egress.namespaceSelectors`; rendering with none fails. DNS egress to
`networkPolicy.dnsNamespace` (default `kube-system`) is always included, because dropping it breaks every
service lookup.

## Support boundary

Community support only: issues and discussions, no hosted service, no availability SLO. Operators own log
retention, backups, Git host availability, OIDC availability, ArgoCD operation, and Kubernetes recovery.
