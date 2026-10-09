// Typed authentication references for the go-git transport: the platform-neutral transport
// carries typed, go-git-supported credentials. Every credential value resolves from a file
// (a Kubernetes Secret mount) at request time; tokens are never embedded in configuration or
// logged.
package gitops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
)

type AuthMode string

const (
	// AuthModeHTTPSToken sends Username as the Basic username and Token as the Basic
	// password over HTTPS. The default platform mode.
	AuthModeHTTPSToken AuthMode = "https-token"
	// AuthModeSSHAgent authenticates over SSH through the local agent.
	AuthModeSSHAgent AuthMode = "ssh-agent"
	// AuthModeNone sends no credentials. Valid only for open test remotes.
	AuthModeNone AuthMode = "none"
)

func KnownAuthModes() []AuthMode {
	return []AuthMode{AuthModeHTTPSToken, AuthModeSSHAgent, AuthModeNone}
}

// ParseAuthMode resolves a raw string to a typed AuthMode, failing closed on unknown values.
func ParseAuthMode(raw string) (AuthMode, error) {
	mode := AuthMode(strings.TrimSpace(raw))
	for _, known := range KnownAuthModes() {
		if mode == known {
			return mode, nil
		}
	}
	return "", fmt.Errorf("unknown auth mode %q", raw)
}

// Credential is the typed authentication reference handed to the transport. Token values
// come from Secret-mounted files and must never be logged; the redacting slog handler drops
// any attribute key containing "token".
type Credential struct {
	Mode     AuthMode
	Username string
	Token    string
	// TokenFile resolves the token from a Secret-mounted file at call time. Mutually
	// exclusive with Token.
	TokenFile string
}

// Validate checks the typing: https-token needs exactly one of Token/TokenFile, and none
// may carry values. An empty Username defaults to "kubeseal-ui" at transport time.
func (c Credential) Validate() error {
	switch c.Mode {
	case AuthModeHTTPSToken:
		if c.Token == "" && c.TokenFile == "" {
			return errors.New("https-token credential requires a token or token file")
		}
		if c.Token != "" && c.TokenFile != "" {
			return errors.New("https-token credential must not set both token and token file")
		}
		return nil
	case AuthModeSSHAgent:
		return nil
	case AuthModeNone:
		if c.Token != "" || c.TokenFile != "" || c.Username != "" {
			return errors.New("none credential must not carry values")
		}
		return nil
	default:
		return fmt.Errorf("unknown auth mode %q", string(c.Mode))
	}
}

// transportAuth converts the typed credential to a go-git AuthMethod, resolving TokenFile
// at call time so rotated Secrets take effect without a restart.
func (c Credential) transportAuth() (transport.AuthMethod, error) {
	switch c.Mode {
	case AuthModeHTTPSToken:
		token := c.Token
		if c.TokenFile != "" {
			raw, err := os.ReadFile(c.TokenFile)
			if err != nil {
				return nil, fmt.Errorf("read token file: %w", err)
			}
			token = strings.TrimSpace(string(raw))
		}
		if token == "" {
			return nil, errors.New("https-token credential resolved an empty token")
		}
		username := c.Username
		if username == "" {
			username = "kubeseal-ui"
		}
		return &githttp.BasicAuth{Username: username, Password: token}, nil
	case AuthModeSSHAgent:
		return gitssh.NewSSHAgentAuth("git")
	case AuthModeNone:
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown auth mode %q", string(c.Mode))
	}
}

// CredentialResolver maps a server-side auth reference to the typed credential for a
// repository. Resolvers fail closed: an unknown reference is an error, never an implicit
// unauthenticated push.
type CredentialResolver interface {
	Resolve(ctx context.Context, repository, authRef string) (Credential, error)
}

// StaticCredentialResolver serves pre-loaded credentials; tests and local remotes use it.
// Production wiring uses FileCredentialResolver.
type StaticCredentialResolver struct {
	credentials map[string]Credential
}

func NewStaticCredentialResolver(credentials map[string]Credential) *StaticCredentialResolver {
	return &StaticCredentialResolver{credentials: credentials}
}

func (r *StaticCredentialResolver) Set(authRef string, credential Credential) {
	if r.credentials == nil {
		r.credentials = make(map[string]Credential)
	}
	r.credentials[authRef] = credential
}

func (r *StaticCredentialResolver) Resolve(_ context.Context, _, authRef string) (Credential, error) {
	if r == nil {
		return Credential{}, errors.New("no credential resolver configured")
	}
	credential, ok := r.credentials[authRef]
	if !ok {
		return Credential{}, fmt.Errorf("no credential for auth reference %q", authRef)
	}
	return credential, nil
}

// FileCredential is the configuration-side typed reference whose token resolves from a
// Secret-mounted file at request time.
type FileCredential struct {
	AuthRef   string
	Mode      AuthMode
	Username  string
	TokenFile string
}

func (c FileCredential) Validate() error {
	if c.AuthRef == "" {
		return errors.New("auth_ref is required")
	}
	if _, err := ParseAuthMode(string(c.Mode)); err != nil {
		return err
	}
	if c.Mode == AuthModeHTTPSToken && c.TokenFile == "" {
		return errors.New("https-token credential requires token_file")
	}
	return nil
}

// FileCredentialResolver resolves FileCredential references by reading the token from disk
// per call.
type FileCredentialResolver struct {
	credentials map[string]FileCredential
}

func NewFileCredentialResolver(credentials []FileCredential) (*FileCredentialResolver, error) {
	resolver := &FileCredentialResolver{credentials: make(map[string]FileCredential)}
	for _, credential := range credentials {
		if err := credential.Validate(); err != nil {
			return nil, fmt.Errorf("credential %q: %w", credential.AuthRef, err)
		}
		resolver.credentials[credential.AuthRef] = credential
	}
	return resolver, nil
}

// Resolve reads the referenced token file. Every call re-reads so Secret rotation is picked
// up without a restart.
func (r *FileCredentialResolver) Resolve(_ context.Context, _, authRef string) (Credential, error) {
	credential, ok := r.credentials[authRef]
	if !ok {
		return Credential{}, fmt.Errorf("no credential for auth reference %q", authRef)
	}
	return Credential{Mode: credential.Mode, Username: credential.Username, TokenFile: credential.TokenFile}, nil
}
