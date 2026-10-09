package config

import "flag"

// Registered at package init: re-registering on each Load() would panic with "flag
// redefined". main() must call flag.Parse() before Load() (see cmd/server).
var (
	flagPort    = flag.Int("port", 8080, "TCP port the api binds to")
	flagLevel   = flag.String("log-level", "info", "slog log level (debug|info|warn|error)")
	flagCertURL = flag.String("cert-url", "", "KUBESEAL_CERT_URL: HTTP endpoint for controller public certificate")
	flagFakeK8s = flag.Bool("fake-k8s", false, "Use fake Kubernetes client (dev only)")
)
