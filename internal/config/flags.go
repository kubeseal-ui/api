package config

import "flag"

// Flag registration happens at package init so the global flag set is
// defined only once per process. Calling Load() multiple times (notably
// from tests) would otherwise panic with "flag redefined".
//
// flag.Parse() must be called from main() before Load(); see cmd/server.
var (
	flagPort  = flag.Int("port", 8080, "TCP port the api binds to")
	flagLevel = flag.String("log-level", "info", "slog log level (debug|info|warn|error)")
)
