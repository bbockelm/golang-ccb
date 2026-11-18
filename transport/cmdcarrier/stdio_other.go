//go:build !(linux || darwin)

package cmdcarrier

import (
	"errors"
	"log/slog"
	"net"
)

// Stdio is unsupported on this platform: claiming stdin and stdout safely needs
// descriptor redirection this package implements only for Linux and macOS,
// which are the platforms htc-ccb ships for.
func Stdio(*slog.Logger) (net.Conn, error) {
	return nil, errors.New("cmdcarrier: the stdio carrier is supported only on Linux and macOS")
}
