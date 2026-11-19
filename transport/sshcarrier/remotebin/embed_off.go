//go:build !embedremote

package remotebin

// Without the embedremote tag nothing is compiled in: the binary stays the
// size it would otherwise be, and staging needs a directory.
func embedded(string) ([]byte, bool) { return nil, false }

func embeddedNames() []string { return nil }
