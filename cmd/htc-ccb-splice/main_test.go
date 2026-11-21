package main

import "testing"

// TestDefaultListenPrefersTheStagedConfiguration: a staged helper crosses an
// SSH session with `env -i`, so an environment variable is the only channel
// the broker that started it has.
func TestDefaultListenPrefersTheStagedConfiguration(t *testing.T) {
	t.Setenv("CCB_SPLICE_LISTEN", "10.0.0.5:9999")
	if got := defaultListen(); got != "10.0.0.5:9999" {
		t.Errorf("defaultListen() = %q, want the staged value", got)
	}
}

// TestDefaultListenIsLoopback: the common case is daemons on this same host,
// and a wildcard bind would offer the pool's inside to anything that can route
// here. A helper serving other hosts is told so explicitly.
func TestDefaultListenIsLoopback(t *testing.T) {
	t.Setenv("CCB_SPLICE_LISTEN", "")
	got := defaultListen()
	if got != "127.0.0.1:9618" {
		t.Errorf("defaultListen() = %q, want loopback", got)
	}
}
