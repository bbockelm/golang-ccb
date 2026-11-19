package ccbserver

import (
	"net"
	"os"
	"strings"
	"testing"
)

func TestParseCarrierRef(t *testing.T) {
	for _, tc := range []struct {
		name   string
		addr   string
		want   carrierRef
		spawns bool
	}{
		{"filesystem", "fs:/gpfs/pool/ccb", carrierRef{scheme: "fs", path: "/gpfs/pool/ccb"}, false},
		{"websocket", "wss://cm.example.org/ccb/tunnel", carrierRef{scheme: "ws", url: "wss://cm.example.org/ccb/tunnel", tls: true}, false},
		{"websocket plaintext", "ws://cm.example.org/ccb/tunnel", carrierRef{scheme: "ws", url: "ws://cm.example.org/ccb/tunnel"}, false},
		{"raw tcp", "tcp://127.0.0.1:9700", carrierRef{scheme: "tcp", addr: "127.0.0.1:9700"}, false},
		{"command", "cmd:ssh bastion htc-ccb -carrier-stdio", carrierRef{scheme: "cmd", argv: "ssh bastion htc-ccb -carrier-stdio"}, true},
		{"command is trimmed", "cmd:  ssh bastion  ", carrierRef{scheme: "cmd", argv: "ssh bastion"}, true},
		{"stdio", "stdio:", carrierRef{scheme: "stdio"}, true},
		{"stdio without colon", "stdio", carrierRef{scheme: "stdio"}, true},
		{"surrounding space", "  tcp://host:9700  ", carrierRef{scheme: "tcp", addr: "host:9700"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseCarrierRef(tc.addr)
			if !ok {
				t.Fatalf("parseCarrierRef(%q) did not recognize a carrier", tc.addr)
			}
			if got != tc.want {
				t.Errorf("parseCarrierRef(%q) = %+v, want %+v", tc.addr, got, tc.want)
			}
			if got.spawns() != tc.spawns {
				t.Errorf("%q spawns() = %v, want %v", tc.addr, got.spawns(), tc.spawns)
			}
		})
	}
}

// A plain Sinful is not a carrier; it keeps the default TCP path. The
// distinction matters most for tcp://, which names a RAW carrier pipe rather
// than the broker's CEDAR port -- the two are not interchangeable, since the
// CEDAR port expects one connection per socket and the carrier is multiplexed.
func TestParseCarrierRefLeavesSinfulsAlone(t *testing.T) {
	for _, addr := range []string{
		"cm.example.org:9618",
		"<127.0.0.1:9618>",
		"<127.0.0.1:9618?sock=collector>",
		"",
		"127.0.0.1:9618#1",
		"stdiosomething",
		"commandish:ssh host",
	} {
		if _, ok := parseCarrierRef(addr); ok {
			t.Errorf("parseCarrierRef(%q) treated a non-carrier address as a carrier", addr)
		}
	}
}

// A carrierRef must stay comparable: detectCarrier compares the refs found on
// the two inside-broker knobs for equality, so a field that cannot be compared
// (a parsed []string argv) would not merely fail to build -- it would have to
// be compared some other way, and the two knobs could silently disagree.
func TestCarrierRefIsComparable(t *testing.T) {
	a, _ := parseCarrierRef("cmd:ssh bastion htc-ccb")
	b, _ := parseCarrierRef("cmd:ssh bastion htc-ccb")
	c, _ := parseCarrierRef("cmd:ssh other-bastion htc-ccb")
	if a != b {
		t.Error("identical carrier addresses produced unequal refs")
	}
	if a == c {
		t.Error("different carrier commands produced equal refs")
	}
}

// A malformed command line is reported when the broker is built, which is at
// startup, rather than on the first dial hours later.
func TestCarrierCommandIsValidatedAtStartup(t *testing.T) {
	_, err := New(Config{
		PublicAddress:           "127.0.0.1:9618",
		Security:                plaintextSec(),
		OutboundNextHop:         "cmd:ssh bastion | tee log",
		OutboundNextHopSecurity: plaintextSec(),
	})
	if err == nil {
		t.Fatal("a carrier command with unquoted shell syntax was accepted")
	}
	if got := err.Error(); !strings.Contains(got, "not through a shell") {
		t.Errorf("error %q does not explain the problem", got)
	}
}

// One inherited pipe cannot carry both roles. Configured on both knobs it would
// be handed to each, and the two would interleave yamux frames on the same
// descriptors -- which looks like a corrupt peer, not a misconfiguration.
func TestStdioCannotBeBothRoles(t *testing.T) {
	_, err := New(Config{
		PublicAddress: "127.0.0.1:9618",
		Security:      plaintextSec(),
		CarrierListen: "stdio:",
		CarrierPipe:   testPipe(t),
		Upstream: &UpstreamConfig{
			BrokerAddr: "stdio:",
			Security:   plaintextSec(),
		},
	})
	if err == nil {
		t.Fatal("stdio: was accepted as both the carrier and the carrier listener")
	}
	if !strings.Contains(err.Error(), "both roles") && !strings.Contains(err.Error(), "cannot carry both") {
		t.Errorf("error %q does not explain that one pipe cannot do both", err)
	}
}

// testPipe is a stand-in for an inherited stdio pipe.
func testPipe(t *testing.T) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a
}

func TestParseSSHCarrierRef(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want carrierRef
	}{
		{"ssh://login.cluster.edu", carrierRef{scheme: "ssh", addr: "login.cluster.edu"}},
		{"ssh://ccb@login.cluster.edu", carrierRef{scheme: "ssh", addr: "login.cluster.edu", user: "ccb"}},
		{"ssh://ccb@login.cluster.edu:2222", carrierRef{scheme: "ssh", addr: "login.cluster.edu:2222", user: "ccb"}},
		{"ssh://login.cluster.edu/", carrierRef{scheme: "ssh", addr: "login.cluster.edu"}},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			got, ok := parseCarrierRef(tc.addr)
			if !ok {
				t.Fatalf("parseCarrierRef(%q) did not recognize a carrier", tc.addr)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
			// ssh has no listening form: an outside broker using one reaches
			// out, so its source is presented as a listener.
			if !got.spawns() {
				t.Error("an ssh carrier claims to have a listening form")
			}
		})
	}
}

// A carrier that cannot verify the host it hands the tunnel to is refused at
// startup, not defaulted into accepting anything.
func TestSSHCarrierRequiresKnownHosts(t *testing.T) {
	_, err := New(Config{
		PublicAddress:           "127.0.0.1:9618",
		Security:                plaintextSec(),
		OutboundNextHop:         "ssh://login.cluster.edu",
		OutboundNextHopSecurity: plaintextSec(),
		CarrierSSH:              SSHCarrierConfig{StageBinary: "/usr/sbin/htc-ccb"},
	})
	if err == nil {
		t.Fatal("an ssh:// carrier was accepted with no known_hosts")
	}
	if !strings.Contains(err.Error(), "KNOWN_HOSTS") {
		t.Errorf("error %q does not name the missing setting", err)
	}
}

// Without a binary to stage there is nothing to run, so one of the two must be
// configured.
func TestSSHCarrierNeedsABinaryOrACommand(t *testing.T) {
	kh := t.TempDir() + "/known_hosts"
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{
		PublicAddress:           "127.0.0.1:9618",
		Security:                plaintextSec(),
		OutboundNextHop:         "ssh://login.cluster.edu",
		OutboundNextHopSecurity: plaintextSec(),
		CarrierSSH:              SSHCarrierConfig{KnownHosts: []string{kh}},
	})
	if err == nil {
		t.Fatal("an ssh:// carrier was accepted with neither a binary nor a command")
	}
	if !strings.Contains(err.Error(), "STAGE_BINARY") {
		t.Errorf("error %q does not say what is missing", err)
	}
}

// With both the host-key policy and a binary, the carrier builds.
func TestSSHCarrierBuilds(t *testing.T) {
	kh := t.TempDir() + "/known_hosts"
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		PublicAddress:           "127.0.0.1:9618",
		Security:                plaintextSec(),
		OutboundNextHop:         "ssh://ccb@login.cluster.edu",
		OutboundNextHopSecurity: plaintextSec(),
		CarrierSSH: SSHCarrierConfig{
			KnownHosts:  []string{kh},
			StageBinary: "/usr/sbin/htc-ccb",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv.carrier == nil {
		t.Fatal("no carrier was built for an ssh:// next hop")
	}
	if got := srv.carrier.describe(); got != "ssh://ccb@login.cluster.edu" {
		t.Errorf("describe() = %q", got)
	}
}
