package cmdcarrier

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseArgv(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want []string
	}{
		{"plain", "ssh bastion htc-ccb -carrier-stdio", []string{"ssh", "bastion", "htc-ccb", "-carrier-stdio"}},
		{"relay", "ssh -W outside-ccb.example.org:9700 bastion", []string{"ssh", "-W", "outside-ccb.example.org:9700", "bastion"}},
		{"extra spaces", "  ssh   bastion  ", []string{"ssh", "bastion"}},
		{"tabs", "ssh\tbastion", []string{"ssh", "bastion"}},
		{"absolute", "/usr/bin/ssh bastion", []string{"/usr/bin/ssh", "bastion"}},
		{"single quotes keep spaces", `ssh -o 'ProxyJump jump.example.org' host`, []string{"ssh", "-o", "ProxyJump jump.example.org", "host"}},
		{"double quotes keep spaces", `ssh -o "User my user" host`, []string{"ssh", "-o", "User my user", "host"}},
		{"quoted metacharacter is literal", `ssh -o 'ProxyCommand=nc -x proxy %h %p' host`, []string{"ssh", "-o", "ProxyCommand=nc -x proxy %h %p", "host"}},
		{"escaped space", `ssh my\ host`, []string{"ssh", "my host"}},
		{"escaped metacharacter", `ssh a\|b`, []string{"ssh", "a|b"}},
		{"backslash in double quotes", `ssh "a\"b"`, []string{"ssh", `a"b`}},
		{"empty argument", `ssh "" host`, []string{"ssh", "", "host"}},
		{"adjacent quoting", `ssh -o"User me"`, []string{"ssh", "-oUser me"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseArgv(tc.in)
			if err != nil {
				t.Fatalf("ParseArgv(%q): %v", tc.in, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseArgv(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A shell metacharacter the operator did not quote is refused rather than
// passed to the child as a literal argument, which is never what was meant and
// produces a baffling failure three layers down.
func TestParseArgvRejectsShellSyntax(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"pipe", "ssh host htc-ccb | tee log", `"|"`},
		{"semicolon", "ssh host; rm -rf /", `";"`},
		{"background", "ssh host &", `"&"`},
		{"redirect", "ssh host > out", `">"`},
		{"subshell", "ssh $(hostname)", `"$"`},
		{"backtick", "ssh `hostname`", "\"`\""},
		{"glob", "ssh host htc-ccb*", `"*"`},
		{"newline", "ssh host\nrm -rf /", `"\n"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseArgv(tc.in)
			if err == nil {
				t.Fatalf("ParseArgv(%q) accepted shell syntax", tc.in)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %s", err, tc.want)
			}
			if !strings.Contains(err.Error(), "not through a shell") {
				t.Errorf("error %q does not explain that there is no shell", err)
			}
		})
	}
}

func TestParseArgvErrors(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"unterminated single", `ssh 'host`, "unterminated single quote"},
		{"unterminated double", `ssh "host`, "unterminated double quote"},
		{"trailing backslash", `ssh host\`, "trailing backslash"},
		{"empty", "   ", "no command"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseArgv(tc.in)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseArgv(%q) = %v, want an error containing %q", tc.in, err, tc.want)
			}
		})
	}
}
