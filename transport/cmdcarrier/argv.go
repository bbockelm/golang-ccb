// Package cmdcarrier obtains a CCB carrier byte pipe from a child process: the
// pipe is the child's stdin and stdout. The child is whatever the operator
// configured, which in practice is one of
//
//	ssh bastion htc-ccb -carrier-stdio    our binary at the far end
//	ssh -W outside-ccb:9700 bastion       a relay, nothing of ours installed
//
// and the same mechanism reaches a container (kubectl exec -i, podman exec -i)
// or a site's bespoke gateway wrapper. See docs/TRANSPORTS.md.
//
// The command is never run through a shell. ParseArgv splits the configured
// string into an argv with shell-like quoting and then rejects the characters a
// shell would have acted on, because treating them as literal arguments is a
// silent misreading of what the operator wrote.
package cmdcarrier

import (
	"fmt"
	"strings"
)

// shellMeta are the characters that would mean something to a shell. Unquoted,
// they are refused rather than passed through as literals: an operator who
// writes `ssh host htc-ccb | tee log` has written something we cannot honour,
// and silently exec'ing ssh with "|" and "tee" as arguments would be a far worse
// answer than an error naming the character.
const shellMeta = "|&;<>()$`\n*?!"

// ParseArgv splits a configured command line into an argv.
//
// Quoting follows the shell closely enough to be unsurprising: single quotes
// take everything literally, double quotes take everything literally except
// \" and \\, and outside quotes a backslash escapes the next character. What it
// deliberately does NOT do is anything else a shell would -- no variable
// expansion, no globbing, no word splitting of expanded values, no operators --
// so the argv is exactly the words written.
//
// A metacharacter that is quoted is kept, so a genuine argument containing one
// is still expressible: 'ProxyCommand=nc -X 5 -x proxy:1080 %h %p'.
func ParseArgv(s string) ([]string, error) {
	var (
		argv    []string
		cur     strings.Builder
		started bool // cur holds a word, even if it is the empty string ""
	)
	flush := func() {
		if started {
			argv = append(argv, cur.String())
			cur.Reset()
			started = false
		}
	}
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case c == ' ' || c == '\t':
			flush()
		case c == '\'':
			started = true
			j := i + 1
			for j < len(runes) && runes[j] != '\'' {
				cur.WriteRune(runes[j])
				j++
			}
			if j >= len(runes) {
				return nil, fmt.Errorf("unterminated single quote in %q", s)
			}
			i = j
		case c == '"':
			started = true
			j := i + 1
			for j < len(runes) && runes[j] != '"' {
				if runes[j] == '\\' && j+1 < len(runes) && (runes[j+1] == '"' || runes[j+1] == '\\') {
					j++
				}
				cur.WriteRune(runes[j])
				j++
			}
			if j >= len(runes) {
				return nil, fmt.Errorf("unterminated double quote in %q", s)
			}
			i = j
		case c == '\\':
			if i+1 >= len(runes) {
				return nil, fmt.Errorf("trailing backslash in %q", s)
			}
			started = true
			i++
			cur.WriteRune(runes[i])
		case strings.ContainsRune(shellMeta, c):
			return nil, fmt.Errorf("unquoted %q in %q: the command is executed directly, not through a shell, so shell syntax does not work here; quote the character if it is meant literally", string(c), s)
		default:
			started = true
			cur.WriteRune(c)
		}
	}
	flush()
	if len(argv) == 0 {
		return nil, fmt.Errorf("no command in %q", s)
	}
	return argv, nil
}
