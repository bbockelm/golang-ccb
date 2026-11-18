package ccbserver

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/bbockelm/golang-ccb/transport/cmdcarrier"
)

// Every cmd: carrier example in the documentation and the sample configuration
// must survive the parser the broker actually uses. The parser deliberately
// refuses unquoted shell metacharacters, so an example written the way one
// would type it into a shell -- with a pipe, a $VARIABLE, a glob -- would be
// refused at startup by an administrator who copied it, and nothing else would
// catch that.
func TestDocumentedCarrierCommandsParse(t *testing.T) {
	// Only configuration values: `CCB_OUTBOUND_NEXT_HOP = cmd:...` and
	// `CCB_CARRIER_LISTEN = cmd:...`. That is exactly what an administrator
	// copies, and it excludes by construction the two things in these documents
	// that name a cmd: string without being one -- the counter-example in
	// TRANSPORTS.md section 5.1, which exists precisely because it is refused,
	// and the -carrier-check sample output, where the route description follows
	// the command on the same line.
	cmdLine := regexp.MustCompile("(?:CCB_OUTBOUND_NEXT_HOP|CCB_CARRIER_LISTEN)\\s*=\\s*cmd:([^`\"\\n]+)")

	files := []string{
		"README.md",
		filepath.Join("docs", "TRANSPORTS.md"),
		filepath.Join("docs", "ADMIN_TUNNELING.md"),
		filepath.Join("docs", "CARRIER_AUTH.md"),
		filepath.Join("packaging", "htc-ccb.conf"),
	}

	found := 0
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		for _, line := range strings.Split(string(body), "\n") {
			for _, m := range cmdLine.FindAllStringSubmatch(line, -1) {
				example := strings.TrimSpace(m[1])
				// The reference tables name the form rather than a command.
				if example == "" || strings.HasPrefix(example, "…") || strings.HasPrefix(example, "<") {
					continue
				}
				found++
				argv, err := cmdcarrier.ParseArgv(example)
				if err != nil {
					t.Errorf("%s: the documented command %q does not parse: %v", f, example, err)
					continue
				}
				if argv[0] != "ssh" && argv[0] != "kubectl" && !filepath.IsAbs(argv[0]) {
					t.Errorf("%s: documented command %q starts with %q, which is neither a known tool nor an absolute path", f, example, argv[0])
				}
			}
		}
	}
	if found < 5 {
		t.Fatalf("only %d cmd: examples found across the documentation; the regexp has probably stopped matching", found)
	}
	t.Logf("%d documented cmd: carrier commands parse", found)
}
