package ccbserver

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A knob that appears in the documentation and in no source file is a knob
// that does nothing. That is a worse failure than an undocumented one: an
// administrator sets it, sees no error, and concludes the feature does not
// work. It has happened here once already -- TRANSPORTS.md documented a
// CCB_CARRIER_COMMAND that was never implemented -- and it was caught by
// diffing the two lists by hand, which is what this does automatically.
//
// The reverse direction is deliberately not checked. An undocumented knob is
// a gap, but a legitimate one: several exist for development and are not
// meant to be in an administrator's reference.
func TestEveryDocumentedKnobIsReadBySomething(t *testing.T) {
	documented := scanNames(t, docFiles(t))
	read := scanQuotedNames(t, goFiles(t))

	var missing []string
	for name := range documented {
		if read[name] || notAKnob[name] || perClassSpelling(name, read) {
			continue
		}
		missing = append(missing, name+" ("+strings.Join(documented[name], ", ")+")")
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("documented but read by no source file -- either implement it, "+
			"remove it from the docs, or add it to notAKnob with the reason:\n  %s",
			strings.Join(missing, "\n  "))
	}
}

// notAKnob lists the CCB_-prefixed names in the docs that htc-ccb is not
// supposed to read, with why. Everything else must be read somewhere.
var notAKnob = map[string]bool{
	// HTCondor's own, which the docs tell an administrator to set on the
	// *pool's* daemons. htc-ccb writes it into their configuration; it never
	// reads it.
	"CCB_ADDRESS": true,
	// condor_master's per-daemon knobs, named <SUBSYS>_ARGS and so on. The
	// master reads them and htc-ccb receives the result as flags.
	"CCB_ARGS":  true,
	"CCB_DEBUG": true,
	"CCB_LOG":   true,
	// CEDAR command names, not configuration.
	"CCB_PROXY_CONNECT":   true,
	"CCB_REVERSE_CONNECT": true,
	// Prose, not a name: "the CCB_CARRIER_* knobs" and a design-document
	// filename both match the pattern.
	"CCB_CARRIER_":         true,
	"CCB_LIMIT_":           true, // CCB_LIMIT_<CLASS>_... in the rate-limit reference
	"CCB_TUNNELING_DESIGN": true,
}

// perClassSpelling reports whether name is a rate-limit knob spelled for a
// network class, CCB_LIMIT_<CLASS>_<KNOB>, whose default-class spelling
// CCB_LIMIT_<KNOB> is read. A misspelt knob still fails: its suffix is read
// nowhere.
func perClassSpelling(name string, read map[string]bool) bool {
	rest, ok := strings.CutPrefix(name, "CCB_LIMIT_")
	if !ok {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] == '_' && read["CCB_LIMIT_"+rest[i+1:]] {
			return true
		}
	}
	return false
}

var knobPattern = regexp.MustCompile(`\bCCB_[A-Z0-9_]+`)
var quotedKnobPattern = regexp.MustCompile(`"(CCB_[A-Z0-9_]+)"`)

// scanNames maps each name to the files that mention it, so a failure says
// where to go.
func scanNames(t *testing.T, files []string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, m := range knobPattern.FindAllString(string(body), -1) {
			if seen[m] {
				continue
			}
			seen[m] = true
			out[m] = append(out[m], f)
		}
	}
	return out
}

func scanQuotedNames(t *testing.T, files []string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range quotedKnobPattern.FindAllStringSubmatch(string(body), -1) {
			out[m[1]] = true
		}
	}
	return out
}

// docFiles is what an administrator reads: the manual, the packaged
// configuration and the README.
func docFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, pat := range []string{"docs/*.md", "packaging/*.conf", "README.md"} {
		m, err := filepath.Glob(pat)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, m...)
	}
	if len(out) == 0 {
		t.Fatal("no documentation found; this test would pass vacuously")
	}
	return out
}

func goFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "build") {
			return filepath.SkipDir
		}
		if strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
