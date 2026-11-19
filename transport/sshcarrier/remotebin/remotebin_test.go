package remotebin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestADirectoryBuildIsFoundByPlatform(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "htc-ccb-linux-amd64"), "amd64 build")
	write(t, filepath.Join(dir, "htc-ccb-linux-arm64"), "arm64 build")

	body, src, err := Find(dir, "linux", "arm64")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if string(body) != "arm64 build" {
		t.Errorf("got the %q build, want the arm64 one", body)
	}
	if src.Embedded {
		t.Error("the build came from a directory; the source should not say embedded")
	}
	if !strings.Contains(src.String(), "htc-ccb-linux-arm64") {
		t.Errorf("the source %q does not name the file it came from", src)
	}
}

// The error is the whole interface when staging fails, so it has to say what
// there was -- a host whose build is missing is usually a host whose build
// was never made, and the fix is invisible from "no linux/arm64 build".
func TestAMissingPlatformErrorNamesWhatIsAvailable(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "htc-ccb-linux-amd64"), "amd64 build")

	// A platform nothing can supply: not the host's, and not one that gets
	// embedded. linux/arm64 would not do -- an embedremote build carries it.
	_, _, err := Find(dir, "plan9", "mips64")
	if err == nil {
		t.Fatal("staging a platform with no build should fail")
	}
	if !strings.Contains(err.Error(), "plan9/mips64") {
		t.Errorf("the error does not say which platform was wanted: %v", err)
	}
	if !strings.Contains(err.Error(), "htc-ccb-linux-amd64") {
		t.Errorf("the error does not say what was available: %v", err)
	}
}

func TestNoSourceAtAllSaysHowToGetOne(t *testing.T) {
	// A platform this build cannot possibly have: not the host's, and not
	// one anybody embeds. Asking for a real one would succeed by
	// self-staging or from an embedded copy, which is not what this checks.
	_, _, err := Find("", "plan9", "mips64")
	if err == nil {
		t.Fatal("with no directory and nothing embedded, Find should fail")
	}
	if !strings.Contains(err.Error(), "embedremote") {
		t.Errorf("the error does not name the way to carry builds: %v", err)
	}
	// The inventory must mention that this binary can always stage itself for
	// its own platform, so an operator is not told to build something they
	// already have.
	if !strings.Contains(err.Error(), "own platform") {
		t.Errorf("the error does not say this binary can stage its own platform: %v", err)
	}
}

// A broker never needs to carry a copy of itself: asked for its own
// platform with nothing configured, it stages the binary it is running.
// This is what keeps the embed tag to the OTHER architectures.
func TestItStagesItselfForItsOwnPlatform(t *testing.T) {
	goos, goarch := Local()
	body, src, err := Find("", goos, goarch)
	if err != nil {
		t.Fatalf("Find(own platform): %v", err)
	}
	if len(body) == 0 {
		t.Fatal("staged an empty binary")
	}
	if !src.Self && !src.Embedded {
		t.Errorf("source is %v; with nothing configured it should be this running binary", src)
	}
	if src.Self {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(exe)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(body)) != fi.Size() {
			t.Errorf("staged %d bytes; the running binary is %d", len(body), fi.Size())
		}
	}
}

// ...but only for its own platform. A different architecture cannot come
// from the running binary, and saying it could would stage something that
// cannot exec.
func TestItDoesNotStageItselfForAnotherPlatform(t *testing.T) {
	goos, goarch := Local()
	otherArch := "arm64"
	if goarch == "arm64" {
		otherArch = "amd64"
	}
	_, src, err := Find("", goos, otherArch)
	if err == nil && src.Self {
		t.Errorf("staged this %s/%s binary onto a %s/%s host", goos, goarch, goos, otherArch)
	}
}

// A directory entry wins over a compiled-in copy, so a site that ships its own
// builds keeps control of what lands on its hosts even in an embedded build.
func TestTheDirectoryWinsOverAnEmbeddedCopy(t *testing.T) {
	if !Any() {
		t.Skip("this build carries no embedded binaries; nothing to outrank")
	}
	names := embeddedNames()
	// Take the first embedded platform and shadow it.
	var goos, goarch string
	for _, n := range names {
		n = strings.TrimSuffix(n, " (embedded)")
		if o, a, ok := ParsePlatform(n); ok {
			goos, goarch = o, a
			break
		}
	}
	if goos == "" {
		t.Skip("no embedded build has a parsable platform name")
	}
	dir := t.TempDir()
	write(t, filepath.Join(dir, Name(goos, goarch)), "the site's own build")
	body, src, err := Find(dir, goos, goarch)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if string(body) != "the site's own build" {
		t.Error("the compiled-in copy outranked the configured directory")
	}
	if src.Embedded {
		t.Error("the source says embedded for a build read from the directory")
	}
}

func TestNamesMatchTheReleaseSpelling(t *testing.T) {
	got := Names("linux", "arm64")
	want := []string{"htc-ccb-relay-linux-arm64", "htc-ccb-linux-arm64"}
	if len(got) != len(want) {
		t.Fatalf("Names = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Names[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if Name("linux", "arm64") != want[0] {
		t.Errorf("Name = %q, want the preferred spelling %q", Name("linux", "arm64"), want[0])
	}
}

// The relay is preferred, but a site that ships only the full binary must
// still get a staged broker -- it runs the same role.
func TestTheFullBinaryIsUsedWhenNoRelayIsShipped(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "htc-ccb-linux-amd64"), "the full binary")
	body, src, err := Find(dir, "linux", "amd64")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if string(body) != "the full binary" {
		t.Errorf("got %q", body)
	}
	if !strings.Contains(src.String(), "htc-ccb-linux-amd64") {
		t.Errorf("source %q does not name the file used", src)
	}
}

// With both present the relay wins: it is the one meant to cross the network.
func TestTheRelayOutranksTheFullBinary(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "htc-ccb-linux-amd64"), "the full binary")
	write(t, filepath.Join(dir, "htc-ccb-relay-linux-amd64"), "the relay")
	body, _, err := Find(dir, "linux", "amd64")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if string(body) != "the relay" {
		t.Errorf("staged %q; the relay should be preferred", body)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// An embedded build must come back decompressed and whole. Without a build in
// builds/ there is nothing to check, so this skips -- CI seeds a small one
// (see the embedremote job) precisely so this does not always skip.
func TestAnEmbeddedBuildComesBackDecompressed(t *testing.T) {
	if !Any() {
		t.Skip("this build carries no embedded binaries")
	}
	for _, n := range embeddedNames() {
		n = strings.TrimSuffix(n, " (embedded)")
		goos, goarch, ok := ParsePlatform(n)
		if !ok {
			t.Fatalf("embedded build %q is not named htc-ccb[-relay]-<os>-<arch>", n)
		}
		body, src, err := Find("", goos, goarch)
		if err != nil {
			t.Fatalf("Find(%s/%s): %v", goos, goarch, err)
		}
		if !src.Embedded {
			t.Errorf("%s came from %s, not the embedded copy", n, src)
		}
		if len(body) == 0 {
			t.Errorf("%s decompressed to nothing", n)
		}
		if src.Size != len(body) {
			t.Errorf("%s reports %d bytes but is %d", n, src.Size, len(body))
		}
	}
}

func TestParsePlatformReadsBothSpellings(t *testing.T) {
	for _, tc := range []struct{ name, goos, goarch string }{
		{"htc-ccb-linux-amd64", "linux", "amd64"},
		{"htc-ccb-relay-linux-arm64", "linux", "arm64"},
		{"htc-ccb-relay-linux-arm64.gz", "linux", "arm64"},
	} {
		goos, goarch, ok := ParsePlatform(tc.name)
		if !ok || goos != tc.goos || goarch != tc.goarch {
			t.Errorf("ParsePlatform(%q) = %q/%q ok=%v, want %s/%s", tc.name, goos, goarch, ok, tc.goos, tc.goarch)
		}
	}
	for _, bad := range []string{"README.md", "htc-ccb", "htc-ccb-linux", "somethingelse-linux-amd64"} {
		if _, _, ok := ParsePlatform(bad); ok {
			t.Errorf("ParsePlatform(%q) accepted a name that is not a build", bad)
		}
	}
}
