package remotebin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestADirectoryBuildIsFoundByPlatform(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "htc-ccb-splice-linux-amd64"), "amd64 build")
	write(t, filepath.Join(dir, "htc-ccb-splice-linux-arm64"), "arm64 build")

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
	if !strings.Contains(src.String(), "htc-ccb-splice-linux-arm64") {
		t.Errorf("the source %q does not name the file it came from", src)
	}
}

// The error is the whole interface when staging fails, so it has to say what
// there was -- a host whose build is missing is usually a host whose build
// was never made, and the fix is invisible from "no linux/arm64 build".
func TestAMissingPlatformErrorNamesWhatIsAvailable(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "htc-ccb-splice-linux-amd64"), "amd64 build")

	// A platform nothing can supply: not the host's, and not one that gets
	// embedded. linux/arm64 would not do -- an embedremote build carries it.
	_, _, err := Find(dir, "plan9", "mips64")
	if err == nil {
		t.Fatal("staging a platform with no build should fail")
	}
	if !strings.Contains(err.Error(), "plan9/mips64") {
		t.Errorf("the error does not say which platform was wanted: %v", err)
	}
	if !strings.Contains(err.Error(), "htc-ccb-splice-linux-amd64") {
		t.Errorf("the error does not say what was available: %v", err)
	}
}

func TestNoSourceAtAllSaysHowToGetOne(t *testing.T) {
	// A platform this build cannot possibly have, so an embedded copy cannot
	// answer it either.
	_, _, err := Find("", "plan9", "mips64")
	if err == nil {
		t.Fatal("with no directory and nothing embedded, Find should fail")
	}
	if !strings.Contains(err.Error(), "embedremote") {
		t.Errorf("the error does not name the way to carry builds: %v", err)
	}
	if !strings.Contains(err.Error(), "htc-ccb-splice") {
		t.Errorf("the error does not name the build to produce: %v", err)
	}
}

// A broker does NOT stage a copy of itself.
//
// It used to: asked for its own platform with nothing configured, it sent the
// binary it was running, which made staging "always work" and let the embedded
// set skip the host platform. That ended with the relay. The far end is a
// splice helper and this broker is not one, so its own binary is not a
// candidate for any platform, including its own.
func TestItNeverStagesItself(t *testing.T) {
	goos, goarch := Local()
	_, src, err := Find("", goos, goarch)
	if Any() {
		// An embedremote build may legitimately answer from a compiled-in
		// copy; what it must never do is reach for the running binary.
		if err == nil && !src.Embedded {
			t.Errorf("staged %v for the host's own platform; the only sources are a directory and an embedded copy", src)
		}
		return
	}
	if err == nil {
		t.Errorf("staged %v with no directory and nothing embedded; the running binary is not a splice helper", src)
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
	want := []string{"htc-ccb-splice-linux-arm64"}
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

// The full broker is NOT a stand-in for the helper.
//
// It used to be the fallback: htc-ccb ran the same -carrier-stdio role, so a
// site shipping only the full binary still got a staged broker. The splice
// helper is a different thing -- a byte relay with no CEDAR, no ClassAds and
// no credentials -- and htc-ccb is a broker. Staging it would silently give
// the far host an inside CCB, a different model with a different
// authorization boundary. Failing is the correct outcome.
func TestTheFullBinaryIsNotAHelper(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "htc-ccb-linux-amd64"), "the full broker")
	_, src, err := Find(dir, "linux", "amd64")
	if err == nil {
		t.Fatalf("staged %v; the full broker is not a splice helper", src)
	}
	if !strings.Contains(err.Error(), "htc-ccb-splice") {
		t.Errorf("the error does not say what build is wanted: %v", err)
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
			t.Fatalf("embedded build %q is not named htc-ccb-splice-<os>-<arch>", n)
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

func TestParsePlatformReadsTheReleaseSpelling(t *testing.T) {
	for _, tc := range []struct{ name, goos, goarch string }{
		{"htc-ccb-splice-linux-amd64", "linux", "amd64"},
		{"htc-ccb-splice-linux-arm64", "linux", "arm64"},
		{"htc-ccb-splice-linux-arm64.gz", "linux", "arm64"},
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
