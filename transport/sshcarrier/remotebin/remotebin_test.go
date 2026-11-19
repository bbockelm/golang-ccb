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

	_, _, err := Find(dir, "linux", "arm64")
	if err == nil {
		t.Fatal("staging a platform with no build should fail")
	}
	if !strings.Contains(err.Error(), "linux/arm64") {
		t.Errorf("the error does not say which platform was wanted: %v", err)
	}
	if !strings.Contains(err.Error(), "htc-ccb-linux-amd64") {
		t.Errorf("the error does not say what was available: %v", err)
	}
}

func TestNoSourceAtAllSaysHowToGetOne(t *testing.T) {
	_, _, err := Find("", "linux", "amd64")
	if Any() {
		// A build made with the embed tag and populated builds would find it.
		if err != nil {
			t.Fatalf("this build carries binaries but Find failed: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("with no directory and nothing embedded, Find should fail")
	}
	if !strings.Contains(err.Error(), "embedremote") {
		t.Errorf("the error does not name the way to carry builds: %v", err)
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
		parts := strings.Split(strings.TrimPrefix(n, "htc-ccb-"), "-")
		if len(parts) == 2 {
			goos, goarch = parts[0], parts[1]
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

func TestNameMatchesTheReleaseSpelling(t *testing.T) {
	if got := Name("linux", "arm64"); got != "htc-ccb-linux-arm64" {
		t.Errorf("Name = %q, want htc-ccb-linux-arm64", got)
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
		plat := strings.TrimPrefix(n, "htc-ccb-")
		parts := strings.Split(plat, "-")
		if len(parts) != 2 {
			t.Fatalf("embedded build %q is not named htc-ccb-<os>-<arch>", n)
		}
		body, src, err := Find("", parts[0], parts[1])
		if err != nil {
			t.Fatalf("Find(%s/%s): %v", parts[0], parts[1], err)
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
