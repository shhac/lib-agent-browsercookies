package browsercookies

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSafariStore writes a Cookies.binarycookies fixture at the modern
// sandboxed-container path under home and returns that path.
func writeSafariStore(t *testing.T, home string, cookies ...binaryCookie) string {
	t.Helper()
	dir := filepath.Join(home, "Library", "Containers", "com.apple.Safari", "Data", "Library", "Cookies")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "Cookies.binarycookies")
	if err := os.WriteFile(path, makeBinaryCookies(makeBinaryCookiePage(cookies...)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadSafariCookieFiltersByHostAndName(t *testing.T) {
	data := makeBinaryCookies(makeBinaryCookiePage(
		binaryCookie{Domain: "other.test", Name: "token_v2", Value: "wrong-host"},
		binaryCookie{Domain: "notion.so", Name: "d", Value: "wrong-name"},
		binaryCookie{Domain: "notion.so", Name: "token_v2", Value: "v03%3Aright"},
	))

	got, ok := readSafariCookie(data, notionTarget)
	if !ok {
		t.Fatal("expected a match")
	}
	// Decode defaults to false: the value is returned verbatim (percent-encoded).
	if got != "v03%3Aright" {
		t.Errorf("value = %q, want verbatim v03%%3Aright", got)
	}
}

// The read layer returns the raw stored value; the Decode policy is applied at
// the Extract boundary, not here.
func TestReadSafariCookieRawRegardlessOfDecode(t *testing.T) {
	data := makeBinaryCookies(makeBinaryCookiePage(
		binaryCookie{Domain: ".notion.so", Name: "token_v2", Value: "v03%3Auser%2Fabc"},
	))
	tgt := notionTarget
	tgt.Decode = true
	got, ok := readSafariCookie(data, tgt)
	if !ok || got != "v03%3Auser%2Fabc" {
		t.Errorf("read layer should return raw value = %q, ok = %v", got, ok)
	}
}

func TestReadSafariCookieNotFound(t *testing.T) {
	data := makeBinaryCookies(makeBinaryCookiePage(
		binaryCookie{Domain: "other.test", Name: "token_v2", Value: "x"},
	))
	if _, ok := readSafariCookie(data, notionTarget); ok {
		t.Error("expected no match for a non-target host")
	}
	// An empty value never matches.
	empty := makeBinaryCookies(makeBinaryCookiePage(
		binaryCookie{Domain: "notion.so", Name: "token_v2", Value: ""},
	))
	if _, ok := readSafariCookie(empty, notionTarget); ok {
		t.Error("expected no match for an empty value")
	}
	// Garbage bytes parse-fail cleanly to (,, false).
	if _, ok := readSafariCookie([]byte("not a cookie file"), notionTarget); ok {
		t.Error("expected no match for unparseable data")
	}
}

func TestExtractSafariHappyPath(t *testing.T) {
	home := t.TempDir()
	path := writeSafariStore(t, home,
		binaryCookie{Domain: "notion.so", Name: "token_v2", Value: "v03%3Asynthetic"},
	)
	plat := testPlatform(t, "darwin", home)

	value, gotPath, err := extractSafari(plat, notionTarget)
	if err != nil {
		t.Fatal(err)
	}
	if value != "v03%3Asynthetic" {
		t.Errorf("value = %q", value)
	}
	if gotPath != path {
		t.Errorf("path = %q, want %q", gotPath, path)
	}
}

func TestExtractSafariNotFound(t *testing.T) {
	home := t.TempDir()
	writeSafariStore(t, home, binaryCookie{Domain: "other.test", Name: "token_v2", Value: "x"})

	_, _, err := extractSafari(testPlatform(t, "darwin", home), notionTarget)
	if err == nil || !strings.Contains(err.Error(), "token_v2") {
		t.Errorf("err = %v, want a no-cookie error naming token_v2", err)
	}
}

func TestExtractSafariMissingStore(t *testing.T) {
	_, _, err := extractSafari(testPlatform(t, "darwin", t.TempDir()), notionTarget)
	if err == nil || !strings.Contains(err.Error(), "Full Disk Access") {
		t.Errorf("err = %v, want a missing-store error with the FDA hint", err)
	}
}

func TestExtractSafariNonDarwin(t *testing.T) {
	for _, goos := range []string{"linux", "windows"} {
		_, _, err := extractSafari(testPlatform(t, goos, t.TempDir()), notionTarget)
		if err == nil || !strings.Contains(err.Error(), "only supported on macOS") {
			t.Errorf("%s: err = %v, want macOS-only error", goos, err)
		}
	}
}

func TestExtractSafariPermissionDenied(t *testing.T) {
	home := t.TempDir()
	path := writeSafariStore(t, home, binaryCookie{Domain: "notion.so", Name: "token_v2", Value: "x"})
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	// Root ignores file permissions; skip rather than assert the wrong branch.
	if data, err := os.ReadFile(path); err == nil {
		_ = data
		t.Skip("cannot simulate permission denial (running as root?)")
	}

	_, _, err := extractSafari(testPlatform(t, "darwin", home), notionTarget)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("err = %v, want permission-denied error", err)
	}
}

func TestSafariSourceMetadataAndRegistry(t *testing.T) {
	s, ok := registry["safari"]
	if !ok {
		t.Fatal("safari not registered")
	}
	if s.supportsProfile {
		t.Error("Safari does not support profiles")
	}
	if !strings.Contains(s.summary, "Safari") {
		t.Errorf("summary = %q", s.summary)
	}
}

func TestExtractViaPublicAPI(t *testing.T) {
	home := t.TempDir()
	path := writeSafariStore(t, home,
		binaryCookie{Domain: "notion.so", Name: "token_v2", Value: "v03%3Aapi"},
	)

	res, err := Extract("safari", notionTarget, WithPlatform(testPlatform(t, "darwin", home)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "v03%3Aapi" || res.Browser != "safari" {
		t.Errorf("result = %+v", res)
	}
	if res.Source["cookies_path"] != path {
		t.Errorf("provenance = %v, want cookies_path %q", res.Source, path)
	}
}
