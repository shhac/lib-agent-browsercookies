package browsercookies

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var notionTarget = Target{CookieName: "token_v2", HostSuffixes: []string{"notion.so", "notion.com"}}

func TestReadChromiumCookiePlaintext(t *testing.T) {
	db := newChromiumCookiesDB(t, t.TempDir(), ".notion.so", "token_v2", "v02:plaintext", nil, 0)
	got, err := readChromiumCookie(testPlatform(t, "darwin", "/home"), chromiumSpec{}, notionTarget, db)
	if err != nil {
		t.Fatal(err)
	}
	if got != "v02:plaintext" {
		t.Errorf("got %q", got)
	}
}

func TestReadChromiumCookieCBCRoundTrip(t *testing.T) {
	const token = "v03%3Auser_token%3Aabc" // percent-encoding is part of the value
	enc := encryptCBC(t, []byte(token), "pw", 1003)
	db := newChromiumCookiesDB(t, t.TempDir(), ".www.notion.so", "token_v2", "", enc, 20)

	got, err := readChromiumCookie(testPlatform(t, "darwin", "/home", "pw"), chromiumSpec{}, notionTarget, db)
	if err != nil {
		t.Fatal(err)
	}
	if got != token {
		t.Errorf("got %q, want verbatim %q", got, token)
	}
}

func TestReadChromiumCookieStripsMetaV24Prefix(t *testing.T) {
	prefix := strings.Repeat("\xAB", 32) // 32-byte SHA-256(host) hash
	enc := encryptCBC(t, append([]byte(prefix), []byte("v03%3Atok")...), "pw", 1003)
	db := newChromiumCookiesDB(t, t.TempDir(), ".notion.so", "token_v2", "", enc, 24)

	got, err := readChromiumCookie(testPlatform(t, "darwin", "/home", "pw"), chromiumSpec{}, notionTarget, db)
	if err != nil {
		t.Fatal(err)
	}
	if got != "v03%3Atok" {
		t.Errorf("got %q", got)
	}
}

// TestReadChromiumCookieAppNotionCom pins the two-domain match: the Desktop
// app's token lives only on app.notion.com.
func TestReadChromiumCookieAppNotionCom(t *testing.T) {
	db := newChromiumCookiesDB(t, t.TempDir(), ".app.notion.com", "token_v2", "v03%3Adesktop", nil, 0)
	got, err := readChromiumCookie(testPlatform(t, "darwin", "/home"), chromiumSpec{}, notionTarget, db)
	if err != nil {
		t.Fatalf("app.notion.com not matched: %v", err)
	}
	if got != "v03%3Adesktop" {
		t.Errorf("got %q", got)
	}
}

func TestReadChromiumCookieDecodePolicy(t *testing.T) {
	db := newChromiumCookiesDB(t, t.TempDir(), ".slack.com", "d", "xoxd-a%2Fb", nil, 0)
	target := Target{CookieName: "d", HostSuffixes: []string{"slack.com"}, Decode: true}
	got, err := readChromiumCookie(testPlatform(t, "darwin", "/home"), chromiumSpec{}, target, db)
	if err != nil {
		t.Fatal(err)
	}
	if got != "xoxd-a/b" {
		t.Errorf("Decode=true should URL-decode: got %q", got)
	}
}

func TestReadChromiumCookieNotFound(t *testing.T) {
	db := newChromiumCookiesDB(t, t.TempDir(), ".example.com", "other", "x", nil, 0)
	_, err := readChromiumCookie(testPlatform(t, "darwin", "/home"), chromiumSpec{}, notionTarget, db)
	if err == nil || !strings.Contains(err.Error(), "no token_v2 cookie found") {
		t.Errorf("err = %v", err)
	}
}

func TestReadChromiumCookieMultiPasswordRetry(t *testing.T) {
	enc := encryptCBC(t, []byte("v03%3Atok"), "right", 1003)
	db := newChromiumCookiesDB(t, t.TempDir(), ".notion.so", "token_v2", "", enc, 20)
	// First password is wrong (PKCS#7 fails), second succeeds.
	got, err := readChromiumCookie(testPlatform(t, "darwin", "/home", "wrong", "right"), chromiumSpec{}, notionTarget, db)
	if err != nil {
		t.Fatal(err)
	}
	if got != "v03%3Atok" {
		t.Errorf("got %q", got)
	}
}

func TestChromiumUserDataDirPerOS(t *testing.T) {
	spec := chromiumSpec{darwin: "Google/Chrome", linux: ".config/google-chrome", windows: "Google/Chrome/User Data"}
	cases := map[string]string{
		"darwin":  filepath.Join("/home", "Library", "Application Support", "Google", "Chrome"),
		"linux":   filepath.Join("/home", ".config", "google-chrome"),
		"windows": filepath.Join("/home", "AppData", "Local", "Google", "Chrome", "User Data"),
	}
	for goos, want := range cases {
		got, err := spec.userDataDir(testPlatform(t, goos, "/home"))
		if err != nil {
			t.Errorf("%s: %v", goos, err)
			continue
		}
		if got != want {
			t.Errorf("%s: userDataDir = %q, want %q", goos, got, want)
		}
	}
}

func TestChromiumCookiesDBPrefersNetworkPath(t *testing.T) {
	// Build a spec pointing at a temp user-data dir with the Default profile.
	home := t.TempDir()
	profileDir := filepath.Join(home, "Library", "Application Support", "Chromium", "Default", "Network")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	newChromiumCookiesDB(t, profileDir, ".notion.so", "token_v2", "x", nil, 0)

	spec := chromiumSpec{darwin: "Chromium"}
	got, err := spec.cookiesDB(testPlatform(t, "darwin", home))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(filepath.Dir(got)) != "Network" {
		t.Errorf("cookiesDB = %q, want the Network/Cookies path", got)
	}
}

func TestReadCookieMetaVersion(t *testing.T) {
	// int64 row
	db := newChromiumCookiesDB(t, t.TempDir(), ".notion.so", "token_v2", "x", nil, 24)
	if v := readCookieMetaVersion(db); v != 24 {
		t.Errorf("int meta = %d, want 24", v)
	}
	// absent meta row
	db2 := newChromiumCookiesDB(t, t.TempDir(), ".notion.so", "token_v2", "x", nil, 0)
	if v := readCookieMetaVersion(db2); v != 0 {
		t.Errorf("absent meta = %d, want 0", v)
	}
}

func TestWindowsAppDataFallbacks(t *testing.T) {
	plat := Platform{Home: "/h", Getenv: func(string) string { return "" }}
	if got := windowsLocalAppData(plat); got != filepath.Join("/h", "AppData", "Local") {
		t.Errorf("LocalAppData fallback = %q", got)
	}
	if got := windowsAppData(plat); got != filepath.Join("/h", "AppData", "Roaming") {
		t.Errorf("AppData fallback = %q", got)
	}
	plat.Getenv = func(k string) string {
		return map[string]string{"LOCALAPPDATA": "L", "APPDATA": "R"}[k]
	}
	if got := windowsLocalAppData(plat); got != "L" {
		t.Errorf("LOCALAPPDATA = %q", got)
	}
	if got := windowsAppData(plat); got != "R" {
		t.Errorf("APPDATA = %q", got)
	}
}

