package browsercookies

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newGeckoCookiesDB writes a Firefox-shaped cookies.sqlite (moz_cookies, one
// plaintext row) into profileDir, returning the DB path.
func newGeckoCookiesDB(t *testing.T, profileDir, host, name, value string) string {
	t.Helper()
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(profileDir, "cookies.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	exec := func(q string, args ...any) {
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	exec(`CREATE TABLE moz_cookies (name TEXT, value TEXT, host TEXT)`)
	exec(`INSERT INTO moz_cookies (name, value, host) VALUES (?, ?, ?)`, name, value, host)
	return path
}

// =============================================================================
// readGeckoCookie
// =============================================================================

func TestReadGeckoCookieVerbatim(t *testing.T) {
	// Firefox stores the value plaintext and verbatim; the percent-encoding is
	// part of Notion's token_v2 and must survive.
	db := newGeckoCookiesDB(t, t.TempDir(), ".notion.so", "token_v2", "v03%3Auser%3Aabc")
	got, err := readGeckoCookie(notionTarget, db)
	if err != nil {
		t.Fatal(err)
	}
	if got != "v03%3Auser%3Aabc" {
		t.Errorf("got %q, want verbatim", got)
	}
}

// The read layer returns the raw stored value; the Decode policy is applied at
// the Extract boundary, not here.
func TestReadGeckoCookieRawRegardlessOfDecode(t *testing.T) {
	db := newGeckoCookiesDB(t, t.TempDir(), ".slack.com", "d", "xoxd-a%2Fb")
	target := Target{CookieName: "d", HostSuffixes: []string{"slack.com"}, Decode: true}
	got, err := readGeckoCookie(target, db)
	if err != nil {
		t.Fatal(err)
	}
	if got != "xoxd-a%2Fb" {
		t.Errorf("read layer should return raw value, got %q", got)
	}
}

func TestReadGeckoCookieAppNotionCom(t *testing.T) {
	// Two-domain match: the token may live on app.notion.com.
	db := newGeckoCookiesDB(t, t.TempDir(), ".app.notion.com", "token_v2", "v03%3Adesktop")
	got, err := readGeckoCookie(notionTarget, db)
	if err != nil {
		t.Fatalf("app.notion.com not matched: %v", err)
	}
	if got != "v03%3Adesktop" {
		t.Errorf("got %q", got)
	}
}

func TestReadGeckoCookieHostFilteredInGo(t *testing.T) {
	// The name matches but the host does not — matchesHost rejects it in Go.
	db := newGeckoCookiesDB(t, t.TempDir(), ".example.com", "token_v2", "x")
	_, err := readGeckoCookie(notionTarget, db)
	if err == nil || !strings.Contains(err.Error(), "no token_v2 cookie found") {
		t.Errorf("err = %v", err)
	}
}

func TestReadGeckoCookieNameNotFound(t *testing.T) {
	db := newGeckoCookiesDB(t, t.TempDir(), ".notion.so", "other", "x")
	_, err := readGeckoCookie(notionTarget, db)
	if err == nil || !strings.Contains(err.Error(), "no token_v2 cookie found") {
		t.Errorf("err = %v", err)
	}
}

// =============================================================================
// parseGeckoProfilesIni
// =============================================================================

func TestParseGeckoProfilesIni(t *testing.T) {
	base := "/base"
	ini := `[Profile0]
Name=default
IsRelative=1
Path=Profiles/abcd0000.default-release
Default=1

; a comment
[Profile1]
Name=dev
IsRelative=1
Path=Profiles/efef1111.dev

[Install AAAA]
Default=Profiles/abcd0000.default-release
`
	profiles := parseGeckoProfilesIni(ini, base)
	if len(profiles) != 2 {
		t.Fatalf("profiles = %d: %#v", len(profiles), profiles)
	}
	if profiles[0].name != "default" ||
		profiles[0].path != filepath.Join(base, "Profiles", "abcd0000.default-release") ||
		!profiles[0].isDefault {
		t.Errorf("profile0 = %#v", profiles[0])
	}
	if profiles[1].name != "dev" || profiles[1].isDefault {
		t.Errorf("profile1 = %#v", profiles[1])
	}
}

func TestParseGeckoProfilesIniAbsolutePath(t *testing.T) {
	ini := "[Profile0]\nName=abs\nIsRelative=0\nPath=/abs/profile\n"
	profiles := parseGeckoProfilesIni(ini, "/base")
	if len(profiles) != 1 || profiles[0].path != "/abs/profile" {
		t.Errorf("profiles = %#v", profiles)
	}
}

func TestParseGeckoProfilesIniInstallDefault(t *testing.T) {
	// A profile with no Default=1 is still the default when [Install] names it.
	ini := "[Profile0]\nName=p\nIsRelative=1\nPath=Profiles/xxxx.p\n\n[Install ZZ]\nDefault=Profiles/xxxx.p\n"
	profiles := parseGeckoProfilesIni(ini, "/base")
	if len(profiles) != 1 || !profiles[0].isDefault {
		t.Errorf("install default not honored: %#v", profiles)
	}
}

// =============================================================================
// listGeckoProfilesIn
// =============================================================================

func TestListGeckoProfilesInFlatVsSubdir(t *testing.T) {
	// Flat (Linux): profiles directly under base.
	flat := t.TempDir()
	if err := os.MkdirAll(filepath.Join(flat, "abcd0000.default-release"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := listGeckoProfilesIn(flat, false)
	if len(got) != 1 || filepath.Base(got[0].path) != "abcd0000.default-release" {
		t.Errorf("flat = %#v", got)
	}

	// Subdir (macOS/Windows): profiles under Profiles/.
	sub := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sub, "Profiles", "efef1111.default"), 0o755); err != nil {
		t.Fatal(err)
	}
	got = listGeckoProfilesIn(sub, true)
	if len(got) != 1 || filepath.Base(got[0].path) != "efef1111.default" {
		t.Errorf("subdir = %#v", got)
	}
}

func TestListGeckoProfilesInZenTitleCased(t *testing.T) {
	// Zen uses title-cased profile dir names; the scan picks them up too.
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "Profiles", "abcd0000.Default (release)"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := listGeckoProfilesIn(base, true)
	if len(got) != 1 || filepath.Base(got[0].path) != "abcd0000.Default (release)" {
		t.Errorf("zen profile not picked up: %#v", got)
	}
}

func TestListGeckoProfilesInDefaultFirst(t *testing.T) {
	base := t.TempDir()
	for _, n := range []string{"aaaa.dev", "bbbb.default-release"} {
		if err := os.MkdirAll(filepath.Join(base, "Profiles", n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ini := "[Profile0]\nName=dev\nIsRelative=1\nPath=Profiles/aaaa.dev\n\n" +
		"[Profile1]\nName=default\nIsRelative=1\nPath=Profiles/bbbb.default-release\nDefault=1\n"
	if err := os.WriteFile(filepath.Join(base, "profiles.ini"), []byte(ini), 0o644); err != nil {
		t.Fatal(err)
	}
	got := listGeckoProfilesIn(base, true)
	if len(got) != 2 {
		t.Fatalf("got %d profiles: %#v", len(got), got)
	}
	if !got[0].isDefault || got[0].name != "default" {
		t.Errorf("default should sort first: %#v", got)
	}
}

// =============================================================================
// pickGeckoProfiles
// =============================================================================

func TestPickGeckoProfiles(t *testing.T) {
	profs := []geckoProfile{
		{name: "default", path: "/base/Profiles/abcd0000.default-release"},
		{name: "dev", path: "/base/Profiles/efef1111.dev"},
	}
	if len(pickGeckoProfiles(profs, "")) != 2 {
		t.Error("empty selector should return all")
	}
	if got := pickGeckoProfiles(profs, "default"); len(got) != 1 || got[0].name != "default" {
		t.Errorf("exact Name = %#v", got)
	}
	if got := pickGeckoProfiles(profs, "efef1111.dev"); len(got) != 1 || got[0].name != "dev" {
		t.Errorf("basename = %#v", got)
	}
	if got := pickGeckoProfiles(profs, "default-release"); len(got) != 1 || got[0].name != "default" {
		t.Errorf("path substring (a ‘.<name>’ suffix) = %#v", got)
	}
	if got := pickGeckoProfiles(profs, "nonexistent"); len(got) != 0 {
		t.Errorf("no match = %#v", got)
	}
}

// =============================================================================
// baseDir + end-to-end
// =============================================================================

func TestGeckoBaseDirPerOS(t *testing.T) {
	spec := geckoSpec{darwin: "Firefox", linux: ".mozilla/firefox", windows: "Mozilla/Firefox"}
	cases := map[string]string{
		"darwin":  filepath.Join("/home", "Library", "Application Support", "Firefox"),
		"linux":   filepath.Join("/home", ".mozilla", "firefox"),
		"windows": filepath.Join("/home", "AppData", "Roaming", "Mozilla", "Firefox"),
	}
	for goos, want := range cases {
		got, err := spec.baseDir(testPlatform(t, goos, "/home"))
		if err != nil {
			t.Errorf("%s: %v", goos, err)
			continue
		}
		if got != want {
			t.Errorf("%s: baseDir = %q, want %q", goos, got, want)
		}
	}
}

func TestExtractGeckoEndToEnd(t *testing.T) {
	home := t.TempDir()
	base := filepath.Join(home, "Library", "Application Support", "Firefox")
	profileDir := filepath.Join(base, "Profiles", "abcd0000.default-release")
	newGeckoCookiesDB(t, profileDir, ".notion.so", "token_v2", "v03%3Atok")
	ini := "[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/abcd0000.default-release\nDefault=1\n"
	if err := os.WriteFile(filepath.Join(base, "profiles.ini"), []byte(ini), 0o644); err != nil {
		t.Fatal(err)
	}

	value, prov, err := extractGecko(testPlatform(t, "darwin", home), geckoSpec{darwin: "Firefox"}, notionTarget, "")
	if err != nil {
		t.Fatal(err)
	}
	if value != "v03%3Atok" {
		t.Errorf("value = %q", value)
	}
	if prov["profile"] != profileDir {
		t.Errorf("provenance = %#v", prov)
	}
}

func TestExtractGeckoNoProfile(t *testing.T) {
	home := t.TempDir()
	_, _, err := extractGecko(testPlatform(t, "darwin", home), geckoSpec{darwin: "Firefox"}, notionTarget, "")
	if err == nil || !strings.Contains(err.Error(), "no matching Firefox-family profile") {
		t.Errorf("err = %v", err)
	}
}

// =============================================================================
// registry integration
// =============================================================================

func TestGeckoRegistered(t *testing.T) {
	for _, want := range []string{"firefox", "zen"} {
		found := false
		for _, n := range Names() {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q not registered; names = %v", want, Names())
		}
	}
	for _, info := range Sources() {
		if info.Name == "firefox" && !info.SupportsProfile {
			t.Error("firefox should report SupportsProfile")
		}
	}
}

func TestExtractFirefoxViaRegistry(t *testing.T) {
	// Full Extract path with no profiles.ini — the dir scan under Profiles/
	// finds the profile, and WithProfile selects it by substring.
	home := t.TempDir()
	profileDir := filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles", "abcd0000.default-release")
	newGeckoCookiesDB(t, profileDir, ".notion.so", "token_v2", "tok")

	res, err := Extract("firefox", notionTarget,
		WithPlatform(testPlatform(t, "darwin", home)),
		WithProfile("default-release"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "tok" || res.Browser != "firefox" || res.Source["profile"] != profileDir {
		t.Errorf("result = %#v", res)
	}
}
