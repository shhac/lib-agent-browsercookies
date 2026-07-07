package browsercookies

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractFromRegisteredChromium(t *testing.T) {
	// Fixture: a chrome install under a fake macOS home.
	home := t.TempDir()
	profileDir := filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "Default")
	if err := mkdir(profileDir); err != nil {
		t.Fatal(err)
	}
	newChromiumCookiesDB(t, profileDir, ".notion.so", "token_v2", "v03%3Atok", nil, 0)

	plat := testPlatform(t, "darwin", home)
	res, err := Extract("chrome", notionTarget, WithPlatform(plat))
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "v03%3Atok" || res.Browser != "chrome" {
		t.Errorf("result = %+v", res)
	}
	if res.Source["cookies_path"] == "" {
		t.Error("missing provenance")
	}
}

func TestExtractUnknownBrowser(t *testing.T) {
	_, err := Extract("netscape", notionTarget, WithPlatform(testPlatform(t, "darwin", "/home")))
	if err == nil || !strings.Contains(err.Error(), "unknown browser") {
		t.Errorf("err = %v", err)
	}
}

func TestNamesAndSourcesRegistered(t *testing.T) {
	names := Names()
	for _, want := range []string{"chrome", "brave", "edge", "arc", "chromium"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s not registered; have %v", want, names)
		}
	}
	if len(Sources()) != len(names) {
		t.Errorf("Sources()=%d, Names()=%d", len(Sources()), len(names))
	}
}
