package browsercookies

import (
	"path/filepath"
	"testing"
)

func TestExtractChromiumStoreFirstExistingPath(t *testing.T) {
	dir := t.TempDir()
	// The real store is the second candidate; the first does not exist.
	newChromiumCookiesDB(t, dir, ".notion.so", "token_v2", "v03%3Adesktop", nil, 0)
	store := ChromiumStore{
		Paths:    []string{filepath.Join(dir, "missing", "Cookies"), filepath.Join(dir, "Cookies")},
		Services: []string{"Notion Safe Storage"},
	}

	res, err := ExtractChromiumStore(store, notionTarget, WithPlatform(testPlatform(t, "darwin", dir)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "v03%3Adesktop" {
		t.Errorf("value = %q", res.Value)
	}
	if res.Source["cookies_path"] != filepath.Join(dir, "Cookies") {
		t.Errorf("provenance = %q", res.Source["cookies_path"])
	}
}

func TestExtractChromiumStoreDecodesAtBoundary(t *testing.T) {
	dir := t.TempDir()
	newChromiumCookiesDB(t, dir, ".slack.com", "d", "xoxd-a%2Fb", nil, 0)
	target := Target{CookieName: "d", HostSuffixes: []string{"slack.com"}, Decode: true}
	store := ChromiumStore{Paths: []string{filepath.Join(dir, "Cookies")}, Services: []string{"Slack Safe Storage"}}

	res, err := ExtractChromiumStore(store, target, WithPlatform(testPlatform(t, "darwin", dir)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "xoxd-a/b" {
		t.Errorf("Decode should apply at the boundary: got %q", res.Value)
	}
}

func TestExtractChromiumStoreNoPath(t *testing.T) {
	store := ChromiumStore{Paths: []string{filepath.Join(t.TempDir(), "nope", "Cookies")}}
	if _, err := ExtractChromiumStore(store, notionTarget, WithPlatform(testPlatform(t, "darwin", "/home"))); err == nil {
		t.Error("expected an error when no candidate path exists")
	}
}

func TestExtractChromiumStoreDecryptsCBC(t *testing.T) {
	dir := t.TempDir()
	enc := encryptCBC(t, []byte("v03%3Adesktoptok"), "pw", 1003)
	newChromiumCookiesDB(t, dir, ".notion.so", "token_v2", "", enc, 20)
	store := ChromiumStore{Paths: []string{filepath.Join(dir, "Cookies")}, Services: []string{"Notion Safe Storage"}}

	res, err := ExtractChromiumStore(store, notionTarget, WithPlatform(testPlatform(t, "darwin", dir, "pw")))
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "v03%3Adesktoptok" {
		t.Errorf("value = %q", res.Value)
	}
}
