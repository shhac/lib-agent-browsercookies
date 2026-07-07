package browsercookies

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLocalStateKey(t *testing.T) {
	localState := func(keyBlob []byte) []byte {
		enc := base64.StdEncoding.EncodeToString(keyBlob)
		return []byte(`{"os_crypt":{"encrypted_key":"` + enc + `"}}`)
	}

	// APPB (Chrome 127+ app-bound) → a clear, actionable error.
	_, err := parseLocalStateKey(localState(append([]byte("APPB"), 0x01)))
	if err == nil || !strings.Contains(err.Error(), "app-bound") {
		t.Errorf("APPB err = %v", err)
	}

	// DPAPI-prefixed → attempts DPAPI unwrap (fails off Windows, which is the
	// point — the prefix routing is what we assert).
	_, err = parseLocalStateKey(localState(append([]byte("DPAPI"), 0x02)))
	if err == nil {
		t.Error("DPAPI-prefixed key should attempt unwrap (errors off Windows)")
	}

	// Bad JSON.
	if _, err := parseLocalStateKey([]byte("{not json")); err == nil {
		t.Error("bad JSON should error")
	}
	// Missing key.
	if _, err := parseLocalStateKey([]byte(`{"os_crypt":{}}`)); err == nil ||
		!strings.Contains(err.Error(), "no os_crypt.encrypted_key") {
		t.Errorf("missing key err = %v", err)
	}
	// Bad base64.
	if _, err := parseLocalStateKey([]byte(`{"os_crypt":{"encrypted_key":"!!!!"}}`)); err == nil {
		t.Error("bad base64 should error")
	}
}

func TestFindLocalState(t *testing.T) {
	base := t.TempDir()
	// Layout: <base>/Local State and <base>/Default/Network/Cookies
	if err := os.WriteFile(filepath.Join(base, "Local State"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cookies := filepath.Join(base, "Default", "Network", "Cookies")
	if err := os.MkdirAll(filepath.Dir(cookies), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := findLocalState(cookies)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(base, "Local State") {
		t.Errorf("findLocalState = %q", got)
	}

	// Not found within the walk-up window.
	deep := filepath.Join(base, "a", "b", "c", "d", "Cookies")
	if _, err := findLocalState(deep); err == nil {
		t.Error("expected not-found for a too-deep path")
	}
}
