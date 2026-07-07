package browsercookies

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// --- sqlite cell coercion defaults ---

func TestRowStringAndBytesCoercion(t *testing.T) {
	row := map[string]any{"s": "hi", "b": []byte("bye"), "i": int64(5), "nil": nil}

	if got := rowString(row, "s"); got != "hi" {
		t.Errorf("rowString(string) = %q", got)
	}
	if got := rowString(row, "b"); got != "bye" {
		t.Errorf("rowString([]byte) = %q", got)
	}
	if got := rowString(row, "i"); got != "" {
		t.Errorf("rowString(int64) = %q, want empty", got)
	}
	if got := rowString(row, "missing"); got != "" {
		t.Errorf("rowString(missing) = %q, want empty", got)
	}

	if got := rowBytes(row, "b"); string(got) != "bye" {
		t.Errorf("rowBytes([]byte) = %q", got)
	}
	if got := rowBytes(row, "s"); string(got) != "hi" {
		t.Errorf("rowBytes(string) = %q", got)
	}
	if got := rowBytes(row, "i"); got != nil {
		t.Errorf("rowBytes(int64) = %v, want nil", got)
	}
	if got := rowBytes(row, "nil"); got != nil {
		t.Errorf("rowBytes(nil) = %v, want nil", got)
	}
}

// --- unsupported-OS branches ---

// TestUnsupportedOSErrors covers the appSupportDir false path via both spec
// resolvers on an OS neither family supports.
func TestUnsupportedOSErrors(t *testing.T) {
	plat := testPlatform(t, "plan9", "/home")
	if _, err := (chromiumSpec{}).userDataDir(plat); err == nil {
		t.Error("chromium userDataDir should error on an unsupported OS")
	}
	if _, err := (geckoSpec{}).baseDir(plat); err == nil {
		t.Error("gecko baseDir should error on an unsupported OS")
	}
	if _, ok := appSupportDir(plat, "d", "l", "w", windowsAppData); ok {
		t.Error("appSupportDir should report ok=false on an unsupported OS")
	}
}

// --- Chromium Linux OSCrypt fallbacks (decryptChromiumUnix) ---

// TestDecryptChromiumUnixLinuxPeanutsFallback pins the Chromium Linux "peanuts"
// default: with no secret-store password, the value still decrypts.
func TestDecryptChromiumUnixLinuxPeanutsFallback(t *testing.T) {
	enc := encryptCBC(t, []byte("v03%3Atok"), "peanuts", 1) // Linux uses 1 iteration
	plat := testPlatform(t, "linux", "/home")               // empty keychain
	got, err := decryptChromiumUnix(plat, []string{"X Safe Storage"}, enc, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != "v03%3Atok" {
		t.Errorf("got %q, want the peanuts-decrypted value", got)
	}
}

// TestDecryptChromiumUnixLinuxV11EmptyPassword pins the v11 empty-passphrase
// fallback that precedes "peanuts".
func TestDecryptChromiumUnixLinuxV11EmptyPassword(t *testing.T) {
	enc := encryptCBC(t, []byte("v03%3Atok"), "", 1)
	copy(enc[:3], "v11") // mark as v11 so the empty-passphrase fallback applies
	plat := testPlatform(t, "linux", "/home")
	got, err := decryptChromiumUnix(plat, []string{"X Safe Storage"}, enc, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != "v03%3Atok" {
		t.Errorf("got %q, want the empty-passphrase-decrypted value", got)
	}
}

// --- Windows DPAPI orchestration (routing/error paths off Windows) ---

// TestDecryptCookieDPAPIv10Routing drives the v10 branch through Local State
// resolution and key parsing. The DPAPI unwrap only succeeds on Windows, so off
// Windows this errors — but the routing, Local State read, and key decode are
// exercised.
func TestDecryptCookieDPAPIv10Routing(t *testing.T) {
	dir := t.TempDir()
	blob := append([]byte("DPAPI"), 0x01, 0x02) // DPAPI-wrapped key marker
	localState := `{"os_crypt":{"encrypted_key":"` + base64.StdEncoding.EncodeToString(blob) + `"}}`
	if err := os.WriteFile(filepath.Join(dir, "Local State"), []byte(localState), 0o600); err != nil {
		t.Fatal(err)
	}
	cookies := filepath.Join(dir, "Cookies")

	enc := append([]byte("v10"), make([]byte, 40)...)
	if _, err := decryptCookieDPAPI(cookies, enc, 0); err == nil {
		t.Error("expected DPAPI unwrap to fail off Windows")
	}
}

// TestDecryptCookieDPAPIRawBlob covers the non-v10 (raw DPAPI blob) branch.
func TestDecryptCookieDPAPIRawBlob(t *testing.T) {
	if _, err := decryptCookieDPAPI(filepath.Join(t.TempDir(), "Cookies"), []byte{1, 2, 3}, 0); err == nil {
		t.Error("expected the raw-DPAPI path to fail off Windows")
	}
}

// TestWindowsCookieKeyMissingLocalState covers the findLocalState error path.
func TestWindowsCookieKeyMissingLocalState(t *testing.T) {
	if _, err := windowsCookieKey(filepath.Join(t.TempDir(), "Cookies")); err == nil {
		t.Error("expected an error when Local State is absent")
	}
}
