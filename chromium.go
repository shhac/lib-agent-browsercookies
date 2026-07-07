package browsercookies

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
)

// chromiumSpec describes where a Chromium-family browser keeps its user-data
// directory, relative to each OS's app-support root, plus the macOS Safe
// Storage keychain services to try. The Cookies DB is resolved under
// <userData>/<profile>/Network/Cookies (newer) or <userData>/<profile>/Cookies.
type chromiumSpec struct {
	darwin   string
	linux    string
	windows  string
	profile  string   // "" → "Default"
	services []string // macOS Safe Storage keychain service names
}

// userDataDir resolves the browser's user-data directory on the platform.
func (s chromiumSpec) userDataDir(plat Platform) (string, error) {
	if dir, ok := appSupportDir(plat, s.darwin, s.linux, s.windows, windowsLocalAppData); ok {
		return dir, nil
	}
	return "", errors.New("unsupported OS for Chromium cookie extraction")
}

// cookiesDB resolves the first existing Cookies database path.
func (s chromiumSpec) cookiesDB(plat Platform) (string, error) {
	userData, err := s.userDataDir(plat)
	if err != nil {
		return "", err
	}
	profile := s.profile
	if profile == "" {
		profile = "Default"
	}
	for _, c := range []string{
		filepath.Join(userData, profile, "Network", "Cookies"),
		filepath.Join(userData, profile, "Cookies"),
	} {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", errors.New("could not find this browser's Cookies database (is it installed and signed in?)")
}

// extractChromium reads and decrypts the target cookie from a Chromium-family
// store.
func extractChromium(plat Platform, s chromiumSpec, t Target) (string, string, error) {
	cookiesPath, err := s.cookiesDB(plat)
	if err != nil {
		return "", "", err
	}
	value, err := readChromiumCookie(plat, s, t, cookiesPath)
	return value, cookiesPath, err
}

// readChromiumCookie snapshots the DB, selects the target cookie, and decrypts
// it. Split from extractChromium so tests can point at a fixture DB directly.
func readChromiumCookie(plat Platform, s chromiumSpec, t Target, cookiesPath string) (string, error) {
	copyPath, cleanup, err := copySqliteForRead(cookiesPath)
	if err != nil {
		return "", err
	}
	defer cleanup()

	metaVersion := readCookieMetaVersion(copyPath)

	rows, err := queryReadonlySqlite(copyPath,
		"select host_key, value, encrypted_value from cookies where name = ? order by length(encrypted_value) desc",
		t.CookieName)
	if err != nil {
		return "", err
	}
	// Host matching lives in one place (Target.matchesHost); rows come back
	// longest-value first, so the first host match is the preferred row.
	var row map[string]any
	for _, r := range rows {
		if t.matchesHost(rowString(r, "host_key")) {
			row = r
			break
		}
	}
	if row == nil {
		return "", errNoCookie(t)
	}

	// Rare: an unencrypted plaintext value.
	if v := rowString(row, "value"); v != "" {
		return v, nil
	}

	encrypted := rowBytes(row, "encrypted_value")
	if len(encrypted) == 0 {
		return "", errors.New("cookie had no value")
	}

	if plat.GOOS == "windows" {
		// Windows wraps the key with DPAPI; Local State is found relative to the
		// original (not the temp copy) path.
		plain, err := decryptCookieDPAPI(cookiesPath, encrypted, metaVersion)
		if err != nil {
			return "", err
		}
		return plain, nil
	}

	return decryptChromiumUnix(plat, s.services, encrypted, metaVersion)
}

// decryptChromiumUnix decrypts a macOS/Linux Chromium cookie with the AES-CBC
// Safe Storage scheme, trying each candidate password until one unpads cleanly.
func decryptChromiumUnix(plat Platform, services []string, encrypted []byte, metaVersion int) (string, error) {
	prefix := ""
	if len(encrypted) >= 3 {
		prefix = string(encrypted[:3])
	}
	data := encrypted
	if prefix == "v10" || prefix == "v11" {
		data = encrypted[3:]
	}

	passwords := plat.Keychain(services)
	if plat.GOOS == "linux" {
		// Chromium Linux OSCrypt fallbacks (os_crypt_linux.cc): the empty
		// passphrase for v11, then the hardcoded default "peanuts". These are
		// Chromium policy, not a secret-store lookup, so they live here.
		if prefix == "v11" {
			passwords = append(passwords, "")
		}
		passwords = append(passwords, "peanuts")
	}
	passwords = dedupe(passwords)
	if len(passwords) == 0 {
		return "", errors.New("could not read a Safe Storage password from the OS keychain")
	}
	for _, pw := range passwords {
		if plain, err := decryptChromiumCBC(data, pw, chromiumIterations(plat.GOOS)); err == nil {
			return stripHostHashPrefix(plain, metaVersion), nil
		}
	}
	return "", errors.New("could not decrypt the cookie with any Safe Storage password")
}

// readCookieMetaVersion returns the Cookies DB schema version (meta.version),
// or 0 when absent.
func readCookieMetaVersion(dbPath string) int {
	rows, err := queryReadonlySqlite(dbPath, "select value from meta where key = 'version'")
	if err != nil || len(rows) == 0 {
		return 0
	}
	switch v := rows[0]["value"].(type) {
	case int64:
		return int(v)
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}
