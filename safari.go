package browsercookies

import (
	"errors"
	"os"
	"path/filepath"
)

// safariFDAHint tells the user how to grant the access Safari's TCC-protected
// cookie store requires.
const safariFDAHint = "; grant your terminal Full Disk Access (System Settings → Privacy & Security → Full Disk Access), then retry"

// safariSource reads a cookie from Safari's Cookies.binarycookies store. macOS
// only: the store lives in a sandboxed container that needs Full Disk Access.
type safariSource struct{}

func init() { registry["safari"] = safariSource{} }

func (safariSource) supportsProfile() bool { return false }
func (safariSource) summary() string       { return "Safari cookie store (macOS; needs Full Disk Access)" }

func (safariSource) extract(plat Platform, t Target, _ string) (string, map[string]string, error) {
	value, path, err := extractSafari(plat, t)
	if err != nil {
		return "", nil, err
	}
	return value, map[string]string{"cookies_path": path}, nil
}

// safariCookiePaths lists candidate Cookies.binarycookies locations under the
// home directory — the modern sandboxed container first, then the legacy path.
func safariCookiePaths(plat Platform) []string {
	return []string{
		filepath.Join(plat.Home, "Library", "Containers", "com.apple.Safari", "Data", "Library", "Cookies", "Cookies.binarycookies"),
		filepath.Join(plat.Home, "Library", "Cookies", "Cookies.binarycookies"),
	}
}

// extractSafari resolves Safari's cookie store and returns the target cookie's
// raw value plus the store path it came from (the decode policy is applied at
// the Extract boundary). macOS only; a permission error means Full Disk Access
// is missing.
func extractSafari(plat Platform, t Target) (value, path string, err error) {
	if plat.GOOS != "darwin" {
		return "", "", errors.New("safari cookie extraction is only supported on macOS")
	}

	readAny := false
	for _, p := range safariCookiePaths(plat) {
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			if os.IsPermission(readErr) {
				return "", "", errors.New("could not read Safari's cookie store (permission denied)" + safariFDAHint)
			}
			continue // not present here — try the next location
		}
		readAny = true
		if v, ok := readSafariCookie(data, t); ok {
			return v, p, nil
		}
	}
	if !readAny {
		return "", "", errors.New("could not find Safari's cookie store" + safariFDAHint)
	}
	return "", "", errNoCookie(t)
}

// readSafariCookie parses a Cookies.binarycookies blob and returns the raw
// value of the first cookie matching the target's name and host (the decode
// policy is applied at the Extract boundary). Split out so tests drive it with
// a fixture blob instead of a real Safari install. Returns ok=false when the
// blob is unparseable or holds no matching cookie.
func readSafariCookie(data []byte, t Target) (string, bool) {
	cookies, err := parseBinaryCookies(data)
	if err != nil {
		return "", false
	}
	for _, c := range cookies {
		if c.Name == t.CookieName && t.matchesHost(c.Domain) && c.Value != "" {
			return c.Value, true
		}
	}
	return "", false
}
