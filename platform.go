package browsercookies

import (
	"os"
	"runtime"
)

// Platform is the injectable environment every OS-specific decision routes
// through, so tests exercise every path-resolution and decryption branch
// regardless of the host OS. The zero value is unusable; use System() for
// production or build one explicitly in tests.
type Platform struct {
	// GOOS is the target OS: "darwin", "linux", or "windows".
	GOOS string
	// Home is the user's home directory.
	Home string
	// Getenv resolves an environment variable (APPDATA, LOCALAPPDATA on
	// Windows). Never nil in a usable Platform.
	Getenv func(string) string
	// Keychain returns candidate Chromium Safe Storage passwords for the given
	// service names, in try order. On macOS these come from the login Keychain,
	// on Linux from secret-tool plus Chromium's OSCrypt fallbacks; on Windows
	// the key is DPAPI-wrapped instead and this is unused. Injected so tests
	// never touch the real secret store.
	Keychain func(services []string, prefix string) []string
}

// System returns the production Platform for the host it runs on.
func System() Platform {
	home, _ := os.UserHomeDir()
	return Platform{
		GOOS:     runtime.GOOS,
		Home:     home,
		Getenv:   os.Getenv,
		Keychain: safeStoragePasswords,
	}
}

// getenv is a nil-safe accessor.
func (p Platform) getenv(k string) string {
	if p.Getenv == nil {
		return ""
	}
	return p.Getenv(k)
}
