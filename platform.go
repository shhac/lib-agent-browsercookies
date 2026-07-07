package browsercookies

import (
	"os"
	"path/filepath"
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
	// Keychain returns Safe Storage passwords held by the OS secret store for
	// the given service names, in try order — the login Keychain on macOS,
	// secret-tool on Linux. Windows wraps the key with DPAPI instead, so this is
	// unused there. Chromium's non-keychain OSCrypt fallbacks (the Linux
	// "peanuts" default) live in the Chromium layer, not here. Injected so tests
	// never touch the real secret store.
	Keychain func(services []string) []string
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

// windowsLocalAppData resolves %LOCALAPPDATA% (Chromium keeps its user data
// here), falling back to the conventional path under the home dir.
func windowsLocalAppData(plat Platform) string {
	if v := plat.getenv("LOCALAPPDATA"); v != "" {
		return v
	}
	return filepath.Join(plat.Home, "AppData", "Local")
}

// windowsAppData resolves %APPDATA% (Firefox keeps its profiles here), falling
// back to the conventional path under the home dir.
func windowsAppData(plat Platform) string {
	if v := plat.getenv("APPDATA"); v != "" {
		return v
	}
	return filepath.Join(plat.Home, "AppData", "Roaming")
}

// appSupportDir resolves an app's per-OS support directory from its per-OS
// subpaths. windowsBase selects the Windows root — LocalAppData for Chromium,
// AppData for Gecko — which is the only structural difference between the two
// browser families. ok is false on an unsupported OS, leaving the error
// message to the caller.
func appSupportDir(plat Platform, darwinSub, linuxSub, windowsSub string, windowsBase func(Platform) string) (dir string, ok bool) {
	switch plat.GOOS {
	case "darwin":
		return filepath.Join(plat.Home, "Library", "Application Support", darwinSub), true
	case "linux":
		return filepath.Join(plat.Home, linuxSub), true
	case "windows":
		return filepath.Join(windowsBase(plat), windowsSub), true
	default:
		return "", false
	}
}
