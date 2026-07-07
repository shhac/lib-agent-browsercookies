package browsercookies

import (
	"os/exec"
	"runtime"
	"strings"
)

// safeStoragePasswords is the production Platform.Keychain: Safe Storage
// passwords held by the OS secret store for the given service names, in try
// order. macOS reads the login Keychain; Linux queries secret-tool. Windows
// uses a DPAPI-wrapped key instead, so this returns nil. Chromium's OSCrypt
// fallbacks (empty/"peanuts") are applied by the Chromium layer, not here.
func safeStoragePasswords(services []string) []string {
	switch runtime.GOOS {
	case "darwin":
		return dedupe(macSafeStoragePasswords(services))
	case "linux":
		return dedupe(linuxSecretToolPasswords(services))
	default:
		return nil
	}
}

func macSafeStoragePasswords(services []string) []string {
	var out []string
	for _, s := range services {
		if v, err := exec.Command("security", "find-generic-password", "-w", "-s", s).Output(); err == nil {
			if pw := strings.TrimRight(string(v), "\n"); pw != "" {
				out = append(out, pw)
			}
		}
	}
	return out
}

func linuxSecretToolPasswords(services []string) []string {
	var out []string
	for _, s := range services {
		if v, err := exec.Command("secret-tool", "lookup", "service", s).Output(); err == nil {
			if pw := strings.TrimRight(string(v), "\n"); pw != "" {
				out = append(out, pw)
			}
		}
	}
	return out
}

// chromiumIterations is the PBKDF2 iteration count: 1 on Linux, 1003 elsewhere.
func chromiumIterations(goos string) int {
	if goos == "linux" {
		return 1
	}
	return 1003
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
