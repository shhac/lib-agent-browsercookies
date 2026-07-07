package browsercookies

import (
	"os/exec"
	"runtime"
	"strings"
)

// safeStoragePasswords is the production Platform.Keychain: candidate Chromium
// Safe Storage passwords for the given service names, in try order. macOS reads
// the login Keychain; Linux tries secret-tool plus Chromium's OSCrypt
// fallbacks. Windows uses a DPAPI-wrapped key instead, so this returns nil.
func safeStoragePasswords(services []string, prefix string) []string {
	switch runtime.GOOS {
	case "darwin":
		return dedupe(macSafeStoragePasswords(services))
	case "linux":
		return dedupe(linuxSafeStoragePasswords(services, prefix))
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

func linuxSafeStoragePasswords(services []string, prefix string) []string {
	var out []string
	for _, s := range services {
		if v, err := exec.Command("secret-tool", "lookup", "service", s).Output(); err == nil {
			if pw := strings.TrimRight(string(v), "\n"); pw != "" {
				out = append(out, pw)
			}
		}
	}
	// Chromium Linux OSCrypt fallbacks (os_crypt_linux.cc): empty for v11, then
	// the hardcoded default "peanuts".
	if prefix == "v11" {
		out = append(out, "")
	}
	return append(out, "peanuts")
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
