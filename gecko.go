package browsercookies

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// geckoSpec describes where a Firefox-family app keeps its profile directories,
// relative to each OS's app root. On macOS and Windows the profiles nest under
// a "Profiles" subdirectory; on Linux they sit directly under the app dir. That
// nesting is applied by discovery, not encoded in these names.
type geckoSpec struct {
	darwin  string // under ~/Library/Application Support/
	linux   string // under the home dir
	windows string // under %APPDATA%
}

// baseDir resolves the app's profile root on the platform.
func (s geckoSpec) baseDir(plat Platform) (string, error) {
	if dir, ok := appSupportDir(plat, s.darwin, s.linux, s.windows, windowsAppData); ok {
		return dir, nil
	}
	return "", errors.New("unsupported OS for Firefox-family cookie extraction")
}

// geckoProfile is one discovered Firefox-family profile.
type geckoProfile struct {
	name      string
	path      string
	isDefault bool
}

// extractGecko resolves the app's profiles, applies the optional selector, and
// returns the target cookie from the first profile that has it.
func extractGecko(plat Platform, s geckoSpec, t Target, profile string) (string, map[string]string, error) {
	base, err := s.baseDir(plat)
	if err != nil {
		return "", nil, err
	}
	// macOS and Windows nest profiles under a "Profiles" subdirectory; Linux
	// keeps them directly under the app dir.
	profilesSubdir := plat.GOOS == "darwin" || plat.GOOS == "windows"
	candidates := pickGeckoProfiles(listGeckoProfilesIn(base, profilesSubdir), profile)
	if len(candidates) == 0 {
		return "", nil, errors.New("no matching Firefox-family profile found (is it installed and signed in?)")
	}

	for _, c := range candidates {
		cookiesPath := filepath.Join(c.path, "cookies.sqlite")
		if _, err := os.Stat(cookiesPath); err != nil {
			continue
		}
		if value, err := readGeckoCookie(t, cookiesPath); err == nil {
			return value, map[string]string{"profile": c.path}, nil
		}
	}
	return "", nil, errNoCookie(t)
}

// readGeckoCookie snapshots a profile's cookies.sqlite and returns the target
// cookie's raw value. Firefox stores cookie values in plaintext (moz_cookies),
// so there is no decryption — host matching runs in Go via Target.matchesHost,
// and the caller's decode policy is applied once at the Extract boundary. Split
// from extractGecko so tests can point at a fixture DB directly.
func readGeckoCookie(t Target, cookiesPath string) (string, error) {
	copyPath, cleanup, err := copySqliteForRead(cookiesPath)
	if err != nil {
		return "", err
	}
	defer cleanup()

	rows, err := queryReadonlySqlite(copyPath,
		"select value, host from moz_cookies where name = '"+t.CookieName+"' order by length(value) desc")
	if err != nil {
		return "", err
	}
	for _, row := range rows {
		if !t.matchesHost(rowString(row, "host")) {
			continue
		}
		if v := rowString(row, "value"); v != "" {
			return v, nil
		}
	}
	return "", errNoCookie(t)
}

// listGeckoProfilesIn discovers profiles under an explicit base dir: profiles.ini
// entries first, then any unlisted directories under the scan dir (the
// "Profiles" subdir on macOS/Windows, else the base dir — so Zen's title-cased
// dirs like "<hash>.Default (release)" are picked up too). Existing paths only,
// default profiles first. Parameterized so tests drive the discovery rules
// against a temp tree.
func listGeckoProfilesIn(baseDir string, profilesSubdir bool) []geckoProfile {
	var candidates []geckoProfile
	if raw, err := os.ReadFile(filepath.Join(baseDir, "profiles.ini")); err == nil {
		candidates = append(candidates, parseGeckoProfilesIni(string(raw), baseDir)...)
	}

	scanDir := baseDir
	if profilesSubdir {
		scanDir = filepath.Join(baseDir, "Profiles")
	}
	if entries, err := os.ReadDir(scanDir); err == nil {
		seen := make(map[string]bool, len(candidates))
		for _, c := range candidates {
			seen[c.path] = true
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			p := filepath.Join(scanDir, e.Name())
			if seen[p] {
				continue
			}
			seen[p] = true
			candidates = append(candidates, geckoProfile{path: p})
		}
	}

	existing := candidates[:0]
	for _, c := range candidates {
		if _, err := os.Stat(c.path); err == nil {
			existing = append(existing, c)
		}
	}
	sort.SliceStable(existing, func(i, j int) bool {
		return existing[i].isDefault && !existing[j].isDefault
	})
	return existing
}

// parseGeckoProfilesIni parses profiles.ini into profile candidates, resolving
// relative paths against baseDir and honoring both per-[Profile] Default=1 and
// [Install] Default=<path> markers.
func parseGeckoProfilesIni(raw, baseDir string) []geckoProfile {
	type entry struct {
		name       string
		path       string
		isRelative bool
		isDefault  bool
	}
	var entries []entry
	installDefaults := map[string]bool{}

	var section string
	var cur *entry
	flush := func() {
		if cur != nil {
			entries = append(entries, *cur)
			cur = nil
		}
	}

	for _, lineRaw := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(strings.TrimRight(lineRaw, "\r"))
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			section = line[1 : len(line)-1]
			if strings.HasPrefix(section, "Profile") {
				cur = &entry{isRelative: true}
			}
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx == -1 {
			continue
		}
		key, value := strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
		if strings.HasPrefix(section, "Profile") && cur != nil {
			switch key {
			case "Name":
				cur.name = value
			case "Path":
				cur.path = value
			case "IsRelative":
				cur.isRelative = value != "0"
			case "Default":
				cur.isDefault = value == "1"
			}
			continue
		}
		if strings.HasPrefix(section, "Install") && key == "Default" && value != "" {
			installDefaults[value] = true
		}
	}
	flush()

	var profiles []geckoProfile
	for _, e := range entries {
		if e.path == "" {
			continue
		}
		path := e.path
		if e.isRelative {
			path = filepath.Join(baseDir, e.path)
		}
		profiles = append(profiles, geckoProfile{
			name:      e.name,
			path:      path,
			isDefault: e.isDefault || installDefaults[e.path],
		})
	}
	return profiles
}

// pickGeckoProfiles narrows candidates by selector: the profile's Name, its
// directory basename, or a path substring (case-insensitive; the substring
// match also covers a bare ".<name>" suffix). An empty selector returns all.
func pickGeckoProfiles(candidates []geckoProfile, selector string) []geckoProfile {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return candidates
	}
	needle := strings.ToLower(selector)
	var matched []geckoProfile
	for _, c := range candidates {
		base := strings.ToLower(filepath.Base(c.path))
		full := strings.ToLower(c.path)
		if strings.ToLower(c.name) == needle || base == needle || strings.Contains(full, needle) {
			matched = append(matched, c)
		}
	}
	return matched
}

// registerGecko adds a Firefox-family browser to the registry.
func registerGecko(name, summary string, spec geckoSpec) {
	registry[name] = source{
		summary:         summary,
		supportsProfile: true,
		extract: func(plat Platform, t Target, profile string) (string, map[string]string, error) {
			return extractGecko(plat, spec, t, profile)
		},
	}
}

func init() {
	registerGecko("firefox", "Firefox cookie store on disk (moz_cookies, plaintext)", geckoSpec{
		darwin: "Firefox", linux: ".mozilla/firefox", windows: "Mozilla/Firefox",
	})
	registerGecko("zen", "Zen Browser cookie store on disk (moz_cookies, plaintext)", geckoSpec{
		darwin: "zen", linux: ".zen", windows: "zen",
	})
}
