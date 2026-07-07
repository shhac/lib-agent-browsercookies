package browsercookies

import (
	"errors"
	"os"
)

// ChromiumStore points the Chromium extraction machinery at a specific on-disk
// cookie store — an Electron desktop app (Slack, Notion, …) or a browser at a
// nonstandard location — rather than one of the registered browsers. It is the
// escape hatch for callers that already know exactly where their app keeps its
// Chromium cookie store; the per-OS path layout is the caller's policy.
type ChromiumStore struct {
	// Paths are candidate Cookies DB locations, tried in order; the first that
	// exists is read.
	Paths []string
	// Services are the macOS Safe Storage keychain service names to try, in
	// order. Ignored off macOS (Linux uses secret-tool, Windows uses DPAPI).
	Services []string
}

// ExtractChromiumStore reads the target cookie from an explicit Chromium store.
// It runs the same snapshot → decrypt → host-hash-strip pipeline as a
// registered Chromium browser; only the store location and keychain services
// are caller-supplied. The decode policy is applied at this boundary, as in
// Extract.
func ExtractChromiumStore(store ChromiumStore, t Target, opts ...Option) (*Result, error) {
	o := options{plat: System()}
	for _, opt := range opts {
		opt(&o)
	}

	cookiesPath := ""
	for _, p := range store.Paths {
		if _, err := os.Stat(p); err == nil {
			cookiesPath = p
			break
		}
	}
	if cookiesPath == "" {
		return nil, errors.New("could not find a Chromium cookie store at any candidate path")
	}

	value, err := readChromiumCookie(o.plat, chromiumSpec{services: store.Services}, t, cookiesPath)
	if err != nil {
		return nil, err
	}
	return &Result{
		Value:   t.finalize(value),
		Browser: "chromium-store",
		Source:  map[string]string{"cookies_path": cookiesPath},
	}, nil
}
