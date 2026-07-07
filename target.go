package browsercookies

import (
	"net/url"
	"strings"
)

// Target is the caller's policy: which cookie to extract and how to return its
// value. It is the service-specific half of the mechanism/policy split — the
// same extraction machinery serves any service by varying this.
type Target struct {
	// CookieName is the cookie to read, e.g. "token_v2" or "d".
	CookieName string
	// HostSuffixes are the domains the cookie may live under, matched against
	// the store's host by suffix — e.g. []string{"notion.so", "notion.com"}.
	// A service that spans domains MUST list all of them, or the cookie is
	// missed on the ones left out.
	HostSuffixes []string
	// Decode URL-decodes the value. The default (false) returns the value
	// verbatim, which is correct for the cookie protocol: browsers transmit
	// cookie values byte-for-byte, so a percent-encoded value (e.g. Notion's
	// "v03%3A…") must stay encoded. Set true only for a service known to want
	// the decoded form.
	Decode bool
}

// matchesHost reports whether a store host belongs to this target.
func (t Target) matchesHost(host string) bool {
	host = strings.TrimPrefix(host, ".")
	for _, suffix := range t.HostSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) || strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// hostSQLClause builds a SQL predicate on the given column matching any of the
// target's host suffixes. Values are suffixes with no user input beyond the
// configured domains, so simple concatenation is safe here.
func (t Target) hostSQLClause(col string) string {
	if len(t.HostSuffixes) == 0 {
		return "1=1"
	}
	parts := make([]string, 0, len(t.HostSuffixes))
	for _, suffix := range t.HostSuffixes {
		parts = append(parts, col+" like '%"+suffix+"'")
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

// finalize applies the decode policy to a raw stored cookie value.
func (t Target) finalize(raw string) string {
	if !t.Decode {
		return raw
	}
	if decoded, err := url.PathUnescape(raw); err == nil {
		return decoded
	}
	return raw
}

// Result is an extracted cookie value plus where it came from.
type Result struct {
	// Value is the cookie value, shaped by Target.Decode.
	Value string
	// Browser is the source name (e.g. "chrome", "firefox").
	Browser string
	// Source carries provenance for diagnostics — the profile or DB path the
	// value was read from. Never the value or any secret.
	Source map[string]string
}
