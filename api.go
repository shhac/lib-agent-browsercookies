package browsercookies

import (
	"fmt"
	"sort"
	"strings"
)

// source is one importable browser or app: it knows how to locate its store on
// a platform and return the target cookie's value plus provenance. There is one
// behavior per source (locate + read), so a struct with a func field is a
// better fit than an interface with a lone implementation each.
type source struct {
	// summary is a one-line human description.
	summary string
	// supportsProfile reports whether the profile argument is meaningful
	// (Firefox-family). Used only for help/metadata.
	supportsProfile bool
	// extract returns the raw cookie value (decode policy is applied by the
	// caller at the Extract boundary), the provenance map, and an error.
	extract func(plat Platform, t Target, profile string) (value string, provenance map[string]string, err error)
}

// options configure Extract.
type options struct {
	plat    Platform
	profile string
}

// Option customizes an Extract call.
type Option func(*options)

// WithPlatform overrides the host environment — for tests and for pointing at
// a non-default install layout.
func WithPlatform(p Platform) Option { return func(o *options) { o.plat = p } }

// WithProfile selects a Firefox-family profile by directory name, path
// substring, or the exact name (ignored by other browsers).
func WithProfile(profile string) Option { return func(o *options) { o.profile = profile } }

// Extract reads the target cookie from the named browser or app.
func Extract(name string, t Target, opts ...Option) (*Result, error) {
	o := options{plat: System()}
	for _, opt := range opts {
		opt(&o)
	}

	key := strings.ToLower(strings.TrimSpace(name))
	src, ok := registry[key]
	if !ok {
		return nil, fmt.Errorf("unknown browser %q (supported: %s)", name, strings.Join(Names(), ", "))
	}
	// Sources return the raw stored value; the decode policy (verbatim vs
	// URL-decode) is applied once here, at the boundary.
	value, provenance, err := src.extract(o.plat, t, o.profile)
	if err != nil {
		return nil, err
	}
	return &Result{Value: t.finalize(value), Browser: key, Source: provenance}, nil
}

// Info describes a supported source for help text and completion.
type Info struct {
	Name            string
	Summary         string
	SupportsProfile bool
}

// Sources returns metadata for every registered browser/app, in name order.
func Sources() []Info {
	out := make([]Info, 0, len(registry))
	for name, src := range registry {
		out = append(out, Info{Name: name, Summary: src.summary, SupportsProfile: src.supportsProfile})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Names returns the supported source names in sorted order.
func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
