package browsercookies

// registry maps a browser/app name to its source. Firefox/Zen (Gecko) and
// Safari are added by their own files as they land.
var registry = map[string]source{}

// registerChromium adds a Chromium-family browser to the registry.
func registerChromium(name, summary string, spec chromiumSpec) {
	registry[name] = chromiumSource{summaryText: summary, spec: spec}
}

// chromiumSource adapts a chromiumSpec to the source interface.
type chromiumSource struct {
	summaryText string
	spec        chromiumSpec
}

func (c chromiumSource) supportsProfile() bool { return false }
func (c chromiumSource) summary() string       { return c.summaryText }

func (c chromiumSource) extract(plat Platform, t Target, _ string) (string, map[string]string, error) {
	value, path, err := extractChromium(plat, c.spec, t)
	if err != nil {
		return "", nil, err
	}
	return value, map[string]string{"cookies_path": path}, nil
}

// chromiumSafeStorage is the macOS keychain service list for a browser, always
// falling back to the generic Chrome/Chromium services.
func chromiumSafeStorage(services ...string) []string {
	return append(services, "Chrome Safe Storage", "Chromium Safe Storage")
}

func init() {
	registerChromium("chrome", "Google Chrome cookie store on disk", chromiumSpec{
		darwin: "Google/Chrome", linux: ".config/google-chrome", windows: "Google/Chrome/User Data",
		services: chromiumSafeStorage("Chrome Safe Storage"),
	})
	registerChromium("brave", "Brave cookie store on disk", chromiumSpec{
		darwin: "BraveSoftware/Brave-Browser", linux: ".config/BraveSoftware/Brave-Browser",
		windows:  "BraveSoftware/Brave-Browser/User Data",
		services: chromiumSafeStorage("Brave Safe Storage", "Brave Browser Safe Storage"),
	})
	registerChromium("edge", "Microsoft Edge cookie store on disk", chromiumSpec{
		darwin: "Microsoft Edge", linux: ".config/microsoft-edge", windows: "Microsoft/Edge/User Data",
		services: chromiumSafeStorage("Microsoft Edge Safe Storage"),
	})
	registerChromium("arc", "Arc cookie store on disk", chromiumSpec{
		// Arc nests under "User Data" on every OS, unlike Chrome.
		darwin: "Arc/User Data", linux: ".config/arc", windows: "Arc/User Data",
		services: chromiumSafeStorage("Arc Safe Storage"),
	})
	registerChromium("chromium", "Chromium cookie store on disk", chromiumSpec{
		darwin: "Chromium", linux: ".config/chromium", windows: "Chromium/User Data",
		services: chromiumSafeStorage("Chromium Safe Storage"),
	})
}
