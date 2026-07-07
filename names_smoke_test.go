package browsercookies

import "testing"

func TestAllSourcesRegistered(t *testing.T) {
	want := map[string]bool{"chrome": true, "brave": true, "edge": true, "arc": true, "chromium": true, "firefox": true, "zen": true, "safari": true}
	for _, n := range Names() {
		delete(want, n)
	}
	if len(want) != 0 {
		t.Errorf("missing registrations: %v", want)
	}
}
