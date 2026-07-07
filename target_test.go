package browsercookies

import "testing"

func TestTargetMatchesHost(t *testing.T) {
	tgt := Target{HostSuffixes: []string{"notion.so", "notion.com"}}
	yes := []string{".www.notion.so", "www.notion.so", ".notion.so", ".app.notion.com", "app.notion.com"}
	no := []string{"example.com", "notion.so.evil.com", ".slack.com"}
	for _, h := range yes {
		if !tgt.matchesHost(h) {
			t.Errorf("matchesHost(%q) = false, want true", h)
		}
	}
	for _, h := range no {
		if tgt.matchesHost(h) {
			t.Errorf("matchesHost(%q) = true, want false", h)
		}
	}
}

func TestTargetFinalize(t *testing.T) {
	verbatim := Target{}
	if got := verbatim.finalize("v03%3Ax"); got != "v03%3Ax" {
		t.Errorf("verbatim = %q", got)
	}
	decode := Target{Decode: true}
	if got := decode.finalize("a%2Fb"); got != "a/b" {
		t.Errorf("decode = %q", got)
	}
}
