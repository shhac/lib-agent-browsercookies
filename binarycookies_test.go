package browsercookies

import (
	"encoding/binary"
	"testing"
)

// --- synthetic Cookies.binarycookies fixture writer ---
// These emit exactly the layout parseBinaryCookies reads, so tests never need a
// real Safari install. Values are synthetic.

func makeBinaryCookieRecord(c binaryCookie) []byte {
	const headerLen = 48 // fixed-size record header before the string blob
	strs := []byte{}
	domainOff := headerLen + len(strs)
	strs = append(append(strs, c.Domain...), 0)
	nameOff := headerLen + len(strs)
	strs = append(append(strs, c.Name...), 0)
	valueOff := headerLen + len(strs)
	strs = append(append(strs, c.Value...), 0)

	size := headerLen + len(strs)
	rec := make([]byte, size)
	binary.LittleEndian.PutUint32(rec[0:4], uint32(size))
	binary.LittleEndian.PutUint32(rec[16:20], uint32(domainOff))
	binary.LittleEndian.PutUint32(rec[20:24], uint32(nameOff))
	binary.LittleEndian.PutUint32(rec[28:32], uint32(valueOff))
	copy(rec[headerLen:], strs)
	return rec
}

func makeBinaryCookiePage(cookies ...binaryCookie) []byte {
	recs := make([][]byte, len(cookies))
	for i, c := range cookies {
		recs[i] = makeBinaryCookieRecord(c)
	}
	headerLen := 8 + 4*len(cookies)
	offsets := make([]int, len(cookies))
	pos := headerLen
	for i, r := range recs {
		offsets[i] = pos
		pos += len(r)
	}

	page := make([]byte, 0, pos)
	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 0x00000100)
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(len(cookies)))
	page = append(page, hdr[:]...)
	for _, o := range offsets {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(o))
		page = append(page, b[:]...)
	}
	for _, r := range recs {
		page = append(page, r...)
	}
	return page
}

func makeBinaryCookies(pages ...[]byte) []byte {
	out := append([]byte{}, "cook"...)
	var pc [4]byte
	binary.BigEndian.PutUint32(pc[:], uint32(len(pages)))
	out = append(out, pc[:]...)
	for _, p := range pages {
		var s [4]byte
		binary.BigEndian.PutUint32(s[:], uint32(len(p)))
		out = append(out, s[:]...)
	}
	for _, p := range pages {
		out = append(out, p...)
	}
	return out
}

func TestParseBinaryCookiesRoundTrip(t *testing.T) {
	want := []binaryCookie{
		{Domain: "notion.so", Name: "token_v2", Value: "v03%3Auser%3Aabc"},
		{Domain: ".example.test", Name: "session", Value: "plain-value"},
	}
	// Two pages so multi-page assembly is exercised.
	data := makeBinaryCookies(
		makeBinaryCookiePage(want[0]),
		makeBinaryCookiePage(want[1]),
	)

	got, err := parseBinaryCookies(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d cookies, want 2: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("cookie %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseBinaryCookiesRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"short", []byte("coo")},
		{"bad magic", append([]byte("junk"), make([]byte, 8)...)},
		{"truncated page-size table", func() []byte {
			b := append([]byte("cook"), 0, 0, 0, 2) // claims 2 pages
			return append(b, 0, 0)                  // but only 2 of 8 size bytes
		}()},
		{"truncated page", func() []byte {
			b := append([]byte("cook"), 0, 0, 0, 1) // 1 page
			b = append(b, 0, 0, 0, 100)             // page size 100
			return append(b, 1, 2, 3)               // only 3 bytes of page data
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseBinaryCookies(tt.data); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestParseBinaryCookiesImplausiblePageCount(t *testing.T) {
	b := append([]byte("cook"), 0xFF, 0xFF, 0xFF, 0xFF) // ~4 billion pages
	if _, err := parseBinaryCookies(b); err == nil {
		t.Error("expected an implausible-page-count error, not a huge allocation")
	}
}

// TestParseBinaryCookiesTruncationNeverPanics feeds every prefix of a valid file
// through the parser; bounds checks must turn each into an error, never a panic.
func TestParseBinaryCookiesTruncationNeverPanics(t *testing.T) {
	full := makeBinaryCookies(makeBinaryCookiePage(
		binaryCookie{Domain: "notion.so", Name: "token_v2", Value: "v03%3Axyz"},
	))
	for n := 0; n <= len(full); n++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic at prefix length %d: %v", n, r)
				}
			}()
			_, _ = parseBinaryCookies(full[:n])
		}()
	}
}

func TestParseBinaryCookiePageBadHeader(t *testing.T) {
	page := makeBinaryCookiePage(binaryCookie{Domain: "notion.so", Name: "token_v2", Value: "v"})
	binary.LittleEndian.PutUint32(page[:4], 0xDEADBEEF) // corrupt the page tag
	if _, err := parseBinaryCookiePage(page); err == nil {
		t.Error("expected a bad-page-header error for a wrong tag")
	}
}

func TestParseBinaryCookieRecord(t *testing.T) {
	valid := makeBinaryCookieRecord(binaryCookie{Domain: "notion.so", Name: "token_v2", Value: "v03%3Aabc"})

	t.Run("round trip", func(t *testing.T) {
		got, err := parseBinaryCookieRecord(valid, 0)
		if err != nil || got.Domain != "notion.so" || got.Name != "token_v2" || got.Value != "v03%3Aabc" {
			t.Errorf("record = %+v, err = %v", got, err)
		}
	})
	t.Run("out of range", func(t *testing.T) {
		if _, err := parseBinaryCookieRecord(valid[:20], 0); err == nil {
			t.Error("expected out-of-range error for a truncated record")
		}
	})
	t.Run("bad size", func(t *testing.T) {
		rec := append([]byte(nil), valid...)
		binary.LittleEndian.PutUint32(rec[0:4], 10) // < 40
		if _, err := parseBinaryCookieRecord(rec, 0); err == nil {
			t.Error("expected bad-size error")
		}
	})
	t.Run("string offset out of range", func(t *testing.T) {
		rec := append([]byte(nil), valid...)
		binary.LittleEndian.PutUint32(rec[28:32], uint32(len(rec)+100)) // valueOff past end
		if _, err := parseBinaryCookieRecord(rec, 0); err == nil {
			t.Error("expected string-offset error")
		}
	})
	t.Run("unterminated string", func(t *testing.T) {
		rec := append([]byte(nil), valid...)
		rec[len(rec)-1] = 'x' // clobber the value's terminating NUL
		if _, err := parseBinaryCookieRecord(rec, 0); err == nil {
			t.Error("expected unterminated-string error")
		}
	})
}
