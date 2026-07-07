package browsercookies

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// binaryCookie is one decoded entry from a Safari Cookies.binarycookies file.
type binaryCookie struct {
	Domain string
	Name   string
	Value  string
}

// maxBinaryCookiePages caps the declared page count so a hostile header cannot
// force a huge slice allocation before any bytes are validated.
const maxBinaryCookiePages = 1 << 20

// parseBinaryCookies decodes Safari's Cookies.binarycookies format (WebKit).
// Layout: magic "cook", big-endian page count and page sizes, then each page
// holds little-endian cookie records with offset-addressed NUL-terminated
// strings. Only the fields we need (domain, name, value) are recovered; bounds
// are checked throughout so a truncated or hostile file yields an error, never
// a panic or an unbounded allocation.
func parseBinaryCookies(data []byte) ([]binaryCookie, error) {
	if len(data) < 8 || !bytes.HasPrefix(data, []byte("cook")) {
		return nil, errors.New("not a Cookies.binarycookies file")
	}
	pageCount := int(binary.BigEndian.Uint32(data[4:8]))
	if pageCount > maxBinaryCookiePages {
		return nil, errors.New("binarycookies: implausible page count")
	}

	off := 8
	pageSizes := make([]int, pageCount)
	for i := 0; i < pageCount; i++ {
		if off+4 > len(data) {
			return nil, errors.New("binarycookies: truncated page-size table")
		}
		pageSizes[i] = int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
	}

	var cookies []binaryCookie
	for _, size := range pageSizes {
		if size < 0 || off+size > len(data) {
			return nil, errors.New("binarycookies: truncated page")
		}
		pc, err := parseBinaryCookiePage(data[off : off+size])
		if err != nil {
			return nil, err
		}
		cookies = append(cookies, pc...)
		off += size
	}
	return cookies, nil
}

// parseBinaryCookiePage decodes one page: a little-endian tag (0x00000100), a
// little-endian cookie count, a count-length table of little-endian record
// offsets from the page start, then the records.
func parseBinaryCookiePage(page []byte) ([]binaryCookie, error) {
	if len(page) < 8 || binary.LittleEndian.Uint32(page[:4]) != 0x00000100 {
		return nil, errors.New("binarycookies: bad page header")
	}
	count := int(binary.LittleEndian.Uint32(page[4:8]))
	// Bound the count by the page length before allocating so a bogus count
	// can neither overrun the offset table nor force a huge slice.
	if count < 0 || 8+count*4 > len(page) {
		return nil, errors.New("binarycookies: bad cookie count")
	}

	out := make([]binaryCookie, 0, count)
	for i := 0; i < count; i++ {
		start := int(binary.LittleEndian.Uint32(page[8+i*4 : 12+i*4]))
		c, err := parseBinaryCookieRecord(page, start)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// parseBinaryCookieRecord decodes one record: a little-endian size, then (at
// fixed offsets) the domain/name/value string offsets relative to the record
// start, then the NUL-terminated strings. The record is sliced to its declared
// size so a string offset can never read past it into the next record.
func parseBinaryCookieRecord(page []byte, start int) (binaryCookie, error) {
	if start < 0 || start+40 > len(page) {
		return binaryCookie{}, errors.New("binarycookies: cookie record out of range")
	}
	size := int(binary.LittleEndian.Uint32(page[start : start+4]))
	if size < 40 || start+size > len(page) {
		return binaryCookie{}, errors.New("binarycookies: bad cookie record size")
	}
	rec := page[start : start+size]

	domainOff := int(binary.LittleEndian.Uint32(rec[16:20]))
	nameOff := int(binary.LittleEndian.Uint32(rec[20:24]))
	valueOff := int(binary.LittleEndian.Uint32(rec[28:32]))

	domain, err := cstringAt(rec, domainOff)
	if err != nil {
		return binaryCookie{}, err
	}
	name, err := cstringAt(rec, nameOff)
	if err != nil {
		return binaryCookie{}, err
	}
	value, err := cstringAt(rec, valueOff)
	if err != nil {
		return binaryCookie{}, err
	}
	return binaryCookie{Domain: domain, Name: name, Value: value}, nil
}

// cstringAt reads a NUL-terminated string at off within rec.
func cstringAt(rec []byte, off int) (string, error) {
	if off < 0 || off >= len(rec) {
		return "", errors.New("binarycookies: string offset out of range")
	}
	end := bytes.IndexByte(rec[off:], 0)
	if end < 0 {
		return "", errors.New("binarycookies: unterminated string")
	}
	return string(rec[off : off+end]), nil
}
