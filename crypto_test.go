package browsercookies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"strings"
	"testing"
)

func TestDecryptChromiumCBCRoundTrip(t *testing.T) {
	const token = "v03%3Auser_token%3Aabcdef"
	enc := encryptCBC(t, []byte(token), "test-pass", 1003)
	plain, err := decryptChromiumCBC(enc[3:], "test-pass", 1003) // drop v10 prefix
	if err != nil {
		t.Fatal(err)
	}
	if got := stripHostHashPrefix(plain, 0); got != token {
		t.Errorf("got %q", got)
	}
}

func TestDecryptChromiumCBCErrors(t *testing.T) {
	if _, err := decryptChromiumCBC(nil, "p", 1); err == nil {
		t.Error("empty data should error")
	}
	if _, err := decryptChromiumCBC([]byte("0123456789abcdef"), "p", 0); err == nil {
		t.Error("zero iterations should error")
	}
	if _, err := decryptChromiumCBC([]byte("short"), "p", 1); err == nil {
		t.Error("non-block-multiple should error")
	}
}

func TestStripHostHashPrefix(t *testing.T) {
	prefix := strings.Repeat("\xAB", 32)
	if got := stripHostHashPrefix([]byte(prefix+"tok"), 24); got != "tok" {
		t.Errorf("v24 strip: %q", got)
	}
	if got := stripHostHashPrefix([]byte("tok"), 20); got != "tok" {
		t.Errorf("pre-v24: %q", got)
	}
	// Verbatim: percent-encoding survives.
	if got := stripHostHashPrefix([]byte("a%3Ab"), 0); got != "a%3Ab" {
		t.Errorf("verbatim: %q", got)
	}
}

func TestPKCS7Unpad(t *testing.T) {
	if _, err := pkcs7Unpad(nil, 16); err == nil {
		t.Error("empty should error")
	}
	if _, err := pkcs7Unpad([]byte("0123456789abcde\x11"), 16); err == nil {
		t.Error("pad > blockSize should error")
	}
	if _, err := pkcs7Unpad([]byte("0123456789abc\x03\x03\x02"), 16); err == nil {
		t.Error("inconsistent pad bytes should error")
	}
}

func TestDecryptChromiumGCMRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	enc := encryptGCM(t, []byte("v03%3Awin_token"), key)

	plain, err := decryptChromiumGCM(enc, key)
	if err != nil {
		t.Fatal(err)
	}
	if got := stripHostHashPrefix(plain, 0); got != "v03%3Awin_token" {
		t.Errorf("got %q", got)
	}
}

func TestDecryptChromiumGCMShort(t *testing.T) {
	if _, err := decryptChromiumGCM([]byte("v10short"), make([]byte, 32)); err == nil {
		t.Error("short cookie should error")
	}
}

// encryptGCM produces a v10 Windows GCM blob: "v10" || nonce(12) || ct || tag.
func encryptGCM(t *testing.T, plaintext, key []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	out := append([]byte("v10"), nonce...)
	return append(out, sealed...)
}
