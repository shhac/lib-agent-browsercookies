package browsercookies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// testPlatform builds a hermetic Platform: a fake home dir, controllable
// env/GOOS, and a stubbed keychain — so no test ever reads the real store.
func testPlatform(t *testing.T, goos, home string, passwords ...string) Platform {
	t.Helper()
	return Platform{
		GOOS:   goos,
		Home:   home,
		Getenv: func(string) string { return "" },
		Keychain: func([]string) []string {
			return append([]string(nil), passwords...)
		},
	}
}

// newChromiumCookiesDB writes a Chromium-shaped Cookies DB at
// <dir>/<profile>/Cookies with one token row, returning the DB path.
func newChromiumCookiesDB(t *testing.T, dir, host, name, value string, encrypted []byte, metaVersion int) string {
	t.Helper()
	path := filepath.Join(dir, "Cookies")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	exec := func(q string, args ...any) {
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	exec(`CREATE TABLE meta (key TEXT, value TEXT)`)
	if metaVersion > 0 {
		exec(`INSERT INTO meta (key, value) VALUES ('version', ?)`, metaVersion)
	}
	exec(`CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB)`)
	exec(`INSERT INTO cookies (host_key, name, value, encrypted_value) VALUES (?, ?, ?, ?)`,
		host, name, value, encrypted)
	return path
}

// encryptCBC produces a "v10"-prefixed Chromium CBC cookie value for the given
// plaintext + password, matching decryptChromiumCBC.
func encryptCBC(t *testing.T, plaintext []byte, password string, iterations int) []byte {
	t.Helper()
	key, err := pbkdf2.Key(sha1.New, password, []byte("saltysalt"), iterations, 16)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, spacesIV(16)).CryptBlocks(out, padded)
	return append([]byte("v10"), out...)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func mkdir(dir string) error { return os.MkdirAll(dir, 0o755) }
