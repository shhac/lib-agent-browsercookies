package browsercookies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
)

// decryptChromiumCBC decrypts a Chromium "v10"/"v11" cookie value (already
// stripped of the 3-byte version prefix) using the macOS/Linux scheme:
// PBKDF2-HMAC-SHA1(password, "saltysalt", iterations, 16) as an AES-128-CBC key
// with a 16-space IV and PKCS#7 padding. It returns the unpadded plaintext; the
// caller strips any leading domain-hash prefix.
func decryptChromiumCBC(data []byte, password string, iterations int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty cookie data")
	}
	if iterations < 1 {
		return nil, errors.New("iterations must be >= 1")
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("cookie data is not a multiple of the AES block size")
	}

	key := pbkdf2SHA1([]byte(password), []byte("saltysalt"), iterations, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, spacesIV(16)).CryptBlocks(plain, data)
	return pkcs7Unpad(plain, aes.BlockSize)
}

// decryptChromiumGCM decrypts a Windows "v10" cookie: prefix(3) || nonce(12) ||
// ciphertext || tag(16), AES-256-GCM.
func decryptChromiumGCM(encrypted, key []byte) ([]byte, error) {
	if len(encrypted) < 3+12+16 {
		return nil, errors.New("cookie too short for AES-GCM")
	}
	nonce := encrypted[3:15]
	ciphertext := encrypted[15:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// stripHostHashPrefix drops the 32-byte SHA-256(host) hash that Chromium
// meta-version >= 24 prepends to the decrypted plaintext. The remaining bytes
// are the verbatim cookie value.
func stripHostHashPrefix(plain []byte, metaVersion int) string {
	if metaVersion >= 24 && len(plain) >= 32 {
		plain = plain[32:]
	}
	return string(plain)
}

func spacesIV(n int) []byte {
	iv := make([]byte, n)
	for i := range iv {
		iv[i] = ' '
	}
	return iv
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padded data")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return nil, errors.New("invalid PKCS#7 padding")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, errors.New("invalid PKCS#7 padding bytes")
		}
	}
	return data[:len(data)-pad], nil
}

// pbkdf2SHA1 is a minimal PBKDF2-HMAC-SHA1, avoiding a golang.org/x/crypto
// dependency for this single use.
func pbkdf2SHA1(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha1.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	out := make([]byte, 0, numBlocks*hashLen)
	buf := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf)
		u := prf.Sum(nil)

		t := make([]byte, len(u))
		copy(t, u)
		for n := 1; n < iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for i := range t {
				t[i] ^= u[i]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
