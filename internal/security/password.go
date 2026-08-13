package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"strconv"
	"strings"
)

const pbkdf2Iterations = 600000
const pbkdf2KeyLength = 32

var passwordB64 = base64.RawURLEncoding

func HashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic("secure random source unavailable")
	}
	key := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyLength)
	return "pbkdf2-sha256$" + strconv.Itoa(pbkdf2Iterations) + "$" + passwordB64.EncodeToString(salt) + "$" + passwordB64.EncodeToString(key)
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 100000 || iterations > 2000000 {
		return false
	}
	salt, err := passwordB64.DecodeString(parts[2])
	if err != nil || len(salt) < 16 {
		return false
	}
	want, err := passwordB64.DecodeString(parts[3])
	if err != nil || len(want) != pbkdf2KeyLength {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLength int) []byte {
	hashLength := sha256.Size
	blocks := (keyLength + hashLength - 1) / hashLength
	derived := make([]byte, 0, blocks*hashLength)
	counter := make([]byte, 4)
	for block := 1; block <= blocks; block++ {
		binary.BigEndian.PutUint32(counter, uint32(block))
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		_, _ = mac.Write(counter)
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		derived = append(derived, t...)
	}
	return derived[:keyLength]
}
