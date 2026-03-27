package crypto

import (
	"bytes"
	"testing"
	"github.com/wow-look-at-my/testify/require"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	enc, err := NewEncryptor(key)
	require.Nil(t, err)

	plaintext := []byte("hello world secret value")
	ciphertext, err := enc.Encrypt(plaintext)
	require.Nil(t, err)

	require.False(t, bytes.Equal(plaintext, ciphertext))

	decrypted, err := enc.Decrypt(ciphertext)
	require.Nil(t, err)

	require.True(t, bytes.Equal(plaintext, decrypted))

}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key := make([]byte, 32)
	enc, err := NewEncryptor(key)
	require.Nil(t, err)

	plaintext := []byte("same input")
	ct1, _ := enc.Encrypt(plaintext)
	ct2, _ := enc.Encrypt(plaintext)

	require.False(t, bytes.Equal(ct1, ct2))

}

func TestDecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	enc, err := NewEncryptor(key)
	require.Nil(t, err)

	_, err = enc.Decrypt([]byte("short"))
	require.NotNil(t, err)

}

func TestDecryptTampered(t *testing.T) {
	key := make([]byte, 32)
	enc, err := NewEncryptor(key)
	require.Nil(t, err)

	ct, _ := enc.Encrypt([]byte("hello"))
	ct[len(ct)-1] ^= 0xff	// tamper

	_, err = enc.Decrypt(ct)
	require.NotNil(t, err)

}

func TestNewEncryptorBadKeySize(t *testing.T) {
	_, err := NewEncryptor([]byte("too short"))
	require.NotNil(t, err)

}
