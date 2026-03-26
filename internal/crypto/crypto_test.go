package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello world secret value")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key := make([]byte, 32)
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("same input")
	ct1, _ := enc.Encrypt(plaintext)
	ct2, _ := enc.Encrypt(plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Fatal("encrypting the same plaintext should produce different ciphertexts (random nonce)")
	}
}

func TestDecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = enc.Decrypt([]byte("short"))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

func TestDecryptTampered(t *testing.T) {
	key := make([]byte, 32)
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	ct, _ := enc.Encrypt([]byte("hello"))
	ct[len(ct)-1] ^= 0xff // tamper

	_, err = enc.Decrypt(ct)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestNewEncryptorBadKeySize(t *testing.T) {
	_, err := NewEncryptor([]byte("too short"))
	if err == nil {
		t.Fatal("expected error for bad key size")
	}
}
