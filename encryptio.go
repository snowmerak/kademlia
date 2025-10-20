package kademlia

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

type Encryptor interface {
	Encrypt(plainText []byte) ([]byte, error)
	Decrypt(cipherText []byte) ([]byte, error)
}

type AES256 struct {
	aead cipher.AEAD
}

func NewAES256(sharedSecret []byte) (*AES256, error) {
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &AES256{aead: aead}, nil
}

func (e *AES256) Encrypt(plainText []byte, sharedSecret []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	rand.Read(nonce)

	cipherText := e.aead.Seal(nil, nonce, plainText, nil)
	return append(nonce, cipherText...), nil
}

func (e *AES256) Decrypt(cipherText []byte, sharedSecret []byte) ([]byte, error) {
	nonceSize := e.aead.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	plainText, err := e.aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plainText, nil
}

type XChaCha20Poly1305 struct {
	aead cipher.AEAD
}

func NewXChaCha20Poly1305(sharedSecret []byte) (*XChaCha20Poly1305, error) {
	aead, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20Poly1305 cipher: %w", err)
	}

	return &XChaCha20Poly1305{aead: aead}, nil
}

func (e *XChaCha20Poly1305) Encrypt(plainText []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	rand.Read(nonce)

	cipherText := e.aead.Seal(nil, nonce, plainText, nil)
	return append(nonce, cipherText...), nil
}

func (e *XChaCha20Poly1305) Decrypt(cipherText []byte) ([]byte, error) {
	nonceSize := e.aead.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	plainText, err := e.aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plainText, nil
}
