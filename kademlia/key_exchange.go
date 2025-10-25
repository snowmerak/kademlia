package kademlia

import (
	"crypto/mlkem"
	"fmt"
)

type KeyExchanger interface {
	// GenerateNewKeyPair generates a new key pair for KEM
	// Returns: decapsulation key (private), encapsulation key (public)
	GenerateNewKeyPair() (decapsulationKey []byte, encapsulationKey []byte, err error)

	// Encapsulate generates a cipher text and shared secret from encapsulation key
	// Used by client to generate cipher text to send to server
	Encapsulate(encapsulationKey []byte) (cipherText []byte, sharedSecret []byte, err error)

	// Decapsulate extracts shared secret from cipher text using decapsulation key
	// Used by server to derive shared secret from received cipher text
	Decapsulate(decapsulationKey []byte, cipherText []byte) (sharedSecret []byte, err error)
}

type MLKEMKeyExchanger struct{}

func (ke *MLKEMKeyExchanger) GenerateNewKeyPair() (decapsulationKey []byte, encapsulationKey []byte, err error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate MLKEM key pair: %w", err)
	}

	return dk.Bytes(), dk.EncapsulationKey().Bytes(), nil
}

func (ke *MLKEMKeyExchanger) Encapsulate(encapsulationKey []byte) (cipherText []byte, sharedSecret []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey1024(encapsulationKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create MLKEM encapsulation key: %w", err)
	}

	// Note: Encapsulate() returns (sharedKey, ciphertext) in that order!
	sharedSecret, cipherText = ek.Encapsulate()

	return cipherText, sharedSecret, nil
}

func (ke *MLKEMKeyExchanger) Decapsulate(decapsulationKey []byte, cipherText []byte) (sharedSecret []byte, err error) {
	dk, err := mlkem.NewDecapsulationKey1024(decapsulationKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create MLKEM decapsulation key: %w", err)
	}

	sharedSecret, err = dk.Decapsulate(cipherText)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate: %w", err)
	}

	return sharedSecret, nil
}
