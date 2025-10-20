package kademlia

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
)

type KeyExchanger interface {
	GenerateNewKeyPair() (privateKey []byte, publicKey []byte, err error)
	ComputeSharedSecret(privateKey []byte, peerPublicKey []byte) ([]byte, error)
}

type X25519KeyExchanger struct{}

func (ke *X25519KeyExchanger) GenerateNewKeyPair() (privateKey []byte, publicKey []byte, err error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate X25519 key pair: %w", err)
	}

	return privKey.Bytes(), privKey.PublicKey().Bytes(), nil
}

func (ke *X25519KeyExchanger) ComputeSharedSecret(privateKey []byte, peerPublicKey []byte) ([]byte, error) {
	privKey, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create X25519 private key: %w", err)
	}

	pubKey, err := ecdh.X25519().NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create X25519 public key: %w", err)
	}

	sharedSecret, err := privKey.ECDH(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	return sharedSecret, nil
}

type MLKEMKeyExchanger struct{}

func (ke *MLKEMKeyExchanger) GenerateNewKeyPair() (privateKey []byte, publicKey []byte, err error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate MLKEM key pair: %w", err)
	}

	return dk.Bytes(), dk.EncapsulationKey().Bytes(), nil
}

func (ke *MLKEMKeyExchanger) ComputeSharedSecret(seed []byte, peerCipherText []byte) ([]byte, error) {
	dk, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to create MLKEM private key: %w", err)
	}

	sharedSecret, err := dk.Decapsulate(peerCipherText)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	return sharedSecret, nil
}
