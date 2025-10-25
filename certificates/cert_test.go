package certificates_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/snowmerak/satellite-network/certificates"
)

func TestNewPrivate(t *testing.T) {
	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	if priv == nil {
		t.Fatal("Private key is nil")
	}
	if priv.Public() == nil {
		t.Fatal("Public key is nil")
	}
}

func TestMarshalUnmarshalPrivate(t *testing.T) {
	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}

	data, err := priv.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	newPriv := &certificates.Private{}
	err = newPriv.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal private key: %v", err)
	}

	// Compare IDs to ensure they match
	origID, _ := priv.Public().ID()
	newID, _ := newPriv.Public().ID()
	if !bytes.Equal(origID, newID) {
		t.Fatal("Unmarshaled private key does not match original")
	}
}

func TestMarshalUnmarshalPublic(t *testing.T) {
	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	pub := priv.Public()

	data, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	newPub := &certificates.Public{}
	err = newPub.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal public key: %v", err)
	}

	// Compare IDs
	origID, _ := pub.ID()
	newID, _ := newPub.ID()
	if !bytes.Equal(origID, newID) {
		t.Fatal("Unmarshaled public key does not match original")
	}
}

func TestEncapsulateDecapsulate(t *testing.T) {
	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	pub := priv.Public()

	sharedSecret1, ciphertext, err := pub.Encapsulate()
	if err != nil {
		t.Fatalf("Failed to encapsulate: %v", err)
	}

	sharedSecret2, err := priv.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decapsulate: %v", err)
	}

	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Fatal("Shared secrets do not match")
	}
}

func TestSignVerify(t *testing.T) {
	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	pub := priv.Public()

	signature, err := priv.SignPublicKey()
	if err != nil {
		t.Fatalf("Failed to sign public key: %v", err)
	}

	err = pub.VerifySignature(signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
}

func TestID(t *testing.T) {
	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	pub := priv.Public()

	id, err := pub.ID()
	if err != nil {
		t.Fatalf("Failed to generate ID: %v", err)
	}
	if len(id) != 64 { // Blake3 Sum512 is 64 bytes
		t.Fatalf("ID length is %d, expected 64", len(id))
	}

	// Ensure ID is deterministic
	id2, _ := pub.ID()
	if !bytes.Equal(id, id2) {
		t.Fatal("ID is not deterministic")
	}
}
