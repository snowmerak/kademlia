package certificates_test

import (
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/snowmerak/satellite-network/certificates"
)

func TestNewStoredData(t *testing.T) {
	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	pub := priv.Public()

	sd := certificates.NewStoredPublicKey(pub)

	if sd.GetPublicKey() != pub {
		t.Error("Public key not set correctly")
	}

	sigs := sd.GetSignatures()
	if len(sigs) != 0 {
		t.Errorf("Expected empty signatures map, got %d entries", len(sigs))
	}
}

func TestAddSignature(t *testing.T) {
	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	pub := priv.Public()

	sd := certificates.NewStoredPublicKey(pub)

	// Add new signature
	added, err := sd.AddSignature("key1", []byte("signature1"))
	if err != nil {
		t.Errorf("Failed to add signature: %v", err)
	}
	if !added {
		t.Error("Expected signature to be added")
	}

	// Try to add duplicate
	added, err = sd.AddSignature("key1", []byte("signature2"))
	if err != nil {
		t.Errorf("Failed to check duplicate: %v", err)
	}
	if added {
		t.Error("Expected signature not to be added (duplicate)")
	}

	// Check signatures
	sigs := sd.GetSignatures()
	if len(sigs) != 1 {
		t.Errorf("Expected 1 signature, got %d", len(sigs))
	}
	if string(sigs["key1"]) != "signature1" {
		t.Error("Signature not stored correctly")
	}
}

func TestMarshalUnmarshalBinary(t *testing.T) {
	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	pub := priv.Public()

	sd := certificates.NewStoredPublicKey(pub)

	// Add some signatures
	sd.AddSignature("key1", []byte("sig1"))
	sd.AddSignature("key2", []byte("sig2"))

	// Marshal
	data, err := sd.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal
	sd2 := &certificates.StoredPublicKey{}
	err = sd2.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Compare
	if !reflect.DeepEqual(sd.GetPublicKey(), sd2.GetPublicKey()) {
		t.Error("Public keys do not match after marshal/unmarshal")
	}

	sigs1 := sd.GetSignatures()
	sigs2 := sd2.GetSignatures()
	if !reflect.DeepEqual(sigs1, sigs2) {
		t.Error("Signatures do not match after marshal/unmarshal")
	}
}

func TestUnmarshalBinaryErrors(t *testing.T) {
	sd := &certificates.StoredPublicKey{}

	// Too short data
	err := sd.UnmarshalBinary([]byte{1, 2, 3})
	if err == nil {
		t.Error("Expected error for too short data")
	}

	// Invalid public key data (simulate)
	// This is hard to test precisely without mocking, but basic length checks are covered
}
