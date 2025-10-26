package certificates_test

import (
	"crypto/rand"
	"reflect"
	"testing"
	"time"

	"github.com/snowmerak/satellite-network/certificates"
)

func TestNewStoredPublicKey(t *testing.T) {
	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	pub := priv.Public()
	createdAt := time.Now()

	sp := certificates.NewStoredPublicKey(pub, createdAt)

	if sp.GetPublicKey() != pub {
		t.Error("Public key not set correctly")
	}

	if !sp.GetCreatedAt().Equal(createdAt) {
		t.Error("CreatedAt not set correctly")
	}

	sigs := sp.GetSignatures()
	if len(sigs) != 0 {
		t.Errorf("Expected empty signatures map, got %d entries", len(sigs))
	}
}

func TestSetGetPreviousHash(t *testing.T) {
	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	pub := priv.Public()

	sp := certificates.NewStoredPublicKey(pub, time.Now())

	hash := []byte("previous_hash")
	sp.SetPreviousHash(hash)

	retrieved := sp.GetPreviousHash()
	if !reflect.DeepEqual(retrieved, hash) {
		t.Error("Previous hash not set or retrieved correctly")
	}
}

func TestAddSignature(t *testing.T) {
	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	pub := priv.Public()

	sp := certificates.NewStoredPublicKey(pub, time.Now())

	// Add new signature
	added, err := sp.AddSignature("key1", []byte("signature1"))
	if err != nil {
		t.Errorf("Failed to add signature: %v", err)
	}
	if !added {
		t.Error("Expected signature to be added")
	}

	// Try to add duplicate
	added, err = sp.AddSignature("key1", []byte("signature2"))
	if err != nil {
		t.Errorf("Failed to check duplicate: %v", err)
	}
	if added {
		t.Error("Expected signature not to be added (duplicate)")
	}

	// Check signatures
	sigs := sp.GetSignatures()
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
	createdAt := time.Now()

	sp := certificates.NewStoredPublicKey(pub, createdAt)

	// Set previous hash
	hash := []byte("prev_hash")
	sp.SetPreviousHash(hash)

	// Add some signatures
	sp.AddSignature("key1", []byte("sig1"))
	sp.AddSignature("key2", []byte("sig2"))

	// Marshal
	data, err := sp.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal
	sp2 := &certificates.StoredPublicKey{}
	err = sp2.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Compare
	if !reflect.DeepEqual(sp.GetPublicKey(), sp2.GetPublicKey()) {
		t.Error("Public keys do not match after marshal/unmarshal")
	}

	if !reflect.DeepEqual(sp.GetPreviousHash(), sp2.GetPreviousHash()) {
		t.Error("Previous hashes do not match after marshal/unmarshal")
	}

	if !sp.GetCreatedAt().Equal(sp2.GetCreatedAt()) {
		t.Error("CreatedAt does not match after marshal/unmarshal")
	}

	sigs1 := sp.GetSignatures()
	sigs2 := sp2.GetSignatures()
	if !reflect.DeepEqual(sigs1, sigs2) {
		t.Error("Signatures do not match after marshal/unmarshal")
	}
}

func TestUnmarshalBinaryErrors(t *testing.T) {
	sp := &certificates.StoredPublicKey{}

	// Too short data
	err := sp.UnmarshalBinary([]byte{1, 2, 3})
	if err == nil {
		t.Error("Expected error for too short data")
	}

	// Invalid public key data (simulate)
	// This is hard to test precisely without mocking, but basic length checks are covered
}
