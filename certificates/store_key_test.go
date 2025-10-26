package certificates_test

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/snowmerak/satellite-network/certificates"
	"github.com/snowmerak/satellite-network/shared/store"
)

func setupTestStore(t *testing.T) *certificates.Store {
	t.Helper()
	sharedStore, err := store.NewStore(store.StoreInMemory)
	if err != nil {
		t.Fatalf("Failed to create shared store: %v", err)
	}
	certStore, err := certificates.NewStore(sharedStore)
	if err != nil {
		t.Fatalf("Failed to create certificates store: %v", err)
	}
	t.Cleanup(func() {
		certStore.Close()
	})
	return certStore
}

func TestStorePublicKey(t *testing.T) {
	s := setupTestStore(t)

	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	pub := priv.Public()
	id, err := pub.ID()
	if err != nil {
		t.Fatalf("Failed to get public key ID: %v", err)
	}

	spk := certificates.NewStoredPublicKey(id, pub, time.Now())

	err = s.StorePublicKey(spk)
	if err != nil {
		t.Fatalf("Failed to store public key: %v", err)
	}

	// Verify by getting it back
	blockID, err := pub.ID()
	if err != nil {
		t.Fatalf("Failed to get block ID: %v", err)
	}
	retrieved, err := s.GetStoredPublicKey(id, blockID)
	if err != nil {
		t.Fatalf("Failed to get stored public key: %v", err)
	}

	retrievedID, err := retrieved.GetPublicKey().ID()
	if err != nil {
		t.Fatalf("Failed to get retrieved ID: %v", err)
	}
	if !bytes.Equal(id, retrievedID) {
		t.Fatal("Stored and retrieved IDs do not match")
	}
}

func TestUpdateLatestPublicKeyReference(t *testing.T) {
	s := setupTestStore(t)

	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	pub := priv.Public()
	id, err := pub.ID()
	if err != nil {
		t.Fatalf("Failed to get public key ID: %v", err)
	}

	blockID := []byte("test_block_id")

	err = s.UpdateLatestPublicKeyReference(id, blockID)
	if err != nil {
		t.Fatalf("Failed to update latest public key reference: %v", err)
	}

	retrieved, err := s.GetLatestPublicKeyReference(id)
	if err != nil {
		t.Fatalf("Failed to get latest public key reference: %v", err)
	}

	if !bytes.Equal(blockID, retrieved) {
		t.Fatal("Updated and retrieved references do not match")
	}
}

func TestGetLatestPublicKeyReference(t *testing.T) {
	s := setupTestStore(t)

	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	pub := priv.Public()
	id, err := pub.ID()
	if err != nil {
		t.Fatalf("Failed to get public key ID: %v", err)
	}

	blockID := []byte("latest_block_id")

	err = s.UpdateLatestPublicKeyReference(id, blockID)
	if err != nil {
		t.Fatalf("Failed to update latest public key reference: %v", err)
	}

	retrieved, err := s.GetLatestPublicKeyReference(id)
	if err != nil {
		t.Fatalf("Failed to get latest public key reference: %v", err)
	}

	if !bytes.Equal(blockID, retrieved) {
		t.Fatal("Retrieved reference does not match expected")
	}
}

func TestGetStoredPublicKey(t *testing.T) {
	s := setupTestStore(t)

	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	pub := priv.Public()
	id, err := pub.ID()
	if err != nil {
		t.Fatalf("Failed to get public key ID: %v", err)
	}

	spk := certificates.NewStoredPublicKey(id, pub, time.Now())

	err = s.StorePublicKey(spk)
	if err != nil {
		t.Fatalf("Failed to store public key: %v", err)
	}

	blockID, err := pub.ID()
	if err != nil {
		t.Fatalf("Failed to get block ID: %v", err)
	}
	retrieved, err := s.GetStoredPublicKey(id, blockID)
	if err != nil {
		t.Fatalf("Failed to get stored public key: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Retrieved stored public key is nil")
	}

	retrievedPub := retrieved.GetPublicKey()
	retrievedID, err := retrievedPub.ID()
	if err != nil {
		t.Fatalf("Failed to get retrieved public key ID: %v", err)
	}
	if !bytes.Equal(id, retrievedID) {
		t.Fatal("Stored and retrieved public key IDs do not match")
	}
}

func TestDeleteStoredPublicKey(t *testing.T) {
	s := setupTestStore(t)

	priv, err := certificates.NewPrivate(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	pub := priv.Public()
	id, err := pub.ID()
	if err != nil {
		t.Fatalf("Failed to get public key ID: %v", err)
	}

	spk := certificates.NewStoredPublicKey(id, pub, time.Now())

	err = s.StorePublicKey(spk)
	if err != nil {
		t.Fatalf("Failed to store public key: %v", err)
	}

	err = s.DeleteStoredPublicKey(id)
	if err != nil {
		t.Fatalf("Failed to delete stored public key: %v", err)
	}

	// Try to get it back - should fail or return nil
	blockID, err := pub.ID()
	if err != nil {
		t.Fatalf("Failed to get block ID: %v", err)
	}
	_, err = s.GetStoredPublicKey(id, blockID)
	if err == nil {
		t.Fatal("Expected error when getting deleted public key, but got none")
	}
}
