package certificates

import (
	"crypto"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"lukechampine.com/blake3"
)

type Private struct {
	kx     *mlkem.DecapsulationKey1024
	sig    *mldsa87.PrivateKey
	public *Public
}

func NewPrivate(reader io.Reader) (*Private, error) {
	kx, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, fmt.Errorf("failed to generate KEM key: %w", err)
	}

	sigPub, sigPrive, err := mldsa87.GenerateKey(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signature key: %w", err)
	}

	return &Private{
		kx:  kx,
		sig: sigPrive,
		public: &Public{
			kx:  kx.EncapsulationKey(),
			sig: sigPub,
		},
	}, nil
}

type Public struct {
	kx  *mlkem.EncapsulationKey1024
	sig *mldsa87.PublicKey
}

func (p *Private) Public() *Public {
	return p.public
}

func (p *Public) MarshalBinary() ([]byte, error) {
	kxBytes := p.kx.Bytes()

	sigBytes, err := p.sig.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature key: %w", err)
	}

	result := make([]byte, 8+len(kxBytes)+len(sigBytes))
	binary.BigEndian.PutUint32(result[:4], uint32(len(kxBytes)))
	binary.BigEndian.PutUint32(result[4:8], uint32(len(sigBytes)))
	copy(result[8:8+len(kxBytes)], kxBytes)
	copy(result[8+len(kxBytes):], sigBytes)

	return result, nil
}

func (p *Public) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("data too short to unmarshal Public")
	}

	kxLen := binary.BigEndian.Uint32(data[:4])
	sigLen := binary.BigEndian.Uint32(data[4:8])

	if len(data) < int(8+kxLen+sigLen) {
		return fmt.Errorf("data too short to unmarshal Public keys")
	}

	kxBytes := data[8 : 8+kxLen]
	sigBytes := data[8+kxLen : 8+kxLen+sigLen]

	kx, err := mlkem.NewEncapsulationKey1024(kxBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal KEM key: %w", err)
	}

	sig := &mldsa87.PublicKey{}
	if err := sig.UnmarshalBinary(sigBytes); err != nil {
		return fmt.Errorf("failed to unmarshal signature key: %w", err)
	}

	p.kx = kx
	p.sig = sig

	return nil
}

func (p *Private) MarshalBinary() ([]byte, error) {
	kxBytes := p.kx.Bytes()

	sigBytes, err := p.sig.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature key: %w", err)
	}

	pubBytes, err := p.public.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	result := make([]byte, 12+len(kxBytes)+len(sigBytes)+len(pubBytes))
	binary.BigEndian.PutUint32(result[:4], uint32(len(kxBytes)))
	binary.BigEndian.PutUint32(result[4:8], uint32(len(sigBytes)))
	binary.BigEndian.PutUint32(result[8:12], uint32(len(pubBytes)))
	copy(result[12:12+len(kxBytes)], kxBytes)
	copy(result[12+len(kxBytes):12+len(kxBytes)+len(sigBytes)], sigBytes)
	copy(result[12+len(kxBytes)+len(sigBytes):], pubBytes)

	return result, nil
}

func (p *Private) UnmarshalBinary(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("data too short to unmarshal Private")
	}

	kxLen := binary.BigEndian.Uint32(data[:4])
	sigLen := binary.BigEndian.Uint32(data[4:8])
	pubLen := binary.BigEndian.Uint32(data[8:12])

	if len(data) < int(12+kxLen+sigLen+pubLen) {
		return fmt.Errorf("data too short to unmarshal Private keys")
	}

	kxBytes := data[12 : 12+kxLen]
	sigBytes := data[12+kxLen : 12+kxLen+sigLen]
	pubBytes := data[12+kxLen+sigLen : 12+kxLen+sigLen+pubLen]

	kx, err := mlkem.NewDecapsulationKey1024(kxBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal KEM key: %w", err)
	}

	sig := &mldsa87.PrivateKey{}
	if err := sig.UnmarshalBinary(sigBytes); err != nil {
		return fmt.Errorf("failed to unmarshal signature key: %w", err)
	}

	pub := &Public{}
	if err := pub.UnmarshalBinary(pubBytes); err != nil {
		return fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	p.kx = kx
	p.sig = sig
	p.public = pub

	return nil
}

func (p *Private) Decapsulate(ciphertext []byte) ([]byte, error) {
	sharedSecret, err := p.kx.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate ciphertext: %w", err)
	}

	return sharedSecret, nil
}

func (p *Public) Encapsulate() (sharedSecret []byte, cipherText []byte, err error) {
	sharedSecret, cipherText = p.kx.Encapsulate()

	return sharedSecret, cipherText, nil
}

func (p *Private) SignPublicKey() ([]byte, error) {
	pubBytes, err := p.public.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key for signing: %w", err)
	}

	signature, err := p.sig.Sign(rand.Reader, pubBytes, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("failed to sign public key: %w", err)
	}

	return signature, nil
}

func (p *Public) VerifySignature(signature []byte) error {
	pubBytes, err := p.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal public key for verification: %w", err)
	}

	if !p.sig.Scheme().Verify(p.sig, pubBytes, signature, nil) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func (p *Public) ID() ([]byte, error) {
	pubBytes, err := p.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key for ID generation: %w", err)
	}

	hashed := blake3.Sum512(pubBytes)
	return hashed[:], nil
}

func (p *Private) SignData(data []byte) ([]byte, error) {
	signature, err := p.sig.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signature, nil
}

func (p *Public) VerifyDataSignature(data, signature []byte) error {
	if !p.sig.Scheme().Verify(p.sig, data, signature, nil) {
		return fmt.Errorf("data signature verification failed")
	}

	return nil
}
