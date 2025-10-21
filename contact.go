package kademlia

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type Contact struct {
	ID        []byte
	PublicKey []byte
	Addrs     []string // Network addresses (e.g., "/ip4/127.0.0.1/tcp/4001" for libp2p)
}

func (c *Contact) Marshal() []byte {
	buffer := bytes.NewBuffer(nil)
	temp := [8]byte{}
	
	// Marshal ID
	binary.BigEndian.PutUint32(temp[:4], uint32(len(c.ID)))
	buffer.Write(temp[:4])
	buffer.Write(c.ID)

	// Marshal PublicKey
	binary.BigEndian.PutUint32(temp[:4], uint32(len(c.PublicKey)))
	buffer.Write(temp[:4])
	buffer.Write(c.PublicKey)

	// Marshal Addrs (length + each addr)
	binary.BigEndian.PutUint32(temp[:4], uint32(len(c.Addrs)))
	buffer.Write(temp[:4])
	
	for _, addr := range c.Addrs {
		addrBytes := []byte(addr)
		binary.BigEndian.PutUint32(temp[:4], uint32(len(addrBytes)))
		buffer.Write(temp[:4])
		buffer.Write(addrBytes)
	}

	return buffer.Bytes()
}

func (c *Contact) Unmarshal(data []byte) error {
	buffer := bytes.NewBuffer(data)
	temp := make([]byte, 4)

	// Unmarshal ID
	if _, err := buffer.Read(temp); err != nil {
		return fmt.Errorf("failed to read ID length: %w", err)
	}
	idLen := binary.BigEndian.Uint32(temp)

	c.ID = make([]byte, idLen)
	if _, err := buffer.Read(c.ID); err != nil {
		return fmt.Errorf("failed to read ID: %w", err)
	}

	// Unmarshal PublicKey
	if _, err := buffer.Read(temp); err != nil {
		return fmt.Errorf("failed to read PublicKey length: %w", err)
	}
	pubKeyLen := binary.BigEndian.Uint32(temp)

	c.PublicKey = make([]byte, pubKeyLen)
	if _, err := buffer.Read(c.PublicKey); err != nil {
		return fmt.Errorf("failed to read PublicKey: %w", err)
	}

	// Unmarshal Addrs
	if _, err := buffer.Read(temp); err != nil {
		return fmt.Errorf("failed to read Addrs length: %w", err)
	}
	addrsLen := binary.BigEndian.Uint32(temp)

	c.Addrs = make([]string, addrsLen)
	for i := 0; i < int(addrsLen); i++ {
		if _, err := buffer.Read(temp); err != nil {
			return fmt.Errorf("failed to read addr[%d] length: %w", i, err)
		}
		addrLen := binary.BigEndian.Uint32(temp)

		addrBytes := make([]byte, addrLen)
		if _, err := buffer.Read(addrBytes); err != nil {
			return fmt.Errorf("failed to read addr[%d]: %w", i, err)
		}
		c.Addrs[i] = string(addrBytes)
	}

	return nil
}
