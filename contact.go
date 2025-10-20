package kademlia

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type Contact struct {
	ID        []byte
	PublicKey []byte
	Host      string
	Port      int
}

func (c *Contact) Marshal() []byte {
	buffer := bytes.NewBuffer(nil)
	temp := [8]byte{}
	binary.BigEndian.PutUint32(temp[:4], uint32(len(c.ID)))
	buffer.Write(temp[:4])
	buffer.Write(c.ID)

	binary.BigEndian.PutUint32(temp[:4], uint32(len(c.PublicKey)))
	buffer.Write(temp[:4])
	buffer.Write(c.PublicKey)

	binary.BigEndian.PutUint32(temp[:4], uint32(len(c.Host)))
	buffer.Write(temp[:4])
	buffer.Write([]byte(c.Host))

	binary.BigEndian.PutUint32(temp[:4], uint32(c.Port))
	buffer.Write(temp[:4])

	return buffer.Bytes()
}

func (c *Contact) Unmarshal(data []byte) error {
	buffer := bytes.NewBuffer(data)
	temp := make([]byte, 4)

	if _, err := buffer.Read(temp); err != nil {
		return fmt.Errorf("failed to read ID length: %w", err)
	}
	idLen := binary.BigEndian.Uint32(temp)

	c.ID = make([]byte, idLen)
	if _, err := buffer.Read(c.ID); err != nil {
		return fmt.Errorf("failed to read ID: %w", err)
	}

	if _, err := buffer.Read(temp); err != nil {
		return fmt.Errorf("failed to read PublicKey length: %w", err)
	}
	pubKeyLen := binary.BigEndian.Uint32(temp)

	c.PublicKey = make([]byte, pubKeyLen)
	if _, err := buffer.Read(c.PublicKey); err != nil {
		return fmt.Errorf("failed to read PublicKey: %w", err)
	}

	if _, err := buffer.Read(temp); err != nil {
		return fmt.Errorf("failed to read Host length: %w", err)
	}
	hostLen := binary.BigEndian.Uint32(temp)

	hostBytes := make([]byte, hostLen)
	if _, err := buffer.Read(hostBytes); err != nil {
		return fmt.Errorf("failed to read Host: %w", err)
	}
	c.Host = string(hostBytes)

	if _, err := buffer.Read(temp); err != nil {
		return fmt.Errorf("failed to read Port: %w", err)
	}
	c.Port = int(binary.BigEndian.Uint32(temp))

	return nil
}
