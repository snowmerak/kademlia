package kademlia

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Session represents an encrypted connection with a peer node
type Session struct {
	conn         net.Conn
	remoteID     []byte
	remoteAddr   string
	remotePublicKey []byte
	encryptor    Encryptor
	sharedSecret []byte
	writeMu      sync.Mutex
	readMu       sync.Mutex
	lastActivity time.Time
	activityMu   sync.RWMutex
	closed       bool
	closeMu      sync.Mutex
}

// HandshakeMessage represents the initial key exchange message
type HandshakeMessage struct {
	NodeID    []byte
	PublicKey []byte
	Timestamp int64
}

// Marshal serializes the handshake message
func (h *HandshakeMessage) Marshal() []byte {
	buf := bytes.NewBuffer(nil)
	temp := make([]byte, 8)

	// NodeID length + data
	binary.BigEndian.PutUint32(temp[:4], uint32(len(h.NodeID)))
	buf.Write(temp[:4])
	buf.Write(h.NodeID)

	// PublicKey length + data
	binary.BigEndian.PutUint32(temp[:4], uint32(len(h.PublicKey)))
	buf.Write(temp[:4])
	buf.Write(h.PublicKey)

	// Timestamp
	binary.BigEndian.PutUint64(temp, uint64(h.Timestamp))
	buf.Write(temp)

	return buf.Bytes()
}

// Unmarshal deserializes the handshake message
func (h *HandshakeMessage) Unmarshal(data []byte) error {
	buf := bytes.NewReader(data)
	temp := make([]byte, 8)

	// Read NodeID
	if _, err := buf.Read(temp[:4]); err != nil {
		return fmt.Errorf("failed to read NodeID length: %w", err)
	}
	nodeIDLen := binary.BigEndian.Uint32(temp[:4])
	h.NodeID = make([]byte, nodeIDLen)
	if _, err := buf.Read(h.NodeID); err != nil {
		return fmt.Errorf("failed to read NodeID: %w", err)
	}

	// Read PublicKey
	if _, err := buf.Read(temp[:4]); err != nil {
		return fmt.Errorf("failed to read PublicKey length: %w", err)
	}
	pubKeyLen := binary.BigEndian.Uint32(temp[:4])
	h.PublicKey = make([]byte, pubKeyLen)
	if _, err := buf.Read(h.PublicKey); err != nil {
		return fmt.Errorf("failed to read PublicKey: %w", err)
	}

	// Read Timestamp
	if _, err := buf.Read(temp); err != nil {
		return fmt.Errorf("failed to read Timestamp: %w", err)
	}
	h.Timestamp = int64(binary.BigEndian.Uint64(temp))

	return nil
}

// InitiateSession initiates a connection and performs key exchange as client
func InitiateSession(
	conn net.Conn,
	router *Router,
) (*Session, error) {
	localID := router.ID()
	localPublicKey, err := router.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Send our handshake message
	handshake := &HandshakeMessage{
		NodeID:    localID,
		PublicKey: localPublicKey,
		Timestamp: time.Now().Unix(),
	}

	handshakeData := handshake.Marshal()
	if err := writeFrame(conn, handshakeData); err != nil {
		return nil, fmt.Errorf("failed to send handshake: %w", err)
	}

	// Receive peer's handshake message
	peerHandshakeData, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive handshake: %w", err)
	}

	var peerHandshake HandshakeMessage
	if err := peerHandshake.Unmarshal(peerHandshakeData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal peer handshake: %w", err)
	}

	// Compute shared secret using Router's Handshake method
	sharedSecret, err := router.Handshake(peerHandshake.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Create encryptor
	encryptor, err := NewXChaCha20Poly1305(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	return &Session{
		conn:            conn,
		remoteID:        peerHandshake.NodeID,
		remoteAddr:      conn.RemoteAddr().String(),
		remotePublicKey: peerHandshake.PublicKey,
		encryptor:       encryptor,
		sharedSecret:    sharedSecret,
		lastActivity:    time.Now(),
		closed:          false,
	}, nil
}

// AcceptSession accepts a connection and performs key exchange as server
func AcceptSession(
	conn net.Conn,
	router *Router,
) (*Session, error) {
	// Receive peer's handshake message first
	peerHandshakeData, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive handshake: %w", err)
	}

	var peerHandshake HandshakeMessage
	if err := peerHandshake.Unmarshal(peerHandshakeData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal peer handshake: %w", err)
	}

	localID := router.ID()
	localPublicKey, err := router.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Send our handshake message
	handshake := &HandshakeMessage{
		NodeID:    localID,
		PublicKey: localPublicKey,
		Timestamp: time.Now().Unix(),
	}

	handshakeData := handshake.Marshal()
	if err := writeFrame(conn, handshakeData); err != nil {
		return nil, fmt.Errorf("failed to send handshake: %w", err)
	}

	// Compute shared secret using Router's Handshake method
	sharedSecret, err := router.Handshake(peerHandshake.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Create encryptor
	encryptor, err := NewXChaCha20Poly1305(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	return &Session{
		conn:            conn,
		remoteID:        peerHandshake.NodeID,
		remoteAddr:      conn.RemoteAddr().String(),
		remotePublicKey: peerHandshake.PublicKey,
		encryptor:       encryptor,
		sharedSecret:    sharedSecret,
		lastActivity:    time.Now(),
		closed:          false,
	}, nil
}

// SendMessage sends an encrypted message to the peer
func (s *Session) SendMessage(data []byte) error {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return fmt.Errorf("session is closed")
	}
	s.closeMu.Unlock()

	// Encrypt the message
	encrypted, err := s.encryptor.Encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %w", err)
	}

	// Send the encrypted frame
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := writeFrame(s.conn, encrypted); err != nil {
		return fmt.Errorf("failed to send frame: %w", err)
	}

	s.updateActivity()
	return nil
}

// ReceiveMessage receives and decrypts a message from the peer
func (s *Session) ReceiveMessage() ([]byte, error) {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return nil, fmt.Errorf("session is closed")
	}
	s.closeMu.Unlock()

	// Receive the encrypted frame
	s.readMu.Lock()
	defer s.readMu.Unlock()

	encrypted, err := readFrame(s.conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive frame: %w", err)
	}

	// Decrypt the message
	decrypted, err := s.encryptor.Decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	s.updateActivity()
	return decrypted, nil
}

// RemoteID returns the peer's node ID
func (s *Session) RemoteID() []byte {
	id := make([]byte, len(s.remoteID))
	copy(id, s.remoteID)
	return id
}

// RemoteAddr returns the peer's address
func (s *Session) RemoteAddr() string {
	return s.remoteAddr
}

// PublicKey returns the peer's public key
func (s *Session) PublicKey() []byte {
	key := make([]byte, len(s.remotePublicKey))
	copy(key, s.remotePublicKey)
	return key
}

// LastActivity returns the time of last activity
func (s *Session) LastActivity() time.Time {
	s.activityMu.RLock()
	defer s.activityMu.RUnlock()
	return s.lastActivity
}

// Close closes the session and underlying connection
func (s *Session) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	return s.conn.Close()
}

// IsClosed returns whether the session is closed
func (s *Session) IsClosed() bool {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closed
}

// updateActivity updates the last activity timestamp
func (s *Session) updateActivity() {
	s.activityMu.Lock()
	defer s.activityMu.Unlock()
	s.lastActivity = time.Now()
}

// writeFrame writes a length-prefixed frame to the connection
func writeFrame(conn net.Conn, data []byte) error {
	// Write length prefix (4 bytes)
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))

	if _, err := conn.Write(lengthBuf); err != nil {
		return fmt.Errorf("failed to write frame length: %w", err)
	}

	// Write data
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to write frame data: %w", err)
	}

	return nil
}

// readFrame reads a length-prefixed frame from the connection
func readFrame(conn net.Conn) ([]byte, error) {
	// Read length prefix (4 bytes)
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("failed to read frame length: %w", err)
	}

	length := binary.BigEndian.Uint32(lengthBuf)

	// Sanity check: prevent excessive memory allocation
	if length > 100*1024*1024 { // 100MB max
		return nil, fmt.Errorf("frame too large: %d bytes", length)
	}

	// Read data
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("failed to read frame data: %w", err)
	}

	return data, nil
}
