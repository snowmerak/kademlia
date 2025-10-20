package kademlia

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/snowmerak/kademlia/rpc"
	"google.golang.org/protobuf/proto"
)

// Session represents an encrypted connection with a peer node
type Session struct {
	router          *Router
	conn            net.Conn
	remoteID        []byte
	remoteAddr      string
	remotePublicKey []byte
	remoteListenPort int // The port the remote peer is listening on
	encryptor       Encryptor
	sharedSecret    []byte
	writeMu         sync.Mutex
	readMu          sync.Mutex
	lastActivity    time.Time
	activityMu      sync.RWMutex
	closed          bool
	closeMu         sync.Mutex

	// Response callbacks for async RPC
	responseCallbacks *ConcurrentMap[string, func([]byte, error)]
}

// HandshakeMessage represents the initial key exchange message
type HandshakeMessage struct {
	NodeID      []byte
	PublicKey   []byte
	Timestamp   int64
	ListenPort  int // The port this node is listening on for incoming connections
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

	// ListenPort
	binary.BigEndian.PutUint32(temp[:4], uint32(h.ListenPort))
	buf.Write(temp[:4])

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

	// Read ListenPort
	if _, err := buf.Read(temp[:4]); err != nil {
		return fmt.Errorf("failed to read ListenPort: %w", err)
	}
	h.ListenPort = int(binary.BigEndian.Uint32(temp[:4]))

	return nil
}

// InitiateSession initiates a connection and performs key exchange as client
func InitiateSession(
	conn net.Conn,
	router *Router,
) (*Session, error) {
	log.Printf("[InitiateSession] Starting handshake with %s", conn.RemoteAddr())
	localID := router.ID()
	localPublicKey, err := router.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Send our handshake message
	handshake := &HandshakeMessage{
		NodeID:     localID,
		PublicKey:  localPublicKey,
		Timestamp:  time.Now().Unix(),
		ListenPort: router.listenAddr.Port,
	}

	log.Printf("[InitiateSession] Sending handshake: NodeID=%x, PublicKey=%x, ListenPort=%d", handshake.NodeID, handshake.PublicKey, handshake.ListenPort)
	
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

	log.Printf("[InitiateSession] Received peer handshake: NodeID=%x, PublicKey=%x, ListenPort=%d", peerHandshake.NodeID, peerHandshake.PublicKey, peerHandshake.ListenPort)

	// Compute shared secret using Router's Handshake method
	sharedSecret, err := router.Handshake(peerHandshake.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	log.Printf("[InitiateSession] Computed shared secret: %x", sharedSecret)

	// Create encryptor
	encryptor, err := NewXChaCha20Poly1305(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	return &Session{
		router:            router,
		conn:              conn,
		remoteID:          peerHandshake.NodeID,
		remoteAddr:        conn.RemoteAddr().String(),
		remotePublicKey:   peerHandshake.PublicKey,
		remoteListenPort:  peerHandshake.ListenPort,
		encryptor:         encryptor,
		sharedSecret:      sharedSecret,
		lastActivity:      time.Now(),
		closed:            false,
		responseCallbacks: NewConcurrentMap[string, func([]byte, error)](),
	}, nil
}

// AcceptSession accepts a connection and performs key exchange as server
func AcceptSession(
	conn net.Conn,
	router *Router,
) (*Session, error) {
	log.Printf("[AcceptSession] Starting handshake with %s", conn.RemoteAddr())
	
	// Receive peer's handshake message first
	peerHandshakeData, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive handshake: %w", err)
	}

	var peerHandshake HandshakeMessage
	if err := peerHandshake.Unmarshal(peerHandshakeData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal peer handshake: %w", err)
	}
	
	log.Printf("[AcceptSession] Received peer handshake: NodeID=%x, PublicKey=%x, ListenPort=%d", peerHandshake.NodeID, peerHandshake.PublicKey, peerHandshake.ListenPort)

	localID := router.ID()
	localPublicKey, err := router.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Send our handshake message
	handshake := &HandshakeMessage{
		NodeID:     localID,
		PublicKey:  localPublicKey,
		Timestamp:  time.Now().Unix(),
		ListenPort: router.listenAddr.Port,
	}

	log.Printf("[AcceptSession] Sending handshake: NodeID=%x, PublicKey=%x, ListenPort=%d", handshake.NodeID, handshake.PublicKey, handshake.ListenPort)

	handshakeData := handshake.Marshal()
	if err := writeFrame(conn, handshakeData); err != nil {
		return nil, fmt.Errorf("failed to send handshake: %w", err)
	}

	// Compute shared secret using Router's Handshake method
	sharedSecret, err := router.Handshake(peerHandshake.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	log.Printf("[AcceptSession] Computed shared secret: %x", sharedSecret)

	// Create encryptor
	encryptor, err := NewXChaCha20Poly1305(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	return &Session{
		router:            router,
		conn:              conn,
		remoteID:          peerHandshake.NodeID,
		remoteAddr:        conn.RemoteAddr().String(),
		remotePublicKey:   peerHandshake.PublicKey,
		remoteListenPort:  peerHandshake.ListenPort,
		encryptor:         encryptor,
		sharedSecret:      sharedSecret,
		lastActivity:      time.Now(),
		closed:            false,
		responseCallbacks: NewConcurrentMap[string, func([]byte, error)](),
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
		// Connection error - close session and remove from map
		go s.Close()
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
		// Connection error - close session and remove from map
		go s.Close()
		return nil, fmt.Errorf("failed to receive frame: %w", err)
	}

	// Decrypt the message
	decrypted, err := s.encryptor.Decrypt(encrypted)
	if err != nil {
		// Decryption error - close session and remove from map
		go s.Close()
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

// RemoteListenPort returns the port the peer is listening on
func (s *Session) RemoteListenPort() int {
	return s.remoteListenPort
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

// Close closes the session and underlying connection, and removes it from the router's session map
func (s *Session) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true

	// Remove from router's session map
	if s.router != nil {
		s.router.sessions.Delete(string(s.remoteID))
	}

	// Close the underlying connection
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

// HandleIncoming handles incoming RPC messages from the peer
func (s *Session) HandleIncoming() {
	for {
		data, err := s.ReceiveMessage()
		if err != nil {
			log.Printf("[Session] HandleIncoming error from %x: %v", s.RemoteID(), err)
			// Connection closed or error - ReceiveMessage already called Close()
			// Notify all pending callbacks with error
			callbackCount := 0
			s.responseCallbacks.Range(func(msgID string, callback func([]byte, error)) bool {
				callbackCount++
				callback(nil, fmt.Errorf("connection closed"))
				return true
			})
			log.Printf("[Session] Notified %d pending callbacks about connection closed", callbackCount)
			return
		}

		// RPC type is first 4 bytes (uint32)
		if len(data) < 4 {
			log.Printf("[Session] Message too short from %x: %d bytes", s.RemoteID(), len(data))
			continue
		}

		rpcType := binary.BigEndian.Uint32(data[:4])
		payload := data[4:]

		// Try to extract message ID to check if this is a response
		messageID := s.extractMessageID(rpcType, payload)
		log.Printf("[Session] Received message type=%d, msgID=%s from %x", rpcType, messageID, s.RemoteID())
		if messageID != "" {
			// Check if we have a callback waiting for this message
			if callback, ok := s.responseCallbacks.Load(messageID); ok {
				// This is a response - invoke callback and remove from map
				s.responseCallbacks.Delete(messageID)
				callback(data, nil)
				continue
			}
		}

		// This is a request - route to handler
		response, err := s.router.HandleRPC(s, rpcType, payload)
		if err != nil {
			log.Printf("[Session] RPC error from %x: %v", s.RemoteID(), err)
			continue
		}

		// Send response
		if response != nil {
			if err := s.SendMessage(response); err != nil {
				log.Printf("[Session] Failed to send RPC response: %v", err)
				return
			}
		}
	}
}

// extractMessageID extracts message ID from RPC payload based on type
func (s *Session) extractMessageID(rpcType uint32, payload []byte) string {
	switch rpcType {
	case RPCTypePing:
		var msg rpc.PingResponse
		if err := proto.Unmarshal(payload, &msg); err == nil && msg.Header != nil {
			return string(msg.Header.MessageId)
		}
	case RPCTypeFindNode:
		var msg rpc.FindNodeResponse
		if err := proto.Unmarshal(payload, &msg); err == nil && msg.Header != nil {
			return string(msg.Header.MessageId)
		}
	}
	return ""
}

// RegisterResponseCallback registers a callback for a specific message ID
func (s *Session) RegisterResponseCallback(messageID string, callback func([]byte, error)) {
	s.responseCallbacks.Store(messageID, callback)
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
