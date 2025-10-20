package kademlia

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/snowmerak/kademlia/rpc"
	"google.golang.org/protobuf/proto"
)

// SendPing sends a PING request to the peer and waits for response
func (r *Router) SendPing(ctx context.Context, nodeID []byte) error {
	sess, err := r.GetOrCreateSession(nodeID)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}
	messageID := uuid.New()

	pubKey, err := r.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	req := &rpc.PingRequest{
		Header: &rpc.RPCHeader{
			MessageId:  messageID[:],
			SenderId:   r.ID(),
			SenderAddr: r.listenAddr.String(),
			Timestamp:  time.Now().UnixMilli(),
		},
		PublicKey: pubKey,
	}

	reqData, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal ping request: %w", err)
	}

	// Add RPC type prefix (4 bytes)
	data := make([]byte, 4+len(reqData))
	binary.BigEndian.PutUint32(data[:4], RPCTypePing)
	copy(data[4:], reqData)

	// Send request
	if err := sess.SendMessage(data); err != nil {
		return fmt.Errorf("failed to send ping: %w", err)
	}

	// Wait for response
	respData, err := sess.ReceiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive ping response: %w", err)
	}

	// Parse response
	if len(respData) < 4 {
		return fmt.Errorf("response too short")
	}

	respType := binary.BigEndian.Uint32(respData[:4])
	if respType != RPCTypePing {
		return fmt.Errorf("unexpected response type: %d", respType)
	}

	var resp rpc.PingResponse
	if err := proto.Unmarshal(respData[4:], &resp); err != nil {
		return fmt.Errorf("failed to unmarshal ping response: %w", err)
	}

	// Verify message ID
	if string(resp.Header.MessageId) != string(messageID[:]) {
		return fmt.Errorf("message ID mismatch")
	}

	return nil
}

// SendFindNode sends a FIND_NODE request and returns the closest contacts
func (r *Router) SendFindNode(ctx context.Context, nodeID []byte, targetID []byte) ([]*Contact, error) {
	sess, err := r.GetOrCreateSession(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	messageID := uuid.New()

	req := &rpc.FindNodeRequest{
		Header: &rpc.RPCHeader{
			MessageId:  messageID[:],
			SenderId:   r.ID(),
			SenderAddr: r.listenAddr.String(),
			Timestamp:  time.Now().UnixMilli(),
		},
		TargetId: targetID,
	}

	reqData, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal find_node request: %w", err)
	}

	// Add RPC type prefix (4 bytes)
	data := make([]byte, 4+len(reqData))
	binary.BigEndian.PutUint32(data[:4], RPCTypeFindNode)
	copy(data[4:], reqData)

	// Send request
	if err := sess.SendMessage(data); err != nil {
		return nil, fmt.Errorf("failed to send find_node: %w", err)
	}

	// Wait for response
	respData, err := sess.ReceiveMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to receive find_node response: %w", err)
	}

	// Parse response
	if len(respData) < 4 {
		return nil, fmt.Errorf("response too short")
	}

	respType := binary.BigEndian.Uint32(respData[:4])
	if respType != RPCTypeFindNode {
		return nil, fmt.Errorf("unexpected response type: %d", respType)
	}

	var resp rpc.FindNodeResponse
	if err := proto.Unmarshal(respData[4:], &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal find_node response: %w", err)
	}

	// Verify message ID
	if string(resp.Header.MessageId) != string(messageID[:]) {
		return nil, fmt.Errorf("message ID mismatch")
	}

	// Convert protobuf contacts to Contact
	contacts := make([]*Contact, len(resp.Contacts))
	for i, pbContact := range resp.Contacts {
		contacts[i] = &Contact{
			ID:        pbContact.Id,
			PublicKey: pbContact.PublicKey,
			Host:      pbContact.Host,
			Port:      int(pbContact.Port),
		}
	}

	return contacts, nil
}
