package kademlia

import (
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/snowmerak/kademlia/rpc"
	"google.golang.org/protobuf/proto"
)

// RPC type constants (uint32)
const (
	RPCTypePing     uint32 = 1
	RPCTypeFindNode uint32 = 2
)

// HandleRPC routes incoming RPC messages to appropriate handlers
func (r *Router) HandleRPC(sess *Session, rpcType uint32, payload []byte) ([]byte, error) {
	switch rpcType {
	case RPCTypePing:
		return r.handlePing(sess, payload)
	case RPCTypeFindNode:
		return r.handleFindNode(sess, payload)
	default:
		// Check for custom handlers
		if handler, ok := r.customHandlers.Load(rpcType); ok {
			// For custom RPCs (type > 2), extract messageID and pass only the actual payload
			if rpcType > 2 && len(payload) >= 16 {
				messageID := payload[:16]
				actualPayload := payload[16:]
				
				// Call the handler with actual payload
				respPayload, err := handler(sess, actualPayload)
				if err != nil {
					return nil, err
				}
				
				// Build response: [4-byte rpcType][16-byte messageID][respPayload]
				result := make([]byte, 4+16+len(respPayload))
				binary.BigEndian.PutUint32(result[:4], rpcType)
				copy(result[4:20], messageID)
				copy(result[20:], respPayload)
				return result, nil
			}
			return handler(sess, payload)
		}
		return nil, fmt.Errorf("unknown RPC type: %d", rpcType)
	}
}

// handlePing processes PING requests
func (r *Router) handlePing(sess *Session, payload []byte) ([]byte, error) {
	var req rpc.PingRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ping request: %w", err)
	}

	log.Printf("[RPC] PING from %x", sess.RemoteID())

	pubKey, err := r.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	resp := &rpc.PingResponse{
		Header: &rpc.RPCHeader{
			MessageId:  req.Header.MessageId,
			SenderId:   r.ID(),
			SenderAddr: r.listenAddr.String(),
			Timestamp:  time.Now().UnixMilli(),
		},
		PublicKey: pubKey,
	}

	respData, err := proto.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ping response: %w", err)
	}

	// Add RPC type prefix (4 bytes)
	result := make([]byte, 4+len(respData))
	binary.BigEndian.PutUint32(result[:4], RPCTypePing)
	copy(result[4:], respData)

	return result, nil
}

// handleFindNode processes FIND_NODE requests
func (r *Router) handleFindNode(sess *Session, payload []byte) ([]byte, error) {
	var req rpc.FindNodeRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal find_node request: %w", err)
	}

	log.Printf("[RPC] FIND_NODE from %x, target=%x", sess.RemoteID(), req.TargetId)

	// Find k closest nodes
	contacts, err := r.FindNearbyNodes(req.TargetId, r.kBucketCount)
	if err != nil {
		return nil, fmt.Errorf("failed to find nearby nodes: %w", err)
	}

	// Convert to protobuf Contact
	pbContacts := make([]*rpc.Contact, len(contacts))
	for i, c := range contacts {
		pbContacts[i] = &rpc.Contact{
			Id:        c.ID,
			PublicKey: c.PublicKey,
			Host:      c.Host,
			Port:      int32(c.Port),
		}
	}

	resp := &rpc.FindNodeResponse{
		Header: &rpc.RPCHeader{
			MessageId:  req.Header.MessageId,
			SenderId:   r.ID(),
			SenderAddr: r.listenAddr.String(),
			Timestamp:  time.Now().UnixMilli(),
		},
		Contacts: pbContacts,
	}

	respData, err := proto.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal find_node response: %w", err)
	}

	// Add RPC type prefix (4 bytes)
	result := make([]byte, 4+len(respData))
	binary.BigEndian.PutUint32(result[:4], RPCTypeFindNode)
	copy(result[4:], respData)

	return result, nil
}
