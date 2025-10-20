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

// SendPing sends a PING request to the peer with async callback
func (r *Router) SendPing(ctx context.Context, nodeID []byte, callback func([]byte, error)) error {
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

	// Register callback if provided
	if callback != nil {
		sess.RegisterResponseCallback(string(messageID[:]), callback)
		
		// Set timeout to clean up callback if no response
		go func() {
			<-ctx.Done()
			// If context is done and callback still exists, invoke with timeout error
			if cb, ok := sess.responseCallbacks.Load(string(messageID[:])); ok {
				sess.responseCallbacks.Delete(string(messageID[:]))
				cb(nil, fmt.Errorf("request timeout"))
			}
		}()
	}

	// Send request
	if err := sess.SendMessage(data); err != nil {
		return fmt.Errorf("failed to send ping: %w", err)
	}

	return nil
}

// SendFindNode sends a FIND_NODE request with async callback
func (r *Router) SendFindNode(ctx context.Context, nodeID []byte, targetID []byte, callback func([]*Contact, error)) error {
	sess, err := r.GetOrCreateSession(nodeID)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
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
		return fmt.Errorf("failed to marshal find_node request: %w", err)
	}

	// Add RPC type prefix (4 bytes)
	data := make([]byte, 4+len(reqData))
	binary.BigEndian.PutUint32(data[:4], RPCTypeFindNode)
	copy(data[4:], reqData)

	// Register callback if provided
	if callback != nil {
		sess.RegisterResponseCallback(string(messageID[:]), func(respData []byte, err error) {
			if err != nil {
				callback(nil, err)
				return
			}

			// Parse response
			if len(respData) < 4 {
				callback(nil, fmt.Errorf("response too short"))
				return
			}

			respType := binary.BigEndian.Uint32(respData[:4])
			if respType != RPCTypeFindNode {
				callback(nil, fmt.Errorf("unexpected response type: %d", respType))
				return
			}

			var resp rpc.FindNodeResponse
			if err := proto.Unmarshal(respData[4:], &resp); err != nil {
				callback(nil, fmt.Errorf("failed to unmarshal find_node response: %w", err))
				return
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

			callback(contacts, nil)
		})

		// Set timeout to clean up callback if no response
		go func() {
			<-ctx.Done()
			if cb, ok := sess.responseCallbacks.Load(string(messageID[:])); ok {
				sess.responseCallbacks.Delete(string(messageID[:]))
				cb(nil, fmt.Errorf("request timeout"))
			}
		}()
	}

	// Send request
	if err := sess.SendMessage(data); err != nil {
		return fmt.Errorf("failed to send find_node: %w", err)
	}

	return nil
}
