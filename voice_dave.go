// Discordgo - Discord bindings for Go
// Available at https://github.com/bwmarrin/discordgo

// Copyright 2015-2016 Bruce Marriner <bruce@sqls.net>.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file contains the DAVE (Discord Audio/Video Encryption) protocol
// support for voice connections.  DAVE provides end-to-end encryption (E2EE)
// on top of the existing transport encryption for Discord voice and video.
//
// See: https://daveprotocol.com/

package discordgo

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/disgoorg/godave"
	"github.com/gorilla/websocket"
)

// Compile-time assertion: VoiceConnection must satisfy godave.Callbacks.
var _ godave.Callbacks = (*VoiceConnection)(nil)

// ------------------------------------------------------------------------------------------------
// Binary DAVE voice gateway message handling (opcodes 25, 27, 29, 30)
// ------------------------------------------------------------------------------------------------

// onBinaryEvent handles binary WebSocket messages from the voice gateway.
// Binary messages are used for DAVE MLS key-exchange opcodes.
//
// The wire format for gateway→client binary messages is:
//
//	[2 bytes: sequence number][1 byte: opcode][rest: opcode-specific payload]
func (v *VoiceConnection) onBinaryEvent(data []byte) {
	if len(data) < 3 {
		v.log(LogWarning, "received binary voice message too short (%d bytes)", len(data))
		return
	}

	// seq := binary.BigEndian.Uint16(data[:2])  // sequence number (unused for now)
	opcode := data[2]
	payload := data[3:]

	v.log(LogDebug, "received binary voice opcode %d (%d payload bytes)", opcode, len(payload))

	switch opcode {

	case 25: // dave_mls_external_sender_package
		// Payload: ExternalSender (raw MLS struct)
		v.RLock()
		dave := v.dave
		v.RUnlock()
		if dave != nil {
			dave.OnDaveMLSExternalSenderPackage(payload)
		}

	case 27: // dave_mls_proposals
		// Payload: ProposalsOperationType + proposals/refs
		v.RLock()
		dave := v.dave
		v.RUnlock()
		if dave != nil {
			dave.OnDaveMLSProposals(payload)
		}

	case 29: // dave_mls_announce_commit_transition
		// Payload: [2 bytes: transition_id][rest: MLSMessage commit]
		if len(payload) < 2 {
			v.log(LogWarning, "OP29 payload too short")
			return
		}
		transitionID := binary.BigEndian.Uint16(payload[:2])
		commitMsg := payload[2:]

		v.RLock()
		dave := v.dave
		v.RUnlock()
		if dave != nil {
			dave.OnDaveMLSPrepareCommitTransition(transitionID, commitMsg)
		}

	case 30: // dave_mls_welcome
		// Payload: [2 bytes: transition_id][rest: Welcome message]
		if len(payload) < 2 {
			v.log(LogWarning, "OP30 payload too short")
			return
		}
		transitionID := binary.BigEndian.Uint16(payload[:2])
		welcomeMsg := payload[2:]

		v.RLock()
		dave := v.dave
		v.RUnlock()
		if dave != nil {
			dave.OnDaveMLSWelcome(transitionID, welcomeMsg)
		}

	default:
		v.log(LogDebug, "unhandled binary voice opcode %d", opcode)
	}
}

// ------------------------------------------------------------------------------------------------
// godave.Callbacks implementation on VoiceConnection
// These are called by the DAVE session to send messages back to the voice gateway.
// ------------------------------------------------------------------------------------------------

// SendMLSKeyPackage sends an MLS Key Package to the voice gateway (OP 26, binary).
// This satisfies the godave.Callbacks interface.
func (v *VoiceConnection) SendMLSKeyPackage(mlsKeyPackage []byte) error {
	msg := make([]byte, 1+len(mlsKeyPackage))
	msg[0] = 26 // opcode
	copy(msg[1:], mlsKeyPackage)

	v.wsMutex.Lock()
	err := v.wsConn.WriteMessage(websocket.BinaryMessage, msg)
	v.wsMutex.Unlock()
	if err != nil {
		return fmt.Errorf("SendMLSKeyPackage: %w", err)
	}
	return nil
}

// SendMLSCommitWelcome sends an MLS Commit + Welcome to the voice gateway (OP 28, binary).
// This satisfies the godave.Callbacks interface.
func (v *VoiceConnection) SendMLSCommitWelcome(mlsCommitWelcome []byte) error {
	msg := make([]byte, 1+len(mlsCommitWelcome))
	msg[0] = 28 // opcode
	copy(msg[1:], mlsCommitWelcome)

	v.wsMutex.Lock()
	err := v.wsConn.WriteMessage(websocket.BinaryMessage, msg)
	v.wsMutex.Unlock()
	if err != nil {
		return fmt.Errorf("SendMLSCommitWelcome: %w", err)
	}
	return nil
}

// SendReadyForTransition notifies the voice gateway that the client is ready for
// a DAVE protocol transition (OP 23, JSON).
// This satisfies the godave.Callbacks interface.
func (v *VoiceConnection) SendReadyForTransition(transitionID uint16) error {
	type readyData struct {
		TransitionID uint16 `json:"transition_id"`
	}
	type readyOp struct {
		Op   int       `json:"op"` // Always 23
		Data readyData `json:"d"`
	}
	data, err := json.Marshal(readyOp{23, readyData{transitionID}})
	if err != nil {
		return fmt.Errorf("SendReadyForTransition marshal: %w", err)
	}

	v.wsMutex.Lock()
	err = v.wsConn.WriteMessage(websocket.TextMessage, data)
	v.wsMutex.Unlock()
	if err != nil {
		return fmt.Errorf("SendReadyForTransition: %w", err)
	}
	return nil
}

// SendInvalidCommitWelcome notifies the voice gateway that a received Commit or
// Welcome message was invalid (OP 31, JSON).
// This satisfies the godave.Callbacks interface.
func (v *VoiceConnection) SendInvalidCommitWelcome(transitionID uint16) error {
	type invalidData struct {
		TransitionID uint16 `json:"transition_id"`
	}
	type invalidOp struct {
		Op   int         `json:"op"` // Always 31
		Data invalidData `json:"d"`
	}
	data, err := json.Marshal(invalidOp{31, invalidData{transitionID}})
	if err != nil {
		return fmt.Errorf("SendInvalidCommitWelcome marshal: %w", err)
	}

	v.wsMutex.Lock()
	err = v.wsConn.WriteMessage(websocket.TextMessage, data)
	v.wsMutex.Unlock()
	if err != nil {
		return fmt.Errorf("SendInvalidCommitWelcome: %w", err)
	}
	return nil
}
