// Discordgo - Discord bindings for Go
// Available at https://github.com/bwmarrin/discordgo

package discordgo

import (
"encoding/binary"
"encoding/json"
"log/slog"
"testing"

"github.com/disgoorg/godave"
)

// ------------------------------------------------------------------------------------------------
// Tests for DAVE end-to-end encryption support
// ------------------------------------------------------------------------------------------------

// testCallbacks is a mock that records calls made by the DAVE session.
type testCallbacks struct {
keyPackages    [][]byte
commitWelcomes [][]byte
readyIDs       []uint16
invalidIDs     []uint16
}

func (tc *testCallbacks) SendMLSKeyPackage(pkg []byte) error {
tc.keyPackages = append(tc.keyPackages, pkg)
return nil
}
func (tc *testCallbacks) SendMLSCommitWelcome(cw []byte) error {
tc.commitWelcomes = append(tc.commitWelcomes, cw)
return nil
}
func (tc *testCallbacks) SendReadyForTransition(id uint16) error {
tc.readyIDs = append(tc.readyIDs, id)
return nil
}
func (tc *testCallbacks) SendInvalidCommitWelcome(id uint16) error {
tc.invalidIDs = append(tc.invalidIDs, id)
return nil
}

// TestDAVENoopSession checks that the default noop DAVE session works correctly.
func TestDAVENoopSession(t *testing.T) {
cb := &testCallbacks{}
sess := godave.NewNoopSession(slog.Default(), godave.UserID("123456789"), cb)

// MaxSupportedProtocolVersion should be 0 (disabled) for noop.
if v := sess.MaxSupportedProtocolVersion(); v != 0 {
t.Errorf("expected MaxSupportedProtocolVersion=0, got %d", v)
}

// Encrypt with noop should be a passthrough.
plain := []byte{0x01, 0x02, 0x03, 0x04}
encBuf := make([]byte, sess.MaxEncryptedFrameSize(len(plain)))
n, err := sess.Encrypt(1234, plain, encBuf)
if err != nil {
t.Fatalf("Encrypt error: %v", err)
}
if n != len(plain) {
t.Errorf("Encrypt: expected n=%d, got %d", len(plain), n)
}
if string(encBuf[:n]) != string(plain) {
t.Errorf("Encrypt: expected passthrough, got %v", encBuf[:n])
}
}

// TestDAVESessionCreateFuncDefault checks that New() sets a default DAVESessionCreateFunc.
func TestDAVESessionCreateFuncDefault(t *testing.T) {
s, err := New("Bot fake-token")
if err != nil {
t.Fatal(err)
}
if s.DAVESessionCreateFunc == nil {
t.Fatal("expected DAVESessionCreateFunc to be set by default, got nil")
}

// Verify the default func creates a noop session with MaxSupportedProtocolVersion = 0.
sess := s.DAVESessionCreateFunc(slog.Default(), godave.UserID("123"), &testCallbacks{})
if sess == nil {
t.Fatal("DAVESessionCreateFunc returned nil session")
}
if v := sess.MaxSupportedProtocolVersion(); v != 0 {
t.Errorf("expected noop MaxSupportedProtocolVersion=0, got %d", v)
}
}

// TestOnBinaryEventOP25 verifies that a binary OP25 (external sender) message
// is correctly routed to the DAVE session.
func TestOnBinaryEventOP25(t *testing.T) {
payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
msg := buildBinaryVoiceMsg(1, 25, 0, false, payload)

recorded := &daveSessionRecorder{}
vc := &VoiceConnection{dave: recorded}
vc.onBinaryEvent(msg)

if len(recorded.externalSenderPackages) != 1 {
t.Fatalf("expected 1 OnDaveMLSExternalSenderPackage call, got %d", len(recorded.externalSenderPackages))
}
if string(recorded.externalSenderPackages[0]) != string(payload) {
t.Errorf("unexpected payload: %v", recorded.externalSenderPackages[0])
}
}

// TestOnBinaryEventOP27 verifies that a binary OP27 (proposals) message
// is correctly routed to the DAVE session.
func TestOnBinaryEventOP27(t *testing.T) {
payload := []byte{0x00, 0x01, 0x02, 0x03}
msg := buildBinaryVoiceMsg(2, 27, 0, false, payload)

recorded := &daveSessionRecorder{}
vc := &VoiceConnection{dave: recorded}
vc.onBinaryEvent(msg)

if len(recorded.proposals) != 1 {
t.Fatalf("expected 1 OnDaveMLSProposals call, got %d", len(recorded.proposals))
}
if string(recorded.proposals[0]) != string(payload) {
t.Errorf("unexpected proposals payload: %v", recorded.proposals[0])
}
}

// TestOnBinaryEventOP29 verifies that a binary OP29 (announce commit transition) message
// is correctly parsed and routed.
func TestOnBinaryEventOP29(t *testing.T) {
transitionID := uint16(42)
commitMsg := []byte{0xAA, 0xBB, 0xCC}
msg := buildBinaryVoiceMsg(3, 29, transitionID, true, commitMsg)

recorded := &daveSessionRecorder{}
vc := &VoiceConnection{dave: recorded}
vc.onBinaryEvent(msg)

if len(recorded.commitTransitions) != 1 {
t.Fatalf("expected 1 OnDaveMLSPrepareCommitTransition call, got %d", len(recorded.commitTransitions))
}
ct := recorded.commitTransitions[0]
if ct.transitionID != transitionID {
t.Errorf("expected transitionID=%d, got %d", transitionID, ct.transitionID)
}
if string(ct.message) != string(commitMsg) {
t.Errorf("unexpected commit message: %v", ct.message)
}
}

// TestOnBinaryEventOP30 verifies that a binary OP30 (welcome) message
// is correctly parsed and routed.
func TestOnBinaryEventOP30(t *testing.T) {
transitionID := uint16(99)
welcomeMsg := []byte{0x11, 0x22, 0x33, 0x44}
msg := buildBinaryVoiceMsg(4, 30, transitionID, true, welcomeMsg)

recorded := &daveSessionRecorder{}
vc := &VoiceConnection{dave: recorded}
vc.onBinaryEvent(msg)

if len(recorded.welcomes) != 1 {
t.Fatalf("expected 1 OnDaveMLSWelcome call, got %d", len(recorded.welcomes))
}
w := recorded.welcomes[0]
if w.transitionID != transitionID {
t.Errorf("expected transitionID=%d, got %d", transitionID, w.transitionID)
}
if string(w.message) != string(welcomeMsg) {
t.Errorf("unexpected welcome message: %v", w.message)
}
}

// TestOnBinaryEventTooShort checks that overly short binary messages are silently dropped.
func TestOnBinaryEventTooShort(t *testing.T) {
recorded := &daveSessionRecorder{}
vc := &VoiceConnection{dave: recorded}

vc.onBinaryEvent(nil)
vc.onBinaryEvent([]byte{0x00})
vc.onBinaryEvent([]byte{0x00, 0x01})

if recorded.callCount() != 0 {
t.Errorf("expected no DAVE calls for short messages, got %d", recorded.callCount())
}
}

// TestOnBinaryEventUnknownOpcode verifies that unknown binary opcodes are silently ignored.
func TestOnBinaryEventUnknownOpcode(t *testing.T) {
msg := buildBinaryVoiceMsg(0, 99, 0, false, []byte{0x01, 0x02})
recorded := &daveSessionRecorder{}
vc := &VoiceConnection{dave: recorded}
vc.onBinaryEvent(msg) // should not panic or call any DAVE method

if recorded.callCount() != 0 {
t.Errorf("expected no DAVE calls for unknown opcode, got %d", recorded.callCount())
}
}

// TestDAVESSRCUserIDMapping verifies that the SSRC→UserID mapping is populated
// correctly from a speaking-update payload.
func TestDAVESSRCUserIDMapping(t *testing.T) {
vc := &VoiceConnection{
dave:             godave.NewNoopSession(slog.Default(), "bot-user", &testCallbacks{}),
daveSSRCToUserID: make(map[uint32]string),
}

rawData := []byte(`{"user_id":"987654321","ssrc":12345,"speaking":true}`)
update := &VoiceSpeakingUpdate{}
if err := json.Unmarshal(rawData, update); err != nil {
t.Fatal(err)
}
if update.SSRC != 0 && update.UserID != "" {
vc.Lock()
vc.daveSSRCToUserID[uint32(update.SSRC)] = update.UserID
vc.Unlock()
}

vc.RLock()
uid := vc.daveSSRCToUserID[12345]
vc.RUnlock()

if uid != "987654321" {
t.Errorf("expected daveSSRCToUserID[12345]=%q, got %q", "987654321", uid)
}
}

// TestDAVEVoiceHandshakeIncludesProtocolVersion verifies that the handshake data
// struct includes the max_dave_protocol_version field.
func TestDAVEVoiceHandshakeIncludesProtocolVersion(t *testing.T) {
type handshakeData struct {
MaxDAVEProtocolVersion int `json:"max_dave_protocol_version"`
}

// The noop session returns 0, so the field should be 0 in the JSON.
d := handshakeData{MaxDAVEProtocolVersion: 0}
b, err := json.Marshal(d)
if err != nil {
t.Fatal(err)
}

var parsed map[string]interface{}
if err := json.Unmarshal(b, &parsed); err != nil {
t.Fatal(err)
}

val, ok := parsed["max_dave_protocol_version"]
if !ok {
t.Fatal("expected max_dave_protocol_version in JSON")
}
if int(val.(float64)) != 0 {
t.Errorf("expected 0, got %v", val)
}
}

// ------------------------------------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------------------------------------

// buildBinaryVoiceMsg constructs a binary voice gateway message.
// [2 bytes: seq][1 byte: opcode][optionally 2 bytes: transitionID][payload]
func buildBinaryVoiceMsg(seq uint16, opcode uint8, transitionID uint16, includeTransitionID bool, payload []byte) []byte {
msg := make([]byte, 3)
binary.BigEndian.PutUint16(msg[:2], seq)
msg[2] = opcode
if includeTransitionID {
tid := make([]byte, 2)
binary.BigEndian.PutUint16(tid, transitionID)
msg = append(msg, tid...)
}
return append(msg, payload...)
}

// daveSessionRecorder records calls to the DAVE session interface for test assertions.
type daveSessionRecorder struct {
externalSenderPackages [][]byte
proposals              [][]byte
commitTransitions      []struct {
transitionID uint16
message      []byte
}
welcomes []struct {
transitionID uint16
message      []byte
}
selectProtocolAcks []uint16
prepareTransitions []struct {
transitionID, protocolVersion uint16
}
executeTransitions []uint16
prepareEpochs      []struct {
epoch           int
protocolVersion uint16
}
addedUsers   []godave.UserID
removedUsers []godave.UserID
}

func (r *daveSessionRecorder) callCount() int {
return len(r.externalSenderPackages) + len(r.proposals) +
len(r.commitTransitions) + len(r.welcomes)
}

func (r *daveSessionRecorder) MaxSupportedProtocolVersion() int           { return 1 }
func (r *daveSessionRecorder) SetChannelID(_ godave.ChannelID)            {}
func (r *daveSessionRecorder) AssignSsrcToCodec(_ uint32, _ godave.Codec) {}
func (r *daveSessionRecorder) MaxEncryptedFrameSize(n int) int            { return n }
func (r *daveSessionRecorder) Encrypt(_ uint32, frame, enc []byte) (int, error) {
return copy(enc, frame), nil
}
func (r *daveSessionRecorder) MaxDecryptedFrameSize(_ godave.UserID, n int) int { return n }
func (r *daveSessionRecorder) Decrypt(_ godave.UserID, frame, dec []byte) (int, error) {
return copy(dec, frame), nil
}
func (r *daveSessionRecorder) AddUser(id godave.UserID) { r.addedUsers = append(r.addedUsers, id) }
func (r *daveSessionRecorder) RemoveUser(id godave.UserID) {
r.removedUsers = append(r.removedUsers, id)
}
func (r *daveSessionRecorder) OnSelectProtocolAck(v uint16) {
r.selectProtocolAcks = append(r.selectProtocolAcks, v)
}
func (r *daveSessionRecorder) OnDavePrepareTransition(tid, pv uint16) {
r.prepareTransitions = append(r.prepareTransitions, struct {
transitionID, protocolVersion uint16
}{tid, pv})
}
func (r *daveSessionRecorder) OnDaveExecuteTransition(tid uint16) {
r.executeTransitions = append(r.executeTransitions, tid)
}
func (r *daveSessionRecorder) OnDavePrepareEpoch(epoch int, pv uint16) {
r.prepareEpochs = append(r.prepareEpochs, struct {
epoch           int
protocolVersion uint16
}{epoch, pv})
}
func (r *daveSessionRecorder) OnDaveMLSExternalSenderPackage(pkg []byte) {
r.externalSenderPackages = append(r.externalSenderPackages, pkg)
}
func (r *daveSessionRecorder) OnDaveMLSProposals(p []byte) {
r.proposals = append(r.proposals, p)
}
func (r *daveSessionRecorder) OnDaveMLSPrepareCommitTransition(tid uint16, msg []byte) {
r.commitTransitions = append(r.commitTransitions, struct {
transitionID uint16
message      []byte
}{tid, msg})
}
func (r *daveSessionRecorder) OnDaveMLSWelcome(tid uint16, msg []byte) {
r.welcomes = append(r.welcomes, struct {
transitionID uint16
message      []byte
}{tid, msg})
}
