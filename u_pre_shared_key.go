package tls

import (
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

type PreSharedKeyExtension interface {
	TLSExtension

	// ReadWithRawHello is used to read the extension from the ClientHello
	// instead of Read(), where the latter is used to read all other extensions.
	//
	// This is needed because the PSK extension needs to calculate the binder
	// based on all previous parts of the ClientHello.
	ReadWithRawHello(raw, b []byte) (int, error)

	// Binders returns the binders that were computed during the handshake.
	//
	// FakePreSharedKeyExtension will return nil to make sure utls DOES NOT
	// actually do any session resumption.
	Binders() [][]byte

	mustEmbedUnimplementedPreSharedKeyExtension() // this works like a type guard
}

type UnimplementedPreSharedKeyExtension struct{}

func (UnimplementedPreSharedKeyExtension) mustEmbedUnimplementedPreSharedKeyExtension() {}

func (*UnimplementedPreSharedKeyExtension) writeToUConn(*UConn) error {
	return errors.New("tls: writeToUConn is not implemented for the PreSharedKeyExtension")
}

func (*UnimplementedPreSharedKeyExtension) Len() int {
	panic("tls: Len is not implemented for the PreSharedKeyExtension")
}

func (*UnimplementedPreSharedKeyExtension) Read([]byte) (int, error) {
	return 0, errors.New("tls: Read is not implemented for the PreSharedKeyExtension")
}

func (*UnimplementedPreSharedKeyExtension) ReadWithRawHello(raw, b []byte) (int, error) {
	return 0, errors.New("tls: ReadWithRawHello is not implemented for the PreSharedKeyExtension")
}

func (*UnimplementedPreSharedKeyExtension) Binders() [][]byte {
	panic("tls: Binders is not implemented for the PreSharedKeyExtension")
}

// UtlsPreSharedKeyExtension is an extension used to set the PSK extension in the
// ClientHello.
type UtlsPreSharedKeyExtension struct {
	UnimplementedPreSharedKeyExtension

	SessionCacheOverride ClientSessionCache

	identities  []pskIdentity
	binders     [][]byte
	binderKey   []byte // this will be used to compute the binder when hello message is ready
	cipherSuite *cipherSuiteTLS13
	earlySecret []byte
}

func (e *UtlsPreSharedKeyExtension) writeToUConn(uc *UConn) error {
	err := e.preloadSession(uc)
	if err != nil {
		return err
	}

	uc.HandshakeState.Hello.PskIdentities = pskIdentities(e.identities).ToPublic()
	// uc.HandshakeState.Hello.PskBinders = e.binders
	// uc.HandshakeState.Hello = hello.getPublicPtr() // write back to public hello
	// uc.HandshakeState.State13.EarlySecret = e.earlySecret
	// uc.HandshakeState.State13.BinderKey = e.binderKey

	return nil
}

func (e *UtlsPreSharedKeyExtension) Len() int {
	length := 4 // extension type + extension length
	length += 2 // identities length
	for _, identity := range e.identities {
		length += 2 + len(identity.label) + 4 // identity length + identity + obfuscated ticket age
	}
	length += 2 // binders length
	for _, binder := range e.binders {
		length += len(binder) + 1 // binder length + binder
	}
	return length
}

func (e *UtlsPreSharedKeyExtension) Read(b []byte) (int, error) {
	return 0, errors.New("tls: PreSharedKeyExtension shouldn't be read, use ReadWithRawHello() instead")
}

func (e *UtlsPreSharedKeyExtension) ReadWithRawHello(raw, b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(extensionPreSharedKey >> 8)
	b[1] = byte(extensionPreSharedKey)
	b[2] = byte((e.Len() - 4) >> 8)
	b[3] = byte(e.Len() - 4)

	// identities length
	identitiesLength := 0
	for _, identity := range e.identities {
		identitiesLength += 2 + len(identity.label) + 4 // identity length + identity + obfuscated ticket age
	}
	b[4] = byte(identitiesLength >> 8)
	b[5] = byte(identitiesLength)

	// identities
	offset := 6
	for _, identity := range e.identities {
		b[offset] = byte(len(identity.label) >> 8)
		b[offset+1] = byte(len(identity.label))
		offset += 2
		copy(b[offset:], identity.label)
		offset += len(identity.label)
		b[offset] = byte(identity.obfuscatedTicketAge >> 24)
		b[offset+1] = byte(identity.obfuscatedTicketAge >> 16)
		b[offset+2] = byte(identity.obfuscatedTicketAge >> 8)
		b[offset+3] = byte(identity.obfuscatedTicketAge)
		offset += 4
	}

	// concatenate ClientHello and PreSharedKeyExtension
	rawHelloSoFar := append(raw, b[:offset]...)
	transcript := e.cipherSuite.hash.New()
	transcript.Write(rawHelloSoFar)
	e.binders = [][]byte{e.cipherSuite.finishedHash(e.binderKey, transcript)}

	// binders length
	bindersLength := 0
	for _, binder := range e.binders {
		bindersLength += len(binder) + 1 // binder length + binder
	}
	b[offset] = byte(bindersLength >> 8)
	b[offset+1] = byte(bindersLength)
	offset += 2

	// binders
	for _, binder := range e.binders {
		b[offset] = byte(len(binder))
		offset++
		copy(b[offset:], binder)
		offset += len(binder)
	}

	return e.Len(), io.EOF
}

func (e *UtlsPreSharedKeyExtension) preloadSession(uc *UConn) error {
	// var sessionCache ClientSessionCache
	// must set either e.Session or uc.config.ClientSessionCache
	if e.SessionCacheOverride != nil {
		uc.config.ClientSessionCache = e.SessionCacheOverride
	}

	// load Hello
	hello := uc.HandshakeState.Hello.getPrivatePtr()
	// try to use loadSession()
	session, earlySecret, binderKey, err := uc.loadSession(hello)
	if err != nil {
		return err
	}
	if session != nil && session.version == VersionTLS13 && binderKey != nil {
		e.identities = hello.pskIdentities
		e.binders = hello.pskBinders
		e.binderKey = binderKey
		e.cipherSuite = cipherSuiteTLS13ByID(session.cipherSuite)
		e.earlySecret = earlySecret
		return nil
	} else {
		return errors.New("tls: session not compatible with TLS 1.3, PSK not possible")
	}
}

// Binders must be called after ReadWithRawHello
func (e *UtlsPreSharedKeyExtension) Binders() [][]byte {
	return e.binders
}

// FakePreSharedKeyExtension is an extension used to send the PSK extension in the
// ClientHello.
//
// However, it DOES NOT do any session resumption AND should not be used with a
// real/valid PSK Identity.
//
// TODO: Only one of FakePreSharedKeyExtension and HardcodedPreSharedKeyExtension should
// be kept, the other one should be just removed. We still need to learn more of the safety
// of hardcoding both Identities and Binders without recalculating the latter.
type FakePreSharedKeyExtension struct {
	UnimplementedPreSharedKeyExtension

	CipherSuite   uint16 `json:"cipher_suite"`   // this is used to compute the binder
	SessionSecret []byte `json:"session_secret"` // this is used to compute the binder

	Identities []PskIdentity `json:"identities"`
	binders    [][]byte
}

func (e *FakePreSharedKeyExtension) writeToUConn(uc *UConn) error {
	return nil // do nothing for this fake extension
}

func (e *FakePreSharedKeyExtension) Len() int {
	length := 4 // extension type + extension length
	length += 2 // identities length
	for _, identity := range e.Identities {
		length += 2 + len(identity.Label) + 4 // identity length + identity + obfuscated ticket age
	}

	cipherSuite := cipherSuiteTLS13ByID(e.CipherSuite)
	if cipherSuite == nil {
		panic("tls: cipher suite not supported by the PreSharedKeyExtension")
	}
	singleBinderSize := cipherSuite.hash.Size()

	length += 2              // binders length
	for range e.Identities { // binders should be as long as the identities
		length += singleBinderSize + 1
	}
	return length
}

func (e *FakePreSharedKeyExtension) Read(b []byte) (int, error) {
	return 0, errors.New("tls: PreSharedKeyExtension shouldn't be read, use ReadWithRawHello() instead")
}

func (e *FakePreSharedKeyExtension) ReadWithRawHello(raw, b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(extensionPreSharedKey >> 8)
	b[1] = byte(extensionPreSharedKey)
	b[2] = byte((e.Len() - 4) >> 8)
	b[3] = byte(e.Len() - 4)

	// identities length
	identitiesLength := 0
	for _, identity := range e.Identities {
		identitiesLength += 2 + len(identity.Label) + 4 // identity length + identity + obfuscated ticket age
	}
	b[4] = byte(identitiesLength >> 8)
	b[5] = byte(identitiesLength)

	// identities
	offset := 6
	for _, identity := range e.Identities {
		b[offset] = byte(len(identity.Label) >> 8)
		b[offset+1] = byte(len(identity.Label))
		offset += 2
		copy(b[offset:], identity.Label)
		offset += len(identity.Label)
		b[offset] = byte(identity.ObfuscatedTicketAge >> 24)
		b[offset+1] = byte(identity.ObfuscatedTicketAge >> 16)
		b[offset+2] = byte(identity.ObfuscatedTicketAge >> 8)
		b[offset+3] = byte(identity.ObfuscatedTicketAge)
		offset += 4
	}

	cipherSuite := cipherSuiteTLS13ByID(e.CipherSuite)
	if cipherSuite == nil {
		return 0, errors.New("tls: cipher suite not supported")
	}
	earlySecret := cipherSuite.extract(e.SessionSecret, nil)
	binderKey := cipherSuite.deriveSecret(earlySecret, resumptionBinderLabel, nil)

	// concatenate ClientHello and PreSharedKeyExtension
	rawHelloSoFar := append(raw, b[:offset]...)
	transcript := cipherSuite.hash.New()
	transcript.Write(rawHelloSoFar)
	e.binders = [][]byte{cipherSuite.finishedHash(binderKey, transcript)}

	// binders length
	bindersLength := 0
	for _, binder := range e.binders {
		bindersLength += len(binder) + 1 // binder length + binder
	}
	b[offset] = byte(bindersLength >> 8)
	b[offset+1] = byte(bindersLength)
	offset += 2

	// binders
	for _, binder := range e.binders {
		b[offset] = byte(len(binder))
		offset++
		copy(b[offset:], binder)
		offset += len(binder)
	}

	return e.Len(), io.EOF
}

func (e *FakePreSharedKeyExtension) Binders() [][]byte {
	return nil
}

func (e *FakePreSharedKeyExtension) UnmarshalJSON(data []byte) error {
	var pskAccepter struct {
		CipherSuite   uint16        `json:"cipher_suite"`
		SessionSecret []byte        `json:"session_secret"`
		Identities    []PskIdentity `json:"identities"`
	}

	if err := json.Unmarshal(data, &pskAccepter); err != nil {
		return err
	}

	e.CipherSuite = pskAccepter.CipherSuite
	e.SessionSecret = pskAccepter.SessionSecret
	e.Identities = pskAccepter.Identities
	return nil
}

// HardcodedPreSharedKeyExtension is an extension used to set the PSK extension in the
// ClientHello.
//
// It does not compute binders based on ClientHello, but uses the binders specified instead.
//
// TODO: Only one of FakePreSharedKeyExtension and HardcodedPreSharedKeyExtension should
// be kept, the other one should be just removed. We still need to learn more of the safety
// of hardcoding both Identities and Binders without recalculating the latter.
type HardcodedPreSharedKeyExtension struct {
	Identities []PskIdentity `json:"identities"`
	Binders    [][]byte      `json:"binders"`
}

func (e *HardcodedPreSharedKeyExtension) writeToUConn(uc *UConn) error {
	if uc.config.ClientSessionCache == nil {
		return nil // don't write the extension if there is no session cache
	}
	if session, ok := uc.config.ClientSessionCache.Get(uc.clientSessionCacheKey()); !ok || session == nil {
		return nil // don't write the extension if there is no session cache available for this session
	}
	uc.HandshakeState.Hello.PskIdentities = e.Identities
	uc.HandshakeState.Hello.PskBinders = e.Binders
	return nil
}

func (e *HardcodedPreSharedKeyExtension) Len() int {
	length := 4 // extension type + extension length
	length += 2 // identities length
	for _, identity := range e.Identities {
		length += 2 + len(identity.Label) + 4 // identity length + identity + obfuscated ticket age
	}
	length += 2 // binders length
	for _, binder := range e.Binders {
		length += len(binder)
	}
	return length
}

func (e *HardcodedPreSharedKeyExtension) Read(b []byte) (int, error) {
	return 0, errors.New("tls: PreSharedKeyExtension shouldn't be read, use ReadWithRawHello() instead")
}

func (e *HardcodedPreSharedKeyExtension) ReadWithRawHello(raw, b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(extensionPreSharedKey >> 8)
	b[1] = byte(extensionPreSharedKey)
	b[2] = byte((e.Len() - 4) >> 8)
	b[3] = byte(e.Len() - 4)

	// identities length
	identitiesLength := 0
	for _, identity := range e.Identities {
		identitiesLength += 2 + len(identity.Label) + 4 // identity length + identity + obfuscated ticket age
	}
	b[4] = byte(identitiesLength >> 8)
	b[5] = byte(identitiesLength)

	// identities
	offset := 6
	for _, identity := range e.Identities {
		b[offset] = byte(len(identity.Label) >> 8)
		b[offset+1] = byte(len(identity.Label))
		offset += 2
		copy(b[offset:], identity.Label)
		offset += len(identity.Label)
		b[offset] = byte(identity.ObfuscatedTicketAge >> 24)
		b[offset+1] = byte(identity.ObfuscatedTicketAge >> 16)
		b[offset+2] = byte(identity.ObfuscatedTicketAge >> 8)
		b[offset+3] = byte(identity.ObfuscatedTicketAge)
		offset += 4
	}

	// binders length
	bindersLength := 0
	for _, binder := range e.Binders {
		bindersLength += len(binder) + 1
	}
	b[offset] = byte(bindersLength >> 8)
	b[offset+1] = byte(bindersLength)
	offset += 2

	// binders
	for _, binder := range e.Binders {
		b[offset] = byte(len(binder))
		offset++
		copy(b[offset:], binder)
		offset += len(binder)
	}

	return e.Len(), io.EOF
}

func (e *HardcodedPreSharedKeyExtension) Write(b []byte) (n int, err error) {
	fullLen := len(b)
	s := cryptobyte.String(b)

	var identitiesLength uint16
	if !s.ReadUint16(&identitiesLength) {
		return 0, errors.New("tls: invalid PSK extension")
	}

	// identities
	for identitiesLength > 0 {
		var identityLength uint16
		if !s.ReadUint16(&identityLength) {
			return 0, errors.New("tls: invalid PSK extension")
		}
		identitiesLength -= 2

		if identityLength > identitiesLength {
			return 0, errors.New("tls: invalid PSK extension")
		}

		var identity []byte
		if !s.ReadBytes(&identity, int(identityLength)) {
			return 0, errors.New("tls: invalid PSK extension")
		}

		identitiesLength -= identityLength // identity

		var obfuscatedTicketAge uint32
		if !s.ReadUint32(&obfuscatedTicketAge) {
			return 0, errors.New("tls: invalid PSK extension")
		}

		e.Identities = append(e.Identities, PskIdentity{
			Label:               identity,
			ObfuscatedTicketAge: obfuscatedTicketAge,
		})

		identitiesLength -= 4 // obfuscated ticket age
	}

	var bindersLength uint16
	if !s.ReadUint16(&bindersLength) {
		return 0, errors.New("tls: invalid PSK extension")
	}

	// binders
	for bindersLength > 0 {
		var binderLength uint8
		if !s.ReadUint8(&binderLength) {
			return 0, errors.New("tls: invalid PSK extension")
		}
		bindersLength -= 1

		if uint16(binderLength) > bindersLength {
			return 0, errors.New("tls: invalid PSK extension")
		}

		var binder []byte
		if !s.ReadBytes(&binder, int(binderLength)) {
			return 0, errors.New("tls: invalid PSK extension")
		}

		e.Binders = append(e.Binders, binder)

		bindersLength -= uint16(binderLength)
	}

	return fullLen, nil
}

func (e *HardcodedPreSharedKeyExtension) UnmarshalJSON(data []byte) error {
	var pskAccepter struct {
		PskIdentities []PskIdentity `json:"identities"`
		PskBinders    [][]byte      `json:"binders"`
	}

	if err := json.Unmarshal(data, &pskAccepter); err != nil {
		return err
	}

	e.Identities = pskAccepter.PskIdentities
	e.Binders = pskAccepter.PskBinders
	return nil
}
