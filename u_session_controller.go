package tls

import "fmt"

// Tracking the state of calling conn.loadSession
type LoadSessionTrackerState int

const NeverCalled LoadSessionTrackerState = 0
const UtlsAboutToCall LoadSessionTrackerState = 1
const CalledByULoadSession LoadSessionTrackerState = 2
const CalledByGoTLS LoadSessionTrackerState = 3

// The state of the session controller
type sessionState int

const NoSession sessionState = 0
const TicketInitialized sessionState = 1
const TicketAllSet sessionState = 2
const PskExtInitialized sessionState = 3
const PskAllSet sessionState = 4

// sessionController is responsible for managing and controlling all session related states. It manages the lifecycle of the session ticket extension and the psk extension, including initialization, removal if the client hello spec doesn't contain any of them, and setting the prepared state to the client hello.
//
// Users should never directly modify the underlying state. Violations will result in undefined behaviors.
//
// Users should never construct sessionController by themselves, use the function `newSessionController` instead.
type sessionController struct {
	// sessionTicketExt logically owns the session ticket extension
	sessionTicketExt *SessionTicketExtension

	// pskExtension logically owns the psk extension
	pskExtension PreSharedKeyExtension

	// uconnRef is a reference to the uconn
	uconnRef *UConn

	// state represents the internal state of the sessionController. Users are advised to modify the state only through designated methods and avoid direct manipulation, as doing so may result in undefined behavior.
	state sessionState

	// loadSessionTracker keeps track of how the conn.loadSession method is being utilized.
	loadSessionTracker LoadSessionTrackerState

	// callingLoadSession is a boolean flag that indicates whether the `conn.loadSession` function is currently being invoked.
	callingLoadSession bool

	// locked is a boolean flag that becomes true once all states are appropriately set. Once `locked` is true, further modifications are disallowed, except for the binders.
	locked bool
}

// newSessionController constructs a new SessionController
func newSessionController(uconn *UConn) *sessionController {
	return &sessionController{
		uconnRef:           uconn,
		sessionTicketExt:   &SessionTicketExtension{},
		pskExtension:       &UtlsPreSharedKeyExtension{},
		state:              NoSession,
		locked:             false,
		callingLoadSession: false,
		loadSessionTracker: NeverCalled,
	}
}

func (s *sessionController) isSessionLocked() bool {
	return s.locked
}

type shouldLoadSessionResult int

const shouldReturn shouldLoadSessionResult = 0
const shouldSetTicket shouldLoadSessionResult = 1
const shouldSetPsk shouldLoadSessionResult = 2
const shouldLoad shouldLoadSessionResult = 3

// shouldLoadSession determines the appropriate action to take when it is time to load the session for the clientHello.
// There are several possible scenarios:
//   - If a session ticket is already initialized, typically via the `initSessionTicketExt()` function, the ticket should be set in the client hello.
//   - If a pre-shared key (PSK) is already initialized, typically via the `overridePskExt()` function, the PSK should be set in the client hello.
//   - If both the `sessionTicketExt` and `pskExtension` are nil, which might occur if the client hello spec does not include them, we should skip the loadSession().
//   - In all other cases, the function proceeds to load the session.
func (s *sessionController) shouldLoadSession() shouldLoadSessionResult {
	if s.sessionTicketExt == nil && s.pskExtension == nil || s.uconnRef.clientHelloBuildStatus != NotBuilt {
		// No need to load session since we don't have the related extensions.
		return shouldReturn
	}
	if s.state == TicketInitialized {
		return shouldSetTicket
	}
	if s.state == PskExtInitialized {
		return shouldSetPsk
	}
	return shouldLoad
}

// utlsAboutToLoadSession updates the loadSessionTracker to `UtlsAboutToCall` to signal the initiation of a session loading operation,
// provided that the preconditions are met. If the preconditions are not met (due to incorrect utls implementation), this function triggers a panic.
func (s *sessionController) utlsAboutToLoadSession() {
	uAssert(s.state == NoSession && !s.locked, "tls: aboutToLoadSession failed: must only load session when the session of the client hello is not locked and when there's currently no session")
	s.loadSessionTracker = UtlsAboutToCall
}

// commonCheck performs various common precondition checks, including validating the `clientHelloBuildStatus`,
// checking the internal state, and verifying the provided parameters.
func (s *sessionController) commonCheck(failureMsg string, params ...any) {
	if s.uconnRef.clientHelloBuildStatus != NotBuilt {
		panic(failureMsg + ": we can't modify the session after the clientHello is built")
	}
	if s.state != NoSession {
		panic(failureMsg + ": the session already set")
	}
	panicOnNil(failureMsg, params...)
}

// finalCheck performs a comprehensive check on the updated state to ensure the correctness of the changes.
// If the checks pass successfully, the sessionController's state will be locked.
// Any failure in passing the tests indicates incorrect implementations in the utls, which will result in triggering a panic.
// Refer to the documentation for the `locked` field for more detailed information.
func (s *sessionController) finalCheck() {
	uAssert(s.state == PskAllSet || s.state == TicketAllSet || s.state == NoSession, "tls: SessionController.finalCheck failed: the session is half set")
	s.locked = true
}

// initSessionTicketExt initializes the ticket and sets the state to `TicketInitialized`.
func (s *sessionController) initSessionTicketExt(session *SessionState, ticket []byte) {
	s.commonCheck("tls: initSessionTicket failed", s.sessionTicketExt, session, ticket)
	s.sessionTicketExt.Session = session
	s.sessionTicketExt.Ticket = ticket
	s.state = TicketInitialized
}

// setSessionTicketToUConn write the ticket states from the session ticket extension to the client hello and handshake state.
func (s *sessionController) setSessionTicketToUConn() {
	uAssert(s.sessionTicketExt != nil && s.state == TicketInitialized, "tls: setSessionTicketExt failed: invalid state")
	s.uconnRef.HandshakeState.Session = s.sessionTicketExt.Session
	s.uconnRef.HandshakeState.Hello.SessionTicket = s.sessionTicketExt.Ticket
	s.state = TicketAllSet
}

// initPSK initializes the PSK extension using a valid session. The PSK extension
// should not be initialized previously, and the parameters must not be nil;
// otherwise, this function will trigger a panic.
func (s *sessionController) initPsk(session *SessionState, earlySecret []byte, binderKey []byte, pskIdentities []pskIdentity) {
	s.commonCheck("tls: initPsk failed", s.pskExtension, session, earlySecret, pskIdentities)
	uAssert(!s.pskExtension.IsInitialized(), "tls: initPsk failed: the psk extension is already initialized")

	publicPskIdentities := mapSlice(pskIdentities, func(private pskIdentity) PskIdentity {
		return PskIdentity{
			Label:               private.label,
			ObfuscatedTicketAge: private.obfuscatedTicketAge,
		}
	})
	s.pskExtension.InitializeByUtls(session, earlySecret, binderKey, publicPskIdentities)
	uAssert(s.pskExtension.IsInitialized(), "the psk extension is not initialized after initialization")
	s.uconnRef.HandshakeState.State13.BinderKey = binderKey
	s.uconnRef.HandshakeState.State13.EarlySecret = earlySecret
	s.uconnRef.HandshakeState.Session = session
	s.uconnRef.HandshakeState.Hello.PskIdentities = publicPskIdentities
	// binders are not expected to be available at this point
	s.state = PskExtInitialized
}

// setPskToHandshake sets the psk to the handshake state and client hello.
func (s *sessionController) setPskToHandshake() {
	uAssert(s.pskExtension != nil && (s.state == PskExtInitialized || s.state == PskAllSet), "tls: setPskToHandshake failed: invalid state")
	pskCommon := s.pskExtension.GetPreSharedKeyCommon()
	if s.state == PskExtInitialized {
		s.uconnRef.HandshakeState.State13.EarlySecret = pskCommon.EarlySecret
		s.uconnRef.HandshakeState.Session = pskCommon.Session
		s.uconnRef.HandshakeState.Hello.PskIdentities = pskCommon.Identities
		s.uconnRef.HandshakeState.Hello.PskBinders = pskCommon.Binders
	} else if s.state == PskAllSet {
		uAssert(s.uconnRef.HandshakeState.Session == pskCommon.Session && sliceEq(s.uconnRef.HandshakeState.State13.EarlySecret, pskCommon.EarlySecret) &&
			allTrue(s.uconnRef.HandshakeState.Hello.PskIdentities, func(i int, psk *PskIdentity) bool {
				return pskCommon.Identities[i].ObfuscatedTicketAge == psk.ObfuscatedTicketAge && sliceEq(pskCommon.Identities[i].Label, psk.Label)
			}), "tls: setPskToHandshake failed: only binders are allowed to change on state `PskAllSet`")
	}
	s.uconnRef.HandshakeState.State13.BinderKey = pskCommon.BinderKey
	s.state = PskAllSet
}

// shouldUpdateBinders determines whether binders should be updated based on the presence of an initialized psk extension.
// This function returns true if an initialized psk extension exists. Binders are allowed to be updated when the state is `PskAllSet`,
// as the `BuildHandshakeState` function can be called multiple times in this case. However, it's important to note that
// the session state, apart from binders, should not be altered more than once.
func (s *sessionController) shouldUpdateBinders() bool {
	if s.pskExtension == nil {
		return false
	}
	return s.state == PskExtInitialized || s.state == PskAllSet
}

func (s *sessionController) updateBinders() {
	uAssert(s.shouldUpdateBinders(), "tls: updateBinders failed: shouldn't update binders")
	s.pskExtension.PatchBuiltHello(s.uconnRef.HandshakeState.Hello)
}

// overridePskExt allows the user of utls to customize the psk extension.
func (s *sessionController) overridePskExt(psk PreSharedKeyExtension) error {
	if s.state != NoSession {
		return fmt.Errorf("SetSessionState13 failed: there's already a session")
	}
	s.pskExtension = psk
	if psk.IsInitialized() {
		s.state = PskExtInitialized
	}
	return nil
}

var customizedHellos = []ClientHelloID{
	HelloCustom,
	HelloRandomized,
	HelloRandomizedALPN,
	HelloRandomizedNoALPN,
}

// CheckSessionExt is designed to be called after applying client hello specs. It performs the following checks and fixups:
//   - If the session ticket extension or PSK extension is missing from the extension list, owned extensions are dropped and states are reset.
//   - Ensures that the session ticket extension or PSK extension matches the owned one.
//   - Ensures that there is only one session ticket extension or PSK extension.
//   - Ensures that the PSK extension is the last extension in the extension list.
func (s *sessionController) checkSessionExt() {
	uAssert(s.uconnRef.clientHelloBuildStatus == NotBuilt, "tls: checkSessionExt failed: we can't modify the session after the clientHello is built")
	numSessionExt := 0
	hasPskExt := false
	for i, e := range s.uconnRef.Extensions {
		switch ext := e.(type) {
		case *SessionTicketExtension:
			if ext != s.uconnRef.sessionController.sessionTicketExt {
				if anyTrue(customizedHellos, func(_ int, h *ClientHelloID) bool {
					return s.uconnRef.ClientHelloID.Client == h.Client
				}) {
					s.uconnRef.Extensions[i] = s.uconnRef.sessionController.sessionTicketExt
				} else {
					panic(fmt.Sprintf("tls: checkSessionExt failed: sessionTicketExtShortcut != SessionTicketExtension from the extension list and the clientHello is build from presets: [%v]", s.uconnRef.ClientHelloID))
				}
			}
			numSessionExt += 1
		case PreSharedKeyExtension:
			uAssert(i == len(s.uconnRef.Extensions)-1, "tls: checkSessionExt failed: PreSharedKeyExtension must be the last extension")
			if ext != s.uconnRef.sessionController.pskExtension {
				if anyTrue(customizedHellos, func(_ int, h *ClientHelloID) bool {
					return s.uconnRef.ClientHelloID.Client == h.Client
				}) {
					s.uconnRef.Extensions[i] = s.uconnRef.sessionController.pskExtension
				} else {
					panic(fmt.Sprintf("tls: checkSessionExt failed: pskExtensionShortcut != PreSharedKeyExtension from the extension list and the clientHello is build from presets: [%v]", s.uconnRef.ClientHelloID))
				}
			}
			hasPskExt = true
		}
	}
	if !(s.state == NoSession || s.state == TicketInitialized || s.state == PskExtInitialized) {
		panic(fmt.Sprintf("tls: checkSessionExt failed: can't remove session ticket extension; the session ticket extension is unused, but the internal state is: %d", s.state))
	}
	if numSessionExt == 0 {
		s.sessionTicketExt = nil
		s.uconnRef.HandshakeState.Session = nil
		s.uconnRef.HandshakeState.Hello.SessionTicket = nil
	} else if numSessionExt > 1 {
		panic("checkSessionExt failed: multiple session ticket extensions in the extension list")
	}
	if !hasPskExt {
		s.pskExtension = nil
		s.uconnRef.HandshakeState.State13.BinderKey = nil
		s.uconnRef.HandshakeState.State13.EarlySecret = nil
		s.uconnRef.HandshakeState.Session = nil
		s.uconnRef.HandshakeState.Hello.PskIdentities = nil
	}
}

// onEnterLoadSessionCheck is intended to be invoked upon entering the `conn.loadSession` function.
// It is designed to ensure the correctness of the utls implementation. If the utls implementation is found to be incorrect, this function will trigger a panic.
func (s *sessionController) onEnterLoadSessionCheck() {
	uAssert(!s.locked, "tls: LoadSessionCoordinator.onEnterLoadSessionCheck failed: session is set and locked, no call to loadSession is allowed")
	switch s.loadSessionTracker {
	case UtlsAboutToCall, NeverCalled:
		s.callingLoadSession = true
	case CalledByULoadSession, CalledByGoTLS:
		panic("tls: LoadSessionCoordinator.onEnterLoadSessionCheck failed: you must not call loadSession() twice")
	default:
		panic("tls: LoadSessionCoordinator.onEnterLoadSessionCheck failed: unimplemented state")
	}
}

// onLoadSessionReturn is intended to be invoked upon returning from the `conn.loadSession` function.
// It serves as a validation step for the correctness of the underlying utls implementation.
// If the utls implementation is incorrect, this function will trigger a panic.
func (s *sessionController) onLoadSessionReturn() {
	uAssert(s.callingLoadSession, "tls: LoadSessionCoordinator.onLoadSessionReturn failed: it's not loading sessions, perhaps this function is not being called by loadSession.")
	switch s.loadSessionTracker {
	case NeverCalled:
		s.loadSessionTracker = CalledByGoTLS
	case UtlsAboutToCall:
		s.loadSessionTracker = CalledByULoadSession
	default:
		panic("tls: LoadSessionCoordinator.onLoadSessionReturn failed: unimplemented state")
	}
	s.callingLoadSession = false
}

// shouldLoadSessionWriteBinders checks if `conn.loadSession` should proceed to write binders and marshal the client hello. If the utls implementation
// is incorrect, this function will trigger a panic.
func (s *sessionController) shouldLoadSessionWriteBinders() bool {
	uAssert(s.callingLoadSession, "tls: shouldWriteBinders failed: LoadSessionCoordinator isn't loading sessions, perhaps this function is not being called by loadSession.")

	switch s.loadSessionTracker {
	case NeverCalled:
		return true
	case UtlsAboutToCall:
		return false
	default:
		panic("tls: shouldWriteBinders failed: unimplemented state")
	}
}
