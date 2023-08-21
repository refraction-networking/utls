package tls

import "fmt"

type LoadSessionTrackerState int

const NeverCalled LoadSessionTrackerState = 0
const UtlsAboutToCall LoadSessionTrackerState = 3
const CalledByULoadSession LoadSessionTrackerState = 1
const CalledByGoTLS LoadSessionTrackerState = 2

type sessionState int

const NoSession sessionState = 0
const TicketInitialized sessionState = 1
const TicketAllSet sessionState = 4
const PskExtInitialized sessionState = 2
const PskAllSet sessionState = 3

// sessionController is responsible for all session related
type sessionController struct {
	sessionTicketExt   *SessionTicketExtension
	pskExtension       PreSharedKeyExtension
	uconnRef           *UConn
	state              sessionState
	loadSessionTracker LoadSessionTrackerState
	callingLoadSession bool
	locked             bool
}

type shouldLoadSessionResult int

const shouldReturn shouldLoadSessionResult = 0
const shouldSetTicket shouldLoadSessionResult = 1
const shouldSetPsk shouldLoadSessionResult = 2
const shouldLoad shouldLoadSessionResult = 3

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

func (s *sessionController) shouldLoadSession() shouldLoadSessionResult {
	if s.sessionTicketExt == nil && s.pskExtension == nil || s.uconnRef.clientHelloBuildStatus != NotBuilt {
		fmt.Println("uLoadSession s.sessionTicketExt == nil && s.pskExtension == nil")
		// There's no need to load session since we don't have the related extensions.
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

func (s *sessionController) aboutToLoadSession() {
	uAssert(s.state == NoSession && !s.locked, "tls: aboutToLoadSession failed: must only load session when the session of the client hello is not locked and when there's currently no session")
	s.loadSessionTracker = UtlsAboutToCall
}

func (s *sessionController) commonCheck(failureMsg string, params ...any) {
	if s.uconnRef.clientHelloBuildStatus != NotBuilt {
		panic(failureMsg + ": we can't modify the session after the clientHello is built")
	}
	if s.state != NoSession {
		panic(failureMsg + ": the session already set")
	}
	panicOnNil(failureMsg, params...)
}

func (s *sessionController) finalCheck() {
	uAssert(s.state == PskAllSet || s.state == TicketAllSet || s.state == NoSession, "tls: SessionController.finalCheck failed: the session is half set")
	s.locked = true
}

func (s *sessionController) initSessionTicketExt(session *SessionState, ticket []byte) {
	s.commonCheck("tls: initSessionTicket failed", s.sessionTicketExt, session, ticket)
	s.sessionTicketExt.Session = session
	s.sessionTicketExt.Ticket = ticket
	s.state = TicketInitialized
}

func (s *sessionController) setSessionTicketToUConn() {
	uAssert(s.sessionTicketExt != nil && s.state == TicketInitialized, "tls: setSessionTicketExt failed: invalid state")
	s.uconnRef.HandshakeState.Session = s.sessionTicketExt.Session
	s.uconnRef.HandshakeState.Hello.SessionTicket = s.sessionTicketExt.Ticket
	s.state = TicketAllSet
}

func mapSlice[T any, U any](slice []T, transform func(T) U) []U {
	newSlice := make([]U, 0, len(slice))
	for _, t := range slice {
		newSlice = append(newSlice, transform(t))
	}
	return newSlice
}

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

func (s *sessionController) setPsk() {
	uAssert(s.pskExtension != nil && (s.state == PskExtInitialized || s.state == PskAllSet), "tls: setPsk failed: invalid state")
	pskCommon := s.pskExtension.GetPreSharedKeyCommon()
	if s.state == PskExtInitialized {
		s.uconnRef.HandshakeState.State13.EarlySecret = pskCommon.EarlySecret
		s.uconnRef.HandshakeState.Session = pskCommon.Session
		s.uconnRef.HandshakeState.Hello.PskIdentities = pskCommon.Identities
		s.uconnRef.HandshakeState.Hello.PskBinders = pskCommon.Binders
	} else if s.state == PskAllSet {
		uAssert(sliceEq([]any{
			s.uconnRef.HandshakeState.State13.EarlySecret,
			s.uconnRef.HandshakeState.Session,
			s.uconnRef.HandshakeState.Hello.PskIdentities,
			s.uconnRef.HandshakeState.Hello.PskBinders,
		}, []any{
			pskCommon.EarlySecret,
			pskCommon.Session,
			pskCommon.Identities,
			pskCommon.Binders,
		}), "setPsk failed: only binders are allowed to change on state `PskAllSet`")
	}
	s.uconnRef.HandshakeState.State13.BinderKey = pskCommon.BinderKey
	s.state = PskAllSet
}

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

func (s *sessionController) checkSessionExt() {
	uAssert(s.uconnRef.clientHelloBuildStatus == NotBuilt, "tls: checkSessionExt failed: we can't modify the session after the clientHello is built")
	numSessionExt := 0
	hasPskExt := false
	for i, e := range s.uconnRef.Extensions {
		switch ext := e.(type) {
		case *SessionTicketExtension:
			if ext != s.uconnRef.sessionController.sessionTicketExt {
				if anyTrue(customizedHellos, func(h *ClientHelloID) bool {
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
				if anyTrue(customizedHellos, func(h *ClientHelloID) bool {
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

func (s *sessionController) shouldWriteBinders() bool {
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
