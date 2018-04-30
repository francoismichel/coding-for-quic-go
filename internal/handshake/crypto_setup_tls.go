package handshake

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// ErrCloseSessionForRetry is returned by HandleCryptoStream when the server wishes to perform a stateless retry
var ErrCloseSessionForRetry = errors.New("closing session in order to recreate after a retry")

// KeyDerivationFunction is used for key derivation
type KeyDerivationFunction func(crypto.TLSExporter, protocol.Perspective) (crypto.UpdatableAEAD, error)

type countingAEAD struct {
	crypto.UpdatableAEAD

	keyPhase protocol.KeyPhase

	numSeal int
}

var _ crypto.UpdatableAEAD = &countingAEAD{}

func (c *countingAEAD) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte {
	c.numSeal++
	return c.UpdatableAEAD.Seal(dst, src, packetNumber, associatedData)
}

func (c *countingAEAD) KeyPhase() protocol.KeyPhase {
	return c.keyPhase
}

type cryptoSetupTLS struct {
	mutex sync.RWMutex

	perspective protocol.Perspective

	keyDerivation   KeyDerivationFunction
	nullAEAD        crypto.AEAD
	lastAEAD        crypto.AEAD
	currentAEAD     *countingAEAD
	currentKeyPhase protocol.KeyPhase
	nextAEAD        *countingAEAD // is never used to open or seal, only cached for the next key update

	receivedPacketWithCurrentAEAD bool
	firstReceivedWithCurrentAEAD  protocol.PacketNumber
	sentPacketWithCurrentAEAD     bool
	firstSentWithCurrentAEAD      protocol.PacketNumber

	tls            MintTLS
	cryptoStream   *CryptoStreamConn
	handshakeEvent chan<- struct{}

	logger utils.Logger
}

var _ CryptoSetupTLS = &cryptoSetupTLS{}

// NewCryptoSetupTLSServer creates a new TLS CryptoSetup instance for a server
func NewCryptoSetupTLSServer(
	tls MintTLS,
	cryptoStream *CryptoStreamConn,
	nullAEAD crypto.AEAD,
	handshakeEvent chan<- struct{},
	logger utils.Logger,
	version protocol.VersionNumber,
) CryptoSetupTLS {
	return &cryptoSetupTLS{
		tls:            tls,
		cryptoStream:   cryptoStream,
		nullAEAD:       nullAEAD,
		perspective:    protocol.PerspectiveServer,
		keyDerivation:  crypto.NewUpdatableAEAD,
		handshakeEvent: handshakeEvent,
		logger:         logger,
	}
}

// NewCryptoSetupTLSClient creates a new TLS CryptoSetup instance for a client
func NewCryptoSetupTLSClient(
	cryptoStream io.ReadWriter,
	connID protocol.ConnectionID,
	hostname string,
	handshakeEvent chan<- struct{},
	tls MintTLS,
	logger utils.Logger,
	version protocol.VersionNumber,
) (CryptoSetupTLS, error) {
	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveClient, connID, version)
	if err != nil {
		return nil, err
	}

	return &cryptoSetupTLS{
		perspective:    protocol.PerspectiveClient,
		tls:            tls,
		nullAEAD:       nullAEAD,
		keyDerivation:  crypto.NewUpdatableAEAD,
		handshakeEvent: handshakeEvent,
		logger:         logger,
	}, nil
}

func (h *cryptoSetupTLS) HandleCryptoStream() error {
	if h.perspective == protocol.PerspectiveServer {
		// mint already wrote the ServerHello, EncryptedExtensions and the certificate chain to the buffer
		// send out that data now
		if _, err := h.cryptoStream.Flush(); err != nil {
			return err
		}
	}

handshakeLoop:
	for {
		if alert := h.tls.Handshake(); alert != mint.AlertNoAlert {
			return fmt.Errorf("TLS handshake error: %s (Alert %d)", alert.String(), alert)
		}
		switch h.tls.State() {
		case mint.StateClientStart: // this happens if a stateless retry is performed
			return ErrCloseSessionForRetry
		case mint.StateClientConnected, mint.StateServerConnected:
			break handshakeLoop
		}
	}

	aead, err := h.keyDerivation(h.tls, h.perspective)
	if err != nil {
		return err
	}
	nextAEAD, err := aead.Next()
	if err != nil {
		return err
	}
	h.mutex.Lock()
	h.currentAEAD = &countingAEAD{
		UpdatableAEAD: aead,
		keyPhase:      protocol.KeyPhaseZero,
	}
	h.nextAEAD = &countingAEAD{
		UpdatableAEAD: nextAEAD,
		keyPhase:      protocol.KeyPhaseOne,
	}
	h.mutex.Unlock()

	h.handshakeEvent <- struct{}{}
	close(h.handshakeEvent)
	return nil
}

func (h *cryptoSetupTLS) OpenHandshake(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error) {
	return h.nullAEAD.Open(dst, src, packetNumber, associatedData)
}

func (h *cryptoSetupTLS) Open1RTT(dst, src []byte, packetNumber protocol.PacketNumber, keyPhase protocol.KeyPhase, associatedData []byte) ([]byte, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.currentAEAD == nil {
		return nil, errors.New("no 1-RTT sealer")
	}
	if keyPhase == h.currentKeyPhase {
		data, err := h.currentAEAD.Open(dst, src, packetNumber, associatedData)
		if err == nil && !h.receivedPacketWithCurrentAEAD {
			h.receivedPacketWithCurrentAEAD = true
			h.firstReceivedWithCurrentAEAD = packetNumber
		}
		return data, err
	}

	// The packet has a different key phase than our current key phase.
	// This can either an old packet, sent under the last AEAD keys...
	if !h.receivedPacketWithCurrentAEAD || packetNumber < h.firstReceivedWithCurrentAEAD {
		if h.lastAEAD == nil {
			return nil, errors.New("bla")
		}
		return h.lastAEAD.Open(dst, src, packetNumber, associatedData)
	}
	// ... or the peer updated the keys.
	// First try to open the packet (to make sure it's not a maliciously injected packet)...
	data, err := h.nextAEAD.Open(dst, src, packetNumber, associatedData)
	if err != nil {
		return nil, err
	}
	// TODO: implement a check that this is not a consecutive key update.
	// ... if opening succeeds, update our AEADs.
	h.logger.Debugf("Received a packet with the next key phase. Updating 1-RTT key.")
	if err := h.updateAEAD(); err != nil {
		return nil, err
	}
	h.receivedPacketWithCurrentAEAD = true
	h.firstReceivedWithCurrentAEAD = packetNumber
	return data, nil
}

func (h *cryptoSetupTLS) maybeUpdateAEAD() error {
	if h.currentAEAD.numSeal < protocol.KeyRotationInterval {
		return nil
	}
	// TODO: make sure that we don't update the AEAD if we haven't received a packet
	h.logger.Debugf("Updating 1-RTT keys, since this key was already used for sealing %d packets.", h.currentAEAD.numSeal)
	return h.updateAEAD()
}

func (h *cryptoSetupTLS) updateAEAD() error {
	nextAEAD, err := h.currentAEAD.Next()
	if err != nil {
		return err
	}
	nextKeyPhase := h.currentAEAD.KeyPhase().Next()
	h.lastAEAD = h.currentAEAD
	h.currentAEAD = h.nextAEAD
	h.currentKeyPhase = h.currentAEAD.KeyPhase()
	h.firstReceivedWithCurrentAEAD = 0
	h.receivedPacketWithCurrentAEAD = false
	h.nextAEAD = &countingAEAD{
		UpdatableAEAD: nextAEAD,
		keyPhase:      nextKeyPhase,
	}
	return nil
}

func (h *cryptoSetupTLS) GetSealer() (protocol.EncryptionLevel, Sealer) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.currentAEAD != nil {
		if err := h.maybeUpdateAEAD(); err != nil {
			panic(err)
		}
		return protocol.EncryptionForwardSecure, h.currentAEAD
	}
	return protocol.EncryptionUnencrypted, h.nullAEAD
}

func (h *cryptoSetupTLS) GetSealerWithEncryptionLevel(encLevel protocol.EncryptionLevel) (Sealer, error) {
	errNoSealer := fmt.Errorf("CryptoSetup: no sealer with encryption level %s", encLevel.String())
	h.mutex.Lock()
	defer h.mutex.Unlock()

	switch encLevel {
	case protocol.EncryptionUnencrypted:
		return h.nullAEAD, nil
	case protocol.EncryptionForwardSecure:
		if h.currentAEAD == nil {
			return nil, errNoSealer
		}
		if err := h.maybeUpdateAEAD(); err != nil {
			return nil, err
		}
		return h.currentAEAD, nil
	default:
		return nil, errNoSealer
	}
}

func (h *cryptoSetupTLS) GetSealerForCryptoStream() (protocol.EncryptionLevel, Sealer) {
	return protocol.EncryptionUnencrypted, h.nullAEAD
}

func (h *cryptoSetupTLS) ConnectionState() ConnectionState {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	mintConnState := h.tls.ConnectionState()
	return ConnectionState{
		// TODO: set the ServerName, once mint exports it
		HandshakeComplete: h.currentAEAD != nil,
		PeerCertificates:  mintConnState.PeerCertificates,
	}
}
