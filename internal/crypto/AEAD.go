package crypto

import "github.com/lucas-clemente/quic-go/internal/protocol"

// An AEAD implements QUIC's authenticated encryption and associated data
type AEAD interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error)
	Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte
	Overhead() int
}

// An UpdatableAEAD is an AEAD that can derive an updated AEAD from its current state
type UpdatableAEAD interface {
	AEAD
	Next() (UpdatableAEAD, error)
}
