package crypto

import "github.com/lucas-clemente/quic-go/internal/protocol"

// An AEAD implements QUIC's authenticated encryption and associated data
type AEAD interface {
	Opener
	Sealer
}

// A Sealer is the sealing part of QUIC's authenticated encryption and associated data
type Sealer interface {
	Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte
	Overhead() int
}

// An Opener is the sealing part of QUIC's authenticated encryption and associated data
type Opener interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error)
}
