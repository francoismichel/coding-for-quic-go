package fec

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type FrameworkSender interface {
	// see coding-for-quic: e is the size of a source/repair symbol
	E()	uint16
	ProtectPayload(payload []byte) (retval protocol.FECPayloadID, err error)
	GetNextFPID() protocol.FECPayloadID
	FlushUnprotectedSymbols() error
}

type FrameworkReceiver interface {
	ReceivePayload(payload []byte, sourceID [4]byte) error
	ReceiveRepairFrame(frame *wire.RepairFrame) error
	GetRecoveredPacket() []byte
}