package fec

import "github.com/lucas-clemente/quic-go/internal/protocol"

type RepairSymbol struct {
	FECSchemeID protocol.FECSchemeID
	data []byte	// May contain metadata
}
