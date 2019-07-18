package fec

import "github.com/lucas-clemente/quic-go/internal/protocol"

// The redundancy control will adapt the number of FEC Source/Repair Symbol

type RedundancyController interface {
	// is called whenever a packet is lost
	OnSourceSymbolLost(protocol.PacketNumber)
	// is called whenever a packet is received
	OnSourceSymbolReceived(protocol.PacketNumber)
	// returns the maximum number of repair symbols that should be generated in a row
	// the argument is an int that represents the number of source symbols sent since the last FEC protection
	GetNumberOfRepairSymbols(int) uint
}