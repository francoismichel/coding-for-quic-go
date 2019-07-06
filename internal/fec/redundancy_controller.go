package fec

import "github.com/lucas-clemente/quic-go/internal/fec/block"

// The redundancy control will adapt the number of FEC Repair Symbols and
// the size of the FEC Group to the current conditions.

// Warning: it assumes that the symbols are sent with packet numbers increasing by one.

const MAX_LOSS_BURST_LENGTH uint = 40
const SAMPLE_SIZE								 = 500

type RedundancyController interface {
	// is called whenever a packet is lost
	OnSourceSymbolLost(*block.BlockSourceSymbol)
	// is called whenever a packet is received
	OnSourceSymbolReceived(*block.BlockSourceSymbol)
	// returns true if these symbols should be sent and protected with repair symbols
	ShouldSend([]*block.BlockSourceSymbol) bool
	// returns the maximum number of repair symbols that should be generated for a single FEC Group
	GetNumberOfRepairSymbols() uint
}


type constantRedundancyController struct {
	nRepairSymbols 			uint
	nSourceSymbols				uint
	windowStepSize		 	uint
}

var _ RedundancyController = &constantRedundancyController{}

func NewConstantRedundancyController(nSourceSymbols uint, nRepairSymbols uint, windowStepSize uint) RedundancyController {
	return &constantRedundancyController{
		nSourceSymbols: 	nSourceSymbols,
		nRepairSymbols: nRepairSymbols,
	}
}

func (*constantRedundancyController) OnSourceSymbolLost(symbol *block.BlockSourceSymbol) {}

func (*constantRedundancyController) OnSourceSymbolReceived(symbol *block.BlockSourceSymbol) {}

func (*constantRedundancyController) ShouldSend([]*block.BlockSourceSymbol) bool {
	// TODO:
	return true
}

func (c *constantRedundancyController) GetNumberOfRepairSymbols() uint {
	return c.nRepairSymbols
}
