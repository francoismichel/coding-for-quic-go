package block

import (
	"github.com/lucas-clemente/quic-go/internal/fec"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

const DEFAULT_K = 5
const DEFAULT_N = 6

// The redundancy control will adapt the number of FEC Repair Symbols and
// the size of the FEC Block to the current conditions.

type RedundancyController interface {
	fec.RedundancyController
	// returns true if these symbols should be sent and protected with repair symbols
	ShouldSend([]*BlockSourceSymbol) bool
}

type constantRedundancyController struct {
	nRepairSymbols 			uint
	nSourceSymbols				uint
	windowStepSize		 	uint
}

var _ fec.RedundancyController = &constantRedundancyController{}

func NewConstantRedundancyController(nSourceSymbols uint, nRepairSymbols uint, windowStepSize uint) fec.RedundancyController {
	return &constantRedundancyController{
		nSourceSymbols: 	nSourceSymbols,
		nRepairSymbols: nRepairSymbols,
	}
}

func NewDefaultRedundancyController() fec.RedundancyController {
	return &constantRedundancyController{
		nSourceSymbols: 	DEFAULT_K,
		nRepairSymbols: DEFAULT_N - DEFAULT_K,
	}
}

func (*constantRedundancyController) OnSourceSymbolLost(pn protocol.PacketNumber) {}

func (*constantRedundancyController) OnSourceSymbolReceived(pn protocol.PacketNumber) {}

func (*constantRedundancyController) ShouldSend([]*BlockSourceSymbol) bool {
	// TODO:
	return true
}

func (c *constantRedundancyController) GetNumberOfRepairSymbols() uint {
	return c.nRepairSymbols
}
