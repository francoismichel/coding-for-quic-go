package block

import (
	"bytes"
	"fmt"
	"github.com/lucas-clemente/quic-go/internal/fec"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)


type BlockFrameworkSender struct {
	fecScheme            BlockFECScheme
	redundancyController RedundancyController
	currentBlock         *FECBlock
	e                    uint16

	BlocksToSend []*FECBlock
}

func NewBlockFrameworkSender(fecScheme BlockFECScheme, redundancyController RedundancyController, E uint16) *BlockFrameworkSender {
	return &BlockFrameworkSender{
		fecScheme:            fecScheme,
		redundancyController: redundancyController,
		currentBlock:         &FECBlock{},
		e:                    E,
	}
}

func (f *BlockFrameworkSender) E() uint16 {
	return f.e
}

func (f *BlockFrameworkSender) GetNextFPID() protocol.FECPayloadID {
	return BlockSourceID{
		BlockNumber: f.currentBlock.BlockNumber,
		BlockOffset: BlockOffset(len(f.currentBlock.sourceSymbolsOffsets)),
	}.ToFPID()
}

func (f *BlockFrameworkSender) protectSourceSymbol(symbol *BlockSourceSymbol) (retval protocol.FECPayloadID) {
	buf := bytes.NewBuffer(retval[:])
	f.currentBlock.AddSourceSymbol(symbol).EncodeBlockSourceID(buf)
	return retval
}

// returns the ID of the first symbol in the payload
func (f *BlockFrameworkSender) ProtectPayload(pn protocol.PacketNumber, payload fec.PreProcessedPayload) (retval protocol.FECPayloadID, err error) {
	if payload == nil || len(payload.Bytes()) == 0 {
		return retval, fmt.Errorf("asked to protect an empty payload")
	}
	symbols, err := PayloadToSourceSymbols(payload.Bytes(), f.e)
	if err != nil {
		return retval, err
	}
	for i, symbol := range symbols {
		if i == 0 {
			retval = f.protectSourceSymbol(symbol)
		} else {
			f.protectSourceSymbol(symbol)
		}
	}

	if f.redundancyController.ShouldSend(f.currentBlock.SourceSymbols) {
		err := f.GenerateRepairSymbols(f.currentBlock, f.redundancyController.GetNumberOfRepairSymbols())
		if err != nil {
			return retval, err
		}
		f.sendCurrentBlock()
	}
	return retval, nil
}

func (f *BlockFrameworkSender) sendCurrentBlock() {
	f.currentBlock.TotalNumberOfSourceSymbols = len(f.currentBlock.SourceSymbols)
	f.currentBlock.TotalNumberOfRepairSymbols = len(f.currentBlock.RepairSymbols)
	f.BlocksToSend = append(f.BlocksToSend, f.currentBlock)
	f.currentBlock = &FECBlock{
		BlockNumber:          f.currentBlock.BlockNumber + 1,
		sourceSymbolsOffsets: make(map[BlockSourceID]BlockOffset),
	}
}


func (f *BlockFrameworkSender) FlushUnprotectedSymbols() error {
	err := f.GenerateRepairSymbols(f.currentBlock, f.redundancyController.GetNumberOfRepairSymbols())
	if err != nil {
		return err
	}
	f.sendCurrentBlock()
	return nil
}

func (f *BlockFrameworkSender) GenerateRepairSymbols(block *FECBlock, numberOfSymbols uint) error {
	symbols, err := f.fecScheme.GetRepairSymbols(block, numberOfSymbols)
	if err != nil {
		return err
	}
	block.SetRepairSymbols(symbols)
	return nil
}