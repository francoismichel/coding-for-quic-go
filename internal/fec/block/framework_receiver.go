package block

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/lucas-clemente/quic-go/internal/fec"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"log"
)

// XXX: a packet can never be spread in different FEC Blocks


type BlockFrameworkReceiver struct {
	e                        protocol.ByteCount
	repairFrameParser        RepairFrameParser
	fecBlocksBuffer          *fecBlocksBuffer
	recoveredPacketsPayloads *recoveredPacketsBuffer
	doRecovery               bool								// Debug parameter: if false, the recovered packets won't be used by the session, like if it has not been recovered
	fecScheme                BlockFECScheme
}
var _ fec.FrameworkReceiver = &BlockFrameworkReceiver{}

func NewBlockFrameworkReceiver(fecScheme BlockFECScheme, repairFrameParser RepairFrameParser, E protocol.ByteCount) (*BlockFrameworkReceiver, error) {
	if E >= protocol.MAX_FEC_SYMBOL_SIZE {
		return nil, fmt.Errorf("framework sender symbol size too big: %d > %d", E, protocol.MAX_FEC_SYMBOL_SIZE)
	}
	buffer := newFecBlocksBuffer(200)
	return &BlockFrameworkReceiver{
		e: E,
		repairFrameParser:				repairFrameParser,
		fecBlocksBuffer: 					buffer,
		recoveredPacketsPayloads: newRecoveredPacketsBuffer(100),
		doRecovery:               true,
		fecScheme:                fecScheme,
	}, nil
}

func (f *BlockFrameworkReceiver) E() protocol.ByteCount {
	return protocol.ByteCount(f.e)
}

func (f *BlockFrameworkReceiver) ReceivePayload(pn protocol.PacketNumber, payload fec.PreProcessedPayload, sourceID protocol.SourceFECPayloadID) error {
	if payload == nil || len(payload.Bytes()) == 0 {
		return fmt.Errorf("receiver framework received an empty payload")
	}
	baseSourceID, err := NewBlockSourceID(sourceID)
	if err != nil {
		return err
	}
	symbols, err := PayloadToSourceSymbols(payload.Bytes(), f.e)
	if err != nil {
		return err
	}
	currentSourceID := baseSourceID
	for _, symbol := range symbols {
		err := f.handleBlockSourceSymbol(symbol, currentSourceID)
		if err != nil {
			return err
		}
		currentSourceID, err = currentSourceID.NextOffset()
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *BlockFrameworkReceiver) HandleRepairFrame(frame *wire.RepairFrame) error {
	r := bytes.NewReader(frame.Metadata)
	nss, nrs, repairID, _, err := f.repairFrameParser.getRepairFrameMetadata(frame)
	if err != nil {
		return err
	}
	first := true
	r = bytes.NewReader(frame.RepairSymbols)
	for ; r.Len() > 0 ; {
		if !first {
			repairID.BlockSourceID, err = repairID.BlockSourceID.NextOffset()
		}
		first = false
		data := make([]byte, f.E())
		_, err = r.Read(data)
		if err != nil {
			return err
		}
		err = f.handleRepairSymbol(&BlockRepairSymbol{
			BlockRepairID: repairID,
			Data: data,
		}, int(nss), int(nrs))
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *BlockFrameworkReceiver) GetRecoveredPacket() *fec.RecoveredPacket {
	return f.recoveredPacketsPayloads.getPacket()
}

func (f *BlockFrameworkReceiver) handleBlockSourceSymbol(symbol *BlockSourceSymbol, id BlockSourceID) error {
	fecBlockNumber := id.BlockNumber
	_, ok:= f.fecBlocksBuffer.fecBlocks[fecBlockNumber]
	if !ok {
		block := NewFECBlock(fecBlockNumber)
		block.SetSourceSymbol(symbol, id)
		f.fecBlocksBuffer.addFECBlock(block)
	}
	f.fecBlocksBuffer.setSourceSymbolInFECBlock(symbol, id)
	return f.updateStateForSomeBlock(fecBlockNumber)

}

func (f *BlockFrameworkReceiver) HandleSourceSymbol(ss *fec.SourceSymbol, id BlockSourceID) error {
	symbol := SourceSymbolToBlockSourceSymbol(ss)
	return f.handleBlockSourceSymbol(symbol, id)

}

// Recovers a packet from this FEC block if possible. If a packet has been recovered or if this FEC block is useless (there is no missing packet in the buffer),
// the fec block will be removed
func (f *BlockFrameworkReceiver) updateStateForSomeBlock(blockNumber BlockNumber) error {
	block := f.fecBlocksBuffer.fecBlocks[blockNumber]
	if len(block.RepairSymbols) == 0 {
		return nil
	}
	if int(block.TotalNumberOfSourceSymbols) > len(block.SourceSymbols) {
		for i := len(block.SourceSymbols) ; i < int(block.TotalNumberOfSourceSymbols) ; i++ {
			block.SourceSymbols = append(block.SourceSymbols, nil)
		}
	}
	if int(block.TotalNumberOfRepairSymbols) > len(block.RepairSymbols) {
		for i := len(block.SourceSymbols) ; i < int(block.TotalNumberOfRepairSymbols) ; i++ {
			block.RepairSymbols = append(block.RepairSymbols, nil)
		}
	}
	if f.fecScheme.CanRecoverSymbols(block) {
		recoveredIdx := make([]BlockOffset, 0, block.TotalNumberOfRepairSymbols)
		for i, s := range block.SourceSymbols {
			if s == nil {
				recoveredIdx = append(recoveredIdx, BlockOffset(i))
			}
		}
		recoveredSymbols, err := f.fecScheme.RecoverSymbols(block)
		if err != nil {
			return err
		}
		if len(recoveredSymbols) == 0 {
			return errors.New("the fec scheme hasn't recovered any symbol although it indicated that it could")
		}
		if len(recoveredSymbols) > 0 {
			recoveredPackets, err := MergeSymbolsToPacketPayloads(block.SourceSymbols, recoveredIdx)
			if err != nil {
				return err
			}
			log.Printf("recovered %d source symbols ! (%d packets)", len(recoveredSymbols), len(recoveredPackets))
			for _, packet := range recoveredPackets {
				f.recoveredPacketsPayloads.addPacket(packet)
			}
			delete(f.fecBlocksBuffer.fecBlocks, blockNumber)
		}
	}
	if block.TotalNumberOfSourceSymbols > 0 && block.CurrentNumberOfSourceSymbols() == block.TotalNumberOfSourceSymbols && uint64(len(block.RepairSymbols)) == block.TotalNumberOfRepairSymbols{
		delete(f.fecBlocksBuffer.fecBlocks, blockNumber)
	}
	return nil
}

func (f *BlockFrameworkReceiver) handleRepairSymbols(rss []*BlockRepairSymbol, totalNumberOfSourceSymbols int, totalNumberOfRepairSymbols int) error {
	// Copying FEC Frame data
	for _, symbol := range rss {
		if symbol != nil {
			err := f.handleRepairSymbol(symbol, totalNumberOfSourceSymbols, totalNumberOfRepairSymbols)
			if err != nil {
				return err
			}
		}
	}
	return nil
}


func (f *BlockFrameworkReceiver) handleRepairSymbol(symbol *BlockRepairSymbol, totalNumberOfSourceSymbols int, totalNumberOfRepairSymbols int) error {
	block, ok := f.fecBlocksBuffer.fecBlocks[symbol.BlockNumber]
	if !ok {
		block = NewFECBlock(symbol.BlockNumber)
		block.RepairSymbols = make([]*BlockRepairSymbol, totalNumberOfRepairSymbols)
		f.fecBlocksBuffer.addFECBlock(block)
	}
	block.TotalNumberOfSourceSymbols = uint64(totalNumberOfSourceSymbols)
	block.TotalNumberOfRepairSymbols = uint64(totalNumberOfRepairSymbols)
	block.SetRepairSymbol(symbol)
	if ok || totalNumberOfSourceSymbols == 1 {
		// recover packet if possible, remove useless buffers
		return f.updateStateForSomeBlock(symbol.BlockNumber)
	}
	return nil
}

type fecBlocksBuffer struct {
	head      *node		// FIFO queue which will be used to remove old fecBuffers which has not been normally removed (never used, maybe because of the loss of more than one packet)
	tail      *node
	size      uint
	maxSize   uint
	fecBlocks map[BlockNumber]*FECBlock
}

type node struct {
	fecBlockNumber BlockNumber
	next           *node
}

func newFecBlocksBuffer(maxSize uint) *fecBlocksBuffer {
	return &fecBlocksBuffer{
		nil,
		nil,
		0,
		maxSize,
		make(map[BlockNumber]*FECBlock),
	}
}

func (b *fecBlocksBuffer) addFECBlock(block *FECBlock) {
	number := block.BlockNumber
	if b.size == b.maxSize {
		toRemove := b.head
		b.head = b.head.next
		delete(b.fecBlocks, toRemove.fecBlockNumber)
		b.size--
	}
	newNode := &node{number, nil}
	if b.size == 0 {
		b.tail = newNode
		b.head = newNode
	} else {
		b.tail.next = newNode
		b.tail = newNode
	}
	b.fecBlocks[number] = block
	b.size++
}

func (b *fecBlocksBuffer) setSourceSymbolInFECBlock(symbol *BlockSourceSymbol, id BlockSourceID) {
	block, ok:= b.fecBlocks[id.BlockNumber]
	if !ok {
		block := NewFECBlock(id.BlockNumber)
		b.addFECBlock(block)
	}

	block.SetSourceSymbol(symbol, id)
}

type recoveredPacketsBuffer struct {
	buffer 	[]*fec.RecoveredPacket
	start 	int
	size 		int
	maxSize int

}

func newRecoveredPacketsBuffer(maxSize int) *recoveredPacketsBuffer {
	return &recoveredPacketsBuffer{
		buffer: make([]*fec.RecoveredPacket, maxSize),
		start: 0,
		size: 0,
		maxSize: maxSize,
	}
}

func (f *recoveredPacketsBuffer) addPacket(packet *fec.RecoveredPacket) {
	f.buffer[f.start + f.size] = packet
	if f.size < f.maxSize {
		f.size++
	} else {
		f.start = (f.start + 1) % f.maxSize
	}
}

func (f *recoveredPacketsBuffer) getPacket() *fec.RecoveredPacket {
	if f.size == 0 {
		return nil
	}
	packet := f.buffer[f.start]
	f.start = (f.start + 1) % f.maxSize
	f.size--
	return packet
}