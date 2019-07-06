package block

import (
	"bytes"
	"errors"
	"github.com/lucas-clemente/quic-go/internal/fec"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

const MAX_BLOCK_OFFSET = 0xFF

type FECSchemeSpecific [4]byte
type BlockNumber uint32
type BlockOffset uint8

type BlockRepairSymbol struct {
	BlockRepairID
	Data []byte
}

// pre: contiguous source symbols in the array symbols must be source symbols that have been sent contiguously one after the other
// when an entry is nil in symbols, this means that one or more non-received symbols should be placed at this place in the array if they were received
func MergeSymbolsToPacketPayloads(symbols []*BlockSourceSymbol) ([]*fec.RecoveredPacket, error) {
	var retVal []*fec.RecoveredPacket
	var currentPacket []byte
	for _, symbol := range symbols {
		if symbol != nil {
			if !(len(currentPacket) == 0 && symbol.SynchronizationByte != SYNCHRONIZATION_BYTE_START_OF_PACKET) &&
				!(symbol.SynchronizationByte == SYNCHRONIZATION_BYTE_START_OF_PACKET && len(currentPacket) > 0){
				currentPacket = append(currentPacket, symbol.PacketChunk...)
				if symbol.SynchronizationByte == SYNCHRONIZATION_BYTE_END_OF_PACKET {
					r := bytes.NewReader(currentPacket)
					// we assume the pn is encoded as a VarInt at the start of the payload
					pn, err := utils.ReadVarInt(r)
					if err != nil {
						return retVal, nil
					}
					retVal = append(retVal, &fec.RecoveredPacket{
						Number:	protocol.PacketNumber(pn),
						Payload: currentPacket[utils.VarIntLen(pn):],
					})
					currentPacket = nil
				}
			}
		} else {
			// we found a nil symbol, forget about the current packet
			currentPacket = currentPacket[0:0]
		}
	}
	return retVal, nil
}


type BlockSourceID struct {
	BlockNumber
	BlockOffset
}

func NewBlockSourceID(id [4]byte) (BlockSourceID, error) {
	br := bytes.NewReader(id[:])
	number, err := utils.BigEndian.ReadUintN(br, 3)
	if err != nil {
		return BlockSourceID{0, 0}, err
	}
	offset, err := utils.BigEndian.ReadUintN(br, 1)
	if err != nil {
		return BlockSourceID{0, 0}, err
	}

	return BlockSourceID{
		BlockNumber: BlockNumber(number),
		BlockOffset: BlockOffset(offset),
	}, nil
}

func (b BlockSourceID) EncodeBlockSourceID(buffer *bytes.Buffer) {
	utils.BigEndian.WriteUintN(buffer, 3, uint64(b.BlockNumber))
	utils.BigEndian.WriteUintN(buffer, 1, uint64(b.BlockOffset))
}

func (b BlockSourceID) ToFPID() (retval protocol.FECPayloadID) {
	buf := bytes.NewBuffer(retval[:])
	b.EncodeBlockSourceID(buf)
	return retval
}

func (b BlockSourceID) NextOffset() (BlockSourceID, error) {
	if b.BlockOffset == MAX_BLOCK_OFFSET {
		return b, errors.New("next offset over the maximum value")
	}

	return BlockSourceID{
		BlockNumber: b.BlockNumber,
		BlockOffset: b.BlockOffset+1,
	}, nil
}

type BlockRepairID struct {
	FECSchemeSpecific
	BlockSourceID
}

func NewBlockRepairID(id [8]byte) (brid BlockRepairID, err error) {
	brid = BlockRepairID{}
	copy(brid.FECSchemeSpecific[:], id[:4])
	br := bytes.NewReader(id[4:])
	number, err := utils.BigEndian.ReadUintN(br, 3)
	if err != nil {
		return brid, err
	}
	offset, err := utils.BigEndian.ReadUintN(br, 1)
	if err != nil {
		return brid, err
	}

	brid.BlockNumber = BlockNumber(number)
	brid.BlockOffset = BlockOffset(offset)
	return brid, nil
}

//TODO: maybe the RepairSymbol should have its number in the structure

type FECBlock struct {
	BlockNumber
	RepairSymbols              []*BlockRepairSymbol
	SourceSymbols              []*BlockSourceSymbol
	sourceSymbolsOffsets       map[BlockSourceID]BlockOffset
	TotalNumberOfSourceSymbols int
	TotalNumberOfRepairSymbols int
}


func NewFECBlock(blockNumber BlockNumber) *FECBlock {
	return &FECBlock{
		BlockNumber:          blockNumber,
		sourceSymbolsOffsets: make(map[BlockSourceID]BlockOffset),
		SourceSymbols:        make([]*BlockSourceSymbol, 0),
	}
}

func (f *FECBlock) AddSourceSymbol(ss *BlockSourceSymbol) BlockSourceID {
	id := BlockSourceID{
		BlockNumber: f.BlockNumber,
		BlockOffset: BlockOffset(len(f.SourceSymbols)),
	}
	f.SourceSymbols = append(f.SourceSymbols, ss)
	f.sourceSymbolsOffsets[id] = id.BlockOffset
	return id
}

func (f *FECBlock) SetSourceSymbol(ss *BlockSourceSymbol, id BlockSourceID) {
	if id.BlockOffset >= BlockOffset(len(f.SourceSymbols)) {
		delta := id.BlockOffset - BlockOffset(len(f.SourceSymbols))
		for i := BlockOffset(0) ; i <= delta ; i++ {
			f.SourceSymbols = append(f.SourceSymbols, nil)
		}
	}
	f.SourceSymbols[id.BlockOffset] = ss
	f.sourceSymbolsOffsets[id] = id.BlockOffset
	return
}

// pre: the BlockOffset of symbol must be smaller than the length of f.RepairSymbols
func (f *FECBlock) SetRepairSymbol(symbol *BlockRepairSymbol) {
	f.RepairSymbols[symbol.BlockOffset] = symbol
}

func (f *FECBlock) AddRepairSymbol(symbol *BlockRepairSymbol) {
	f.RepairSymbols = append(f.RepairSymbols, symbol)
}

func (f *FECBlock) HasID(id BlockSourceID) bool {
	_, ok := f.sourceSymbolsOffsets[id]
	return ok
}

func (f *FECBlock) GetSymbolOffset(id BlockSourceID) BlockOffset {
	return f.sourceSymbolsOffsets[id]
}
func (f *FECBlock) CurrentNumberOfSymbols() int {
	return len(f.sourceSymbolsOffsets)
}

func (f *FECBlock) GetRepairSymbols() []*BlockRepairSymbol {
	return f.RepairSymbols
}

func (f *FECBlock) SetRepairSymbols(symbols []*BlockRepairSymbol) {
	f.RepairSymbols = symbols
}

func (f *FECBlock) GetSourceSymbols() []*BlockSourceSymbol {
	retVal := make([]*BlockSourceSymbol, len(f.SourceSymbols))
	for _, idx := range f.sourceSymbolsOffsets {
		retVal[idx] = f.SourceSymbols[idx]
	}
	return retVal

}