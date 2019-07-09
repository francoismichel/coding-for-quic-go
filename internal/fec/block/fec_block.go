package block

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/lucas-clemente/quic-go/internal/fec"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"io"
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
// pre: previouslyLostSymbols must be sorted in increasing order
// when an entry is nil in symbols, this means that one or more non-received symbols should be placed at this place in the array if they were received
// post: returns a slice containing the packets that have been recovered (the packets whose no symbol was in the recoveredSymbols)
// are not present in the slice
func MergeSymbolsToPacketPayloads(symbols []*BlockSourceSymbol, recoveredSymbols []BlockOffset) ([]*fec.RecoveredPacket, error) {
	var retVal []*fec.RecoveredPacket
	var currentPacket []byte
	var pn protocol.PacketNumber
	currentPacketIsOfInterest := false
	for i, symbol := range symbols {
		if symbol != nil {
			if !(len(currentPacket) == 0 && !symbol.SynchronizationByte.IsStartOfPacket()) &&
				!(symbol.SynchronizationByte.IsStartOfPacket() && len(currentPacket) > 1) {
				chunk := symbol.PacketChunk
				if symbol.SynchronizationByte.IsPacketNumberPresent() {
					r := bytes.NewReader(chunk)
					pn64, err := utils.ReadVarInt(r)
					if err != nil {
						return retVal, err
					}
					pn = protocol.PacketNumber(pn64)
					chunk = chunk[utils.VarIntLen(pn64):]
				} else if symbol.SynchronizationByte.IsStartOfPacket() {
					return nil, fmt.Errorf("block framework: the first source symbol does not indicate the packet number")
				}
				if len(recoveredSymbols) > 0 && BlockOffset(i) == recoveredSymbols[0] {
					currentPacketIsOfInterest = true
					recoveredSymbols = recoveredSymbols[1:]
				}
				currentPacket = append(currentPacket, chunk...)
				if symbol.SynchronizationByte.IsEndOfPacket() {
					if currentPacketIsOfInterest {
						// add the packet only if it was not available before
						// we assume the pn is encoded as a VarInt at the start of the payload
						retVal = append(retVal, &fec.RecoveredPacket{
							Number:	pn,
							Payload: currentPacket,
						})
					}
					currentPacket = nil
					currentPacketIsOfInterest = false
				}
			}
		} else {
			// we found a nil symbol, forget about the current packet
			currentPacket = nil
			currentPacketIsOfInterest = false
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
	return ParseBlockSourceID(br)
}

func ParseBlockSourceID(r *bytes.Reader) (BlockSourceID, error) {
	number, err := utils.BigEndian.ReadUint24(r)
	if err != nil {
		return BlockSourceID{0, 0}, err
	}
	offset, err := r.ReadByte()
	if err != nil {
		return BlockSourceID{0, 0}, err
	}

	return BlockSourceID{
		BlockNumber: BlockNumber(number),
		BlockOffset: BlockOffset(offset),
	}, nil
}

func (b BlockSourceID) EncodeBlockSourceID(buffer *bytes.Buffer) {
	utils.BigEndian.WriteUint24(buffer, uint32(b.BlockNumber))
	buffer.WriteByte(byte(b.BlockOffset))
}

func (b BlockSourceID) ToFPID() (retval protocol.SourceFECPayloadID) {
	buf := bytes.NewBuffer(nil)
	b.EncodeBlockSourceID(buf)
	copy(retval[:], buf.Bytes())
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
	number, err := utils.BigEndian.ReadUint24(br)
	if err != nil {
		return brid, err
	}
	offset, err := br.ReadByte()
	if err != nil {
		return brid, err
	}

	brid.BlockNumber = BlockNumber(number)
	brid.BlockOffset = BlockOffset(offset)
	return brid, nil
}

func (id BlockRepairID) Write(b *bytes.Buffer) error {
	_, err := b.Write(id.FECSchemeSpecific[:])
	if err != nil {
		return err
	}
	utils.BigEndian.WriteUint24(b, uint32(id.BlockNumber))
	err = b.WriteByte(byte(id.BlockOffset))
	if err != nil {
		return err
	}
	return nil
}

//TODO: maybe the RepairSymbol should have its number in the structure

type FECBlock struct {
	BlockNumber
	RepairSymbols              []*BlockRepairSymbol
	SourceSymbols              []*BlockSourceSymbol
	sourceSymbolsOffsets       map[BlockSourceID]BlockOffset
	repairSymbolsOffsets       map[BlockRepairID]BlockOffset
	TotalNumberOfSourceSymbols uint64
	TotalNumberOfRepairSymbols uint64
}


func NewFECBlock(blockNumber BlockNumber) *FECBlock {
	return &FECBlock{
		BlockNumber:          blockNumber,
		sourceSymbolsOffsets: make(map[BlockSourceID]BlockOffset),
		repairSymbolsOffsets: make(map[BlockRepairID]BlockOffset),
	}
}

func (f *FECBlock) AddSourceSymbol(ss *BlockSourceSymbol) BlockSourceID {
	id := BlockSourceID{
		BlockNumber: f.BlockNumber,
		BlockOffset: BlockOffset(len(f.sourceSymbolsOffsets)),
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
	if symbol.BlockOffset >= BlockOffset(len(f.RepairSymbols)) {
		delta := symbol.BlockOffset - BlockOffset(len(f.RepairSymbols))
		for i := BlockOffset(0) ; i <= delta ; i++ {
			f.RepairSymbols = append(f.RepairSymbols, nil)
		}
	}
	f.RepairSymbols[symbol.BlockOffset] = symbol
	f.repairSymbolsOffsets[symbol.BlockRepairID] = symbol.BlockOffset
}

func (f *FECBlock) AddRepairSymbol(symbol *BlockRepairSymbol) {
	f.RepairSymbols = append(f.RepairSymbols, symbol)
	id := BlockRepairID{
		FECSchemeSpecific: FECSchemeSpecific{},
		BlockSourceID: BlockSourceID{
			BlockNumber: f.BlockNumber,
			BlockOffset: BlockOffset(len(f.RepairSymbols)),
		},
	}
	f.repairSymbolsOffsets[id] = id.BlockOffset
}

func (f *FECBlock) HasID(id BlockSourceID) bool {
	_, ok := f.sourceSymbolsOffsets[id]
	return ok
}

func (f *FECBlock) GetSymbolOffset(id BlockSourceID) BlockOffset {
	return f.sourceSymbolsOffsets[id]
}

func (f *FECBlock) CurrentNumberOfSourceSymbols() uint64 {
	return uint64(len(f.sourceSymbolsOffsets))
}

func (f *FECBlock) CurrentNumberOfRepairSymbols() uint64 {
	return uint64(len(f.repairSymbolsOffsets))
}

func (f *FECBlock) SetRepairSymbols(symbols []*BlockRepairSymbol) {
	for _, symbol := range symbols {
		f.SetRepairSymbol(symbol)
	}
}

func (f *FECBlock) GetRepairSymbols() []*BlockRepairSymbol {
	retVal := make([]*BlockRepairSymbol, len(f.RepairSymbols))
	for _, idx := range f.repairSymbolsOffsets {
		retVal[idx] = f.RepairSymbols[idx]
	}
	return retVal
}

func (f *FECBlock) GetSourceSymbols() []*BlockSourceSymbol {
	retVal := make([]*BlockSourceSymbol, len(f.SourceSymbols))
	for _, idx := range f.sourceSymbolsOffsets {
		retVal[idx] = f.SourceSymbols[idx]
	}
	return retVal

}

type FECFramesParser interface {
	wire.FECFramesParser
	getRepairFrame(b *FECBlock, maxSize protocol.ByteCount) (*wire.RepairFrame, int, error)
	getRepairFrameMetadata(f *wire.RepairFrame) (nss uint64, nrs uint64, id BlockRepairID, nSymbols uint64, err error)
	getRepairFrameMetadataSize(nss uint64, nrs uint64, id BlockRepairID, nSymbols uint64) protocol.ByteCount
	getRecoveredFrame([]protocol.PacketNumber, protocol.ByteCount) (*wire.RecoveredFrame, int, error)
	getRecoveredFramePacketNumbers(frame *wire.RecoveredFrame) ([]protocol.PacketNumber, error)
}

var _ FECFramesParser = &fecFramesParserI{}

type fecFramesParserI struct {
	e protocol.ByteCount
}

func NewFECFramesParser(E protocol.ByteCount) FECFramesParser {
	return &fecFramesParserI{e: E}
}

func (p *fecFramesParserI) ParseRepairFrame(r *bytes.Reader) (*wire.RepairFrame, error) {
	// type byte
	_, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	offset, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	// browse all the metadata
	// nss
	_, err = utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	// nrs
	_, err = utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	// Block repair id
	var id [8]byte
	_, err = r.Read(id[:])
	if err != nil {
		return nil, err
	}
	// nSymbols
	nSymbols, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	offsetRS, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	_, err = r.Seek(offset, io.SeekStart)
	if err != nil {
		return nil, err
	}

	metadataSize := offsetRS - offset

	frame := &wire.RepairFrame{
		Metadata: make([]byte, metadataSize),
		RepairSymbols: make([]byte, protocol.ByteCount(nSymbols)*p.e),
	}
	_, err = r.Read(frame.Metadata)
	if err != nil {
		return nil, err
	}
	_, err = r.Read(frame.RepairSymbols)
	if err != nil {
		return nil, err
	}
	return frame, nil
}

// Ultra simple, non-optimized recovered frame
func (p *fecFramesParserI) ParseRecoveredFrame(r *bytes.Reader) (*wire.RecoveredFrame, error) {
	// this function does not process the payload yet, but reads it in order to know its size
	// type byte
	_, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	payloadStartOffset, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	nRecovered, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	for i := 0 ; i < int(nRecovered) ; i++ {
		_, err := utils.ReadVarInt(r)
		if err != nil {
			return nil, err
		}
	}
	payloadEndOffset, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	payloadLength := payloadEndOffset - payloadStartOffset
	framePayload := make([]byte, payloadLength)

	_, err = r.Seek(payloadStartOffset, io.SeekStart)
	if err != nil {
		return nil, err
	}
	_, err = r.Read(framePayload)
	if err != nil {
		return nil, err
	}
	return &wire.RecoveredFrame{
		Data: framePayload,
	}, nil
}

func (p *fecFramesParserI) getRepairFrameMetadata(f *wire.RepairFrame) (nss uint64, nrs uint64, id BlockRepairID, nSymbols uint64, err error) {
	r := bytes.NewReader(f.Metadata)
	// browse all the metadata
	nss, err = utils.ReadVarInt(r)
	if err != nil {
		return
	}
	nrs, err = utils.ReadVarInt(r)
	if err != nil {
		return
	}
	// Block repair id FEC Scheme-specific
	_, err = r.Read(id.FECSchemeSpecific[:])
	if err != nil {
		return
	}
	id.BlockSourceID, err = ParseBlockSourceID(r)
	if err != nil {
		return
	}
	// nSymbols
	nSymbols, err = utils.ReadVarInt(r)
	if err != nil {
		return
	}
	if protocol.ByteCount(len(f.RepairSymbols)) % p.e != 0 {
		err = fmt.Errorf("getRepairFrameMetadata: len(f.RepairSymbols) (%d) is not a multiple of E (%d)", len(f.RepairSymbols), p.e)
		return
	}
	if p.e*protocol.ByteCount(nSymbols) != protocol.ByteCount(len(f.RepairSymbols)) {
		err = fmt.Errorf("getRepairFrameMetadata: len(f.RepairSymbols) (%d) does not match the number of symbols announces in the metadata (%d symbols -> %d bytes)", len(f.RepairSymbols), nSymbols, protocol.ByteCount(nSymbols)*p.e)
		return
	}
	return
}

func (p *fecFramesParserI) getRepairFrameMetadataSize(nss uint64, nrs uint64, id BlockRepairID, nSymbols uint64) protocol.ByteCount {
	return utils.VarIntLen(nss) + utils.VarIntLen(nrs) + 8 + utils.VarIntLen(nSymbols)
}


func (f *fecFramesParserI) getRepairFrame(block *FECBlock, maxSize protocol.ByteCount) (*wire.RepairFrame, int, error) {
	if maxSize == 0 {
		return nil, 0, nil
	}
	// remove the type byte
	maxSize--
	brid := BlockRepairID{
		FECSchemeSpecific: FECSchemeSpecific{},
		BlockSourceID: block.RepairSymbols[0].BlockSourceID,
	}
	// the metadata size if we only send 1 repair symbol
	minMdSize := f.getRepairFrameMetadataSize(block.TotalNumberOfSourceSymbols, block.TotalNumberOfRepairSymbols, brid, 1)
	if maxSize < minMdSize + f.e {
		// not enough size to send at least one repair symbol
		return nil, 0, nil
	}
	// we can send at least one repair symbol and we found one block to send
	b := &bytes.Buffer{}

	// write the metadata
	utils.WriteVarInt(b, uint64(block.TotalNumberOfSourceSymbols))
	utils.WriteVarInt(b, uint64(block.TotalNumberOfRepairSymbols))
	err := brid.Write(b)
	if err != nil {
		return nil, 0, err
	}
	// compute the number of symbols to send
	nSymbols := utils.MinByteCount((maxSize-protocol.ByteCount(b.Len())) / f.e, protocol.ByteCount(len(block.RepairSymbols)))
	lenSize := utils.VarIntLen(uint64(nSymbols))
	if nSymbols * f.e + lenSize > maxSize - protocol.ByteCount(b.Len()) {
		// not enough size to encode the length, let's make some place
		nSymbols--
	}
	utils.WriteVarInt(b, uint64(nSymbols))
	// write all the symbols
	for i := 0 ; i < int(nSymbols) ; i++ {
		b.Write(block.RepairSymbols[i].Data)
	}

	payload := b.Bytes()
	return &wire.RepairFrame{
		Metadata: payload[:len(payload) - int(nSymbols*f.e)],
		RepairSymbols: payload[len(payload) - int(nSymbols*f.e):],
	}, int(nSymbols), nil
}

func (p *fecFramesParserI) getRecoveredFrame(pns []protocol.PacketNumber, maxLen protocol.ByteCount) (*wire.RecoveredFrame, int, error) {
	if len(pns) == 0 {
		return nil, 0, nil
	}
	writtenPn := 0
	maxLen--	// type byte
	b := bytes.NewBuffer(nil)
	utils.WriteVarInt(b, uint64(len(pns)))
	for _, pn := range pns {
		lenPn := utils.VarIntLen(uint64(pn))
		if maxLen < lenPn {
			break
		}
		utils.WriteVarInt(b, uint64(pn))
		maxLen -= lenPn
		writtenPn++
	}
	return &wire.RecoveredFrame{
		Data: b.Bytes(),
	}, writtenPn, nil
}

func (p *fecFramesParserI) getRecoveredFramePacketNumbers(rf *wire.RecoveredFrame) ([]protocol.PacketNumber, error) {
	b := bytes.NewBuffer(rf.Data)
	nRecoveredPacketNumbers, err := utils.ReadVarInt(b)
	if err != nil {
		return nil, err
	}
	var pns []protocol.PacketNumber
	for i := uint64(0) ; i < nRecoveredPacketNumbers ; i++ {
		pn, err := utils.ReadVarInt(b)
		if err != nil {
			return nil, err
		}
		pns = append(pns, protocol.PacketNumber(pn))
	}
	return pns, nil
}