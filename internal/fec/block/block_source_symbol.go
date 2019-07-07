package block

import (
	"errors"
	"github.com/lucas-clemente/quic-go/internal/fec"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

const SYNCHRONIZATION_BYTE_START_OF_PACKET = 0
const SYNCHRONIZATION_BYTE_MIDDLE_OF_PACKET = 1
const SYNCHRONIZATION_BYTE_END_OF_PACKET = 2

type BlockSourceSymbol struct {
	fec.SourceSymbol
	SynchronizationByte byte
	PacketChunk []byte
}

func ParseBlockSourceSymbol(symbol []byte) *BlockSourceSymbol {
	return &BlockSourceSymbol{
		SourceSymbol: fec.SourceSymbol{
			Data: symbol,
		},
		SynchronizationByte: symbol[0],
		PacketChunk: symbol[1:],
	}
}

func SourceSymbolToBlockSourceSymbol(symbol *fec.SourceSymbol) *BlockSourceSymbol {
	return &BlockSourceSymbol{
		SourceSymbol: *symbol,
		SynchronizationByte: symbol.Data[0],
		PacketChunk: symbol.Data[1:],

	}
}

func PayloadToSourceSymbols(payload []byte, E protocol.ByteCount) ([]*BlockSourceSymbol, error) {
	packetChunkSize := int(E-1)
	var retVal []*BlockSourceSymbol
	if len(payload) % packetChunkSize != 0 {
		return nil, errors.New("payload size is not aligned with e")
	}
	for i := 0 ; i < len(payload) / packetChunkSize ; i++ {
		data := make([]byte, E)
		switch {
		case i == 0:
			data[0] = SYNCHRONIZATION_BYTE_START_OF_PACKET
		case i < len(payload) / packetChunkSize - 1:
			data[0] = SYNCHRONIZATION_BYTE_MIDDLE_OF_PACKET
		case i == len(payload) / packetChunkSize - 1:
			data[0] = SYNCHRONIZATION_BYTE_END_OF_PACKET
		}
		copy(data[1:], payload[:packetChunkSize])
		retVal = append(retVal, ParseBlockSourceSymbol(data))
	}
	return retVal, nil
}