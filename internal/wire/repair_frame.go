package wire

import (
	"bytes"
	"fmt"
	"github.com/lucas-clemente/quic-go/internal/utils"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type RepairFrame struct{
	Payload []byte
}


func parseRepairFrame(r *bytes.Reader, version protocol.VersionNumber) (*RepairFrame, error) {
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}
	length, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	if length > protocol.MAX_FEC_SYMBOL_SIZE {
		return nil, fmt.Errorf("decoded repair frame too big: %d > %d", length, protocol.MAX_FEC_SYMBOL_SIZE)
	}
	data := make([]byte, length)
	_, err = r.Read(data)
	if err != nil {
		return nil, err
	}
	return &RepairFrame{
		Payload: data,
	}, nil
}

func (f *RepairFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	b.WriteByte(protocol.REPAIR_FRAME_TYPE)
	if len(f.Payload) > protocol.MAX_FEC_SYMBOL_SIZE {
		return fmt.Errorf("encoding repair frame too big: %d > %d", len(f.Payload), protocol.MAX_FEC_SYMBOL_SIZE)
	}
	utils.WriteVarInt(b, uint64(len(f.Payload)))
	b.Write(f.Payload)
	return nil
}

// Length of a written frame
func (f *RepairFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	return 1 + utils.VarIntLen(uint64(len(f.Payload))) + protocol.ByteCount(len(f.Payload))
}
