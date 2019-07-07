package wire

import (
	"bytes"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type RepairFrame struct{
	Metadata      []byte
	RepairSymbols []byte
}

func (f *RepairFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	err := b.WriteByte(protocol.REPAIR_FRAME_TYPE)
	if err != nil {
		return err
	}
	_, err = b.Write(f.Metadata)
	if err != nil {
		return err
	}
	_, err = b.Write(f.RepairSymbols)
	if err != nil {
		return err
	}
	return nil
}

// Length of a written frame
func (f *RepairFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	return protocol.ByteCount(1 + len(f.Metadata) + len(f.RepairSymbols))
}
