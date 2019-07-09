package wire

import (
	"bytes"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// the RECOVERED frame format is defined by the underlying FEC Framework/Scheme
type RecoveredFrame struct {
	Data []byte
}

func (f *RecoveredFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	err := b.WriteByte(protocol.RECOVERED_FRAME_TYPE)
	if err != nil {
		return err
	}
	_, err = b.Write(f.Data)
	if err != nil {
		return err
	}
	return nil
}

// Length of a written frame
func (f *RecoveredFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	return protocol.ByteCount(1 + len(f.Data))
}