package wire

import (
	"bytes"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// TODO: this frame should be FECScheme (or FECFramework)-specific

// A FECSrcFPIFrame identifies a source symbol
type FECSrcFPIFrame struct{
	protocol.SourceFECPayloadID
}

func parseFECSrcFPIFrame(r *bytes.Reader, version protocol.VersionNumber) (*FECSrcFPIFrame, error) {
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	frame := &FECSrcFPIFrame{}
	if _, err := r.Read(frame.SourceFECPayloadID[:]); err != nil {
		return nil, err
	} else {
		return frame, nil
	}
}

func (f *FECSrcFPIFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	b.WriteByte(protocol.FEC_SRC_FPI_FRAME_TYPE)
	b.Write(f.SourceFECPayloadID[:])
	return nil
}

// Length of a written frame
func (f *FECSrcFPIFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	return protocol.ByteCount(1 + len(f.SourceFECPayloadID))
}
