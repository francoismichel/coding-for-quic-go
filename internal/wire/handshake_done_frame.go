package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// A HandshakeDoneFrame is a ping frame
type HandshakeDoneFrame struct{}

// ParseHandshakeDoneFrame parses a HandshakeDone frame
func parseHandshakeDoneFrame(r *bytes.Reader, version protocol.VersionNumber) (*HandshakeDoneFrame, error) {
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}
	return &HandshakeDoneFrame{}, nil
}

func (f *HandshakeDoneFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	typeByte := uint8(0x42)
	b.WriteByte(typeByte)
	return nil
}

// Length of a written frame
func (f *HandshakeDoneFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	return 1
}
