package quic

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type streamFrameSorter struct {
	sorter      *frameSorter
	finalOffset protocol.ByteCount
}

func newStreamFrameSorter() *streamFrameSorter {
	return &streamFrameSorter{
		sorter:      newFrameSorter(),
		finalOffset: protocol.MaxByteCount,
	}
}

func (s *streamFrameSorter) Push(f *wire.StreamFrame) error {
	if f.FinBit {
		s.finalOffset = f.Offset + f.DataLen()
	}
	return s.sorter.Push(f.Data, f.Offset)
}

func (s *streamFrameSorter) Pop() ([]byte, bool /* fin */) {
	data, offset := s.sorter.Pop()
	return data, offset+protocol.ByteCount(len(data)) >= s.finalOffset
}
