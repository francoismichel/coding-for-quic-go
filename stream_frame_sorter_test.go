package quic

import (
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("STREAM frame sorter", func() {
	var s *streamFrameSorter

	BeforeEach(func() {
		s = newStreamFrameSorter()
	})

	It("pushes and pops frames", func() {
		Expect(s.Push(&wire.StreamFrame{
			Data:   []byte("bar"),
			Offset: 3,
		})).To(Succeed())
		data, _ := s.Pop()
		Expect(data).To(BeNil())
		Expect(s.Push(&wire.StreamFrame{Data: []byte("foo")})).To(Succeed())
		data, fin := s.Pop()
		Expect(data).To(Equal([]byte("foo")))
		Expect(fin).To(BeFalse())
		data, fin = s.Pop()
		Expect(data).To(Equal([]byte("bar")))
		Expect(fin).To(BeFalse())
	})

	Context("FIN handling", func() {
		It("saves a FIN at offset 0", func() {
			Expect(s.Push(&wire.StreamFrame{FinBit: true})).To(Succeed())
			data, fin := s.Pop()
			Expect(data).To(BeEmpty())
			Expect(fin).To(BeTrue())
			data, fin = s.Pop()
			Expect(data).To(BeNil())
			Expect(fin).To(BeTrue())
		})

		It("saves a FIN frame at non-zero offset", func() {
			Expect(s.Push(&wire.StreamFrame{
				Data:   []byte("foobar"),
				FinBit: true,
			})).To(Succeed())
			data, fin := s.Pop()
			Expect(data).To(Equal([]byte("foobar")))
			Expect(fin).To(BeTrue())
			data, fin = s.Pop()
			Expect(data).To(BeNil())
			Expect(fin).To(BeTrue())
		})

		It("sets the FIN if a stream is closed after receiving some data", func() {
			Expect(s.Push(&wire.StreamFrame{Data: []byte("foobar")})).To(Succeed())
			Expect(s.Push(&wire.StreamFrame{
				Offset: 6,
				FinBit: true,
			})).To(Succeed())
			data, fin := s.Pop()
			Expect(data).To(Equal([]byte("foobar")))
			Expect(fin).To(BeTrue())
			data, fin = s.Pop()
			Expect(data).To(BeNil())
			Expect(fin).To(BeTrue())
		})
	})
})
