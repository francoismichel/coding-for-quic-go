package fec_schemes

import (
	"errors"
	. "github.com/lucas-clemente/quic-go/internal/fec/block"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"runtime"
	"unsafe"
)

type XORFECScheme struct {
	dontOptimize bool
}

var _ BlockFECScheme = &XORFECScheme{}

var XORFECSchemeCannotRecoverPacket = errors.New("XORFECScheme: cannot recover packet")
var XORFECSchemeCannotGetRepairSymbol = errors.New("XORFECScheme: cannot get repair symbol")
var XORFECSchemeTooMuchSymbolsNeeded = errors.New("XORFECScheme: cannot generate enough repair symbols")

func (f *XORFECScheme) CanRecoverSymbols(block *FECBlock) bool {
	return block.CurrentNumberOfSourceSymbols() == block.TotalNumberOfSourceSymbols-1 && block.CurrentNumberOfRepairSymbols() == 1
}

func (f *XORFECScheme) RecoverSymbols(block *FECBlock) ([]*BlockSourceSymbol, error) {
	if !f.CanRecoverSymbols(block) {
		return nil, XORFECSchemeCannotRecoverPacket
	}
	missing := 0
	current := block.RepairSymbols[0].Data
	for i, p := range block.GetSourceSymbols() {
		if p != nil {
			current = f.XOR(current, p.Data)
		} else {
			missing = i
		}
	}
	recoveredSymbol := ParseBlockSourceSymbol(current)
	block.SourceSymbols[missing] = recoveredSymbol
	return []*BlockSourceSymbol{
		recoveredSymbol,
	}, nil
}

func (f *XORFECScheme) GetRepairSymbols(block *FECBlock, numberOfSymbols uint) ([]*BlockRepairSymbol, error) {
	var fecSchemeSpecific [4]byte
	packets := block.GetSourceSymbols()
	max := 0
	for _, p := range block.GetSourceSymbols() {
		if max < len(p.Data) {
			max = len(p.Data)
		}
	}

	if len(packets) == 0 {
		return nil, XORFECSchemeCannotGetRepairSymbol
	}
	if numberOfSymbols > 1 {
		return nil, XORFECSchemeTooMuchSymbolsNeeded
	}
	var current []byte
	first := true
	for _, p := range packets {
		if p != nil {
			if first {
				current = p.Data
				first = false
			} else {
				current = f.XOR(current, p.Data)
			}
		}
	}
	return []*BlockRepairSymbol{{
		BlockRepairID: BlockRepairID{
			FECSchemeSpecific: fecSchemeSpecific,
			BlockSourceID: BlockSourceID{
				BlockNumber: block.BlockNumber,
				BlockOffset: BlockOffset(0),
			},
		},
		Data:          current,
	}}, nil
}


func (f *XORFECScheme) XOR(a, b []byte) []byte {
	if !f.dontOptimize && supportsUnaligned {
		return fastXORBytes(a, b)
	} else {
		return slowXOR(a, b)
	}
}

func slowXOR(a []byte, b []byte) []byte {
	var retVal []byte
	if len(a) >= len(b) {
		retVal = make([]byte, protocol.MaxReceivePacketSize)[:len(a)]
	} else {
		retVal = make([]byte, protocol.MaxReceivePacketSize)[:len(b)]
	}
	for i := 0; i < len(retVal); i++ {
		if i >= len(a) {
			retVal[i] = b[i]
		} else if i >= len(b) {
			retVal[i] = a[i]
		} else {
			retVal[i] = a[i] ^ b[i]
		}
	}
	return retVal
}

const wordSize = int(unsafe.Sizeof(uintptr(0)))
const supportsUnaligned = runtime.GOARCH == "386" || runtime.GOARCH == "amd64" || runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le" || runtime.GOARCH == "s390x"
// fastXORBytes xors in bulk. It only works on architectures that
// support unaligned read/writes.
func fastXORBytes(a, b []byte) []byte {
	n := len(a)
	nMax := len(b)
	if len(b) < n {
		n = len(b)
		nMax = len(a)
	}
	if n == 0 {
		return nil
	}
	dst := make([]byte, nMax)
	w := n / wordSize
	if w > 0 {
		dw := *(*[]uintptr)(unsafe.Pointer(&dst))
		aw := *(*[]uintptr)(unsafe.Pointer(&a))
		bw := *(*[]uintptr)(unsafe.Pointer(&b))
		// xor all the full words
		for i := 0; i < w; i++ {
			dw[i] = aw[i] ^ bw[i]
		}
	}
	// xor the remaining bytes
	for i := (n - n%wordSize); i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	for i := n ; i < nMax ; i++ {
		if len(b) > len(a) {
			dst[i] = b[i]
		} else {
			dst[i] = a[i]
		}
	}
	return dst
}

