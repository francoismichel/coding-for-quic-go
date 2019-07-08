package fec_schemes

import (
	"errors"
	"github.com/klauspost/reedsolomon"
	. "github.com/lucas-clemente/quic-go/internal/fec/block"
)

var _ BlockFECScheme = &ReedSolomonFECScheme{}

var ReedSolomonNoRepairSymbolInFECGroup = errors.New("ReedSolomon FEC Scheme: impossible to recover FEC Group with no repair symbol")
var ReedSolomonInvalidNumberOfSymbols		= errors.New("ReedSolomon FEC Scheme: impossible to build FEC Scheme with a number of symbols equal to zero")

// The number of source symbols will be determined by the number
// of packets in the fecGroup in the Generate and Recover functions
func NewReedSolomonFECScheme() (*ReedSolomonFECScheme, error) {
	return &ReedSolomonFECScheme{
		schemes: make(map[[2]uint]reedsolomon.Encoder),
		performCaching: true,
	}, nil
}

type ReedSolomonFECScheme struct {
	schemes map[[2]uint]reedsolomon.Encoder
	currentRedundancy [2]uint
	performCaching bool
}


func (f *ReedSolomonFECScheme) GetRepairSymbols(block *FECBlock, numberOfSymbols uint) ([]*BlockRepairSymbol, error) {
	sourceSymbols := block.SourceSymbols
	if len(sourceSymbols) == 0 {
		return nil, nil
	}
	symbolLength := len(sourceSymbols[0].Data)
	reedSolomonInput := make([][]byte, len(sourceSymbols) + int(numberOfSymbols))
	for i := range sourceSymbols {
		reedSolomonInput[i] = sourceSymbols[i].Data
	}

	for i := len(sourceSymbols) ; i < len(reedSolomonInput) ; i++ {
		reedSolomonInput[i] = make([]byte, symbolLength)
	}
	enc, err := f.getEncoder(uint(len(sourceSymbols)), numberOfSymbols)
	if err != nil {
		return nil, err
	}

	err = enc.Encode(reedSolomonInput) // won't error as the shards are of equal size
	if err != nil {
		return nil, err
	}
	repairSymbols := make([]*BlockRepairSymbol, len(reedSolomonInput[len(sourceSymbols):]))
	for i, symbol := range reedSolomonInput[len(sourceSymbols):] {
		repairSymbols[i] = &BlockRepairSymbol{
			BlockRepairID: BlockRepairID{
				FECSchemeSpecific: FECSchemeSpecific{},
				BlockSourceID: BlockSourceID{
					BlockNumber: block.BlockNumber,
					BlockOffset: BlockOffset(i),
				},
			},
			Data: symbol,
		}
	}
	return repairSymbols, nil
}
func (f *ReedSolomonFECScheme) RecoverSymbols(block *FECBlock) ([]*BlockSourceSymbol, error) {
	if block.TotalNumberOfRepairSymbols == 0 {
		return nil, ReedSolomonNoRepairSymbolInFECGroup
	}
	k, n := block.TotalNumberOfSourceSymbols, block.TotalNumberOfSourceSymbols + block.TotalNumberOfRepairSymbols

	enc, err := f.getEncoder(uint(k), uint(n-k))
	if err != nil {
		return nil, err
	}
	reedSolomonInput := make([][]byte, n)
	var indicesToRecover []int
	// Regularize the size of the packets for the decoder
	for i, symbol := range block.SourceSymbols {
		if symbol != nil {
			reedSolomonInput[i] = symbol.Data
		} else {
			// this ss is missing
			indicesToRecover = append(indicesToRecover, i)
		}
	}

	for _, rs := range block.RepairSymbols {
		reedSolomonInput[block.TotalNumberOfSourceSymbols + uint64(rs.BlockOffset)] = rs.Data
	}

	err = enc.ReconstructData(reedSolomonInput)
	if err != nil {
		return nil, err
	}


	var recoveredSymbols []*BlockSourceSymbol
	for _, i := range indicesToRecover {
		recovered := ParseBlockSourceSymbol(reedSolomonInput[i])
		block.SetSourceSymbol(recovered, BlockSourceID{
			BlockNumber: block.BlockNumber,
			BlockOffset: BlockOffset(i),
		})
		recoveredSymbols = append(recoveredSymbols, recovered)
	}
	return recoveredSymbols, nil
}

func (f *ReedSolomonFECScheme) CanRecoverSymbols(block *FECBlock) bool {
	return block.CurrentNumberOfRepairSymbols() != 0 &&
		block.TotalNumberOfSourceSymbols != 0 &&
		block.CurrentNumberOfSourceSymbols() < block.TotalNumberOfSourceSymbols && // there is nothing to recover if this is not true
		block.CurrentNumberOfSourceSymbols() + block.CurrentNumberOfRepairSymbols() >= block.TotalNumberOfSourceSymbols // impossible to recover if this is not true
}

func (f *ReedSolomonFECScheme) getEncoder(nSourceSymbols, nRepairSymbols uint) (reedsolomon.Encoder, error) {
	if f.performCaching {
		f.currentRedundancy[0] = nSourceSymbols
		f.currentRedundancy[1] = nRepairSymbols
		if _, ok := f.schemes[f.currentRedundancy]; !ok {
			// encode
			enc, err := reedsolomon.New(int(nSourceSymbols), int(nRepairSymbols))
			if err != nil {
				return nil, err
			}

			f.schemes[f.currentRedundancy] = enc
		}
		return f.schemes[f.currentRedundancy], nil
	} else {
		return reedsolomon.New(int(nSourceSymbols), int(nRepairSymbols))
	}
}