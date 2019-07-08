package fec_utils

import (
	"fmt"
	"github.com/lucas-clemente/quic-go/internal/fec"
	"github.com/lucas-clemente/quic-go/internal/fec/block"
	"github.com/lucas-clemente/quic-go/internal/fec/block/fec_schemes"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

func CreateFrameworkSenderFromFECSchemeID(id protocol.FECSchemeID, controller fec.RedundancyController, symbolSize protocol.ByteCount) (fec.FrameworkSender, wire.RepairFrameParser, error) {
	switch {
	case IsBlockFECScheme(id):
		fecScheme, err := GetBlockFECScheme(id)
		if err != nil {
			return nil, nil, err
		}
		if controller == nil {
			controller = block.NewDefaultRedundancyController()
		}
		if blockController, ok := controller.(block.RedundancyController); !ok {
			return nil, nil, fmt.Errorf("wrong redundancy controller: expected a BlockRedundancyController")
		} else {
			rfp := block.NewRepairFrameParser(symbolSize)
			sender, err := block.NewBlockFrameworkSender(fecScheme, blockController, rfp, symbolSize)
			return sender, rfp, err
		}
	case id == protocol.FECDisabled:
		return nil, nil, nil
	default:
		return nil, nil, fmt.Errorf("invalid sender FECSchemeID: %d", id)
	}
}

func CreateFrameworkReceiverFromFECSchemeID(id protocol.FECSchemeID, symbolSize protocol.ByteCount) (fec.FrameworkReceiver, wire.RepairFrameParser, error) {
	switch {
	case IsBlockFECScheme(id):
		fecScheme, err := GetBlockFECScheme(id)
		if err != nil {
			return nil, nil, err
		}
		rfp := block.NewRepairFrameParser(symbolSize)
		receiver, err := block.NewBlockFrameworkReceiver(fecScheme, rfp, symbolSize)
		return receiver, rfp, err
	case id == protocol.FECDisabled:
		return nil, nil, nil
	default:
		return nil, nil, fmt.Errorf("invalid receiver FECSchemeID: %d", id)
	}
}


func IsBlockFECScheme(id protocol.FECSchemeID) bool {
	switch id {
	case protocol.XORFECScheme, protocol.ReedSolomonFECScheme:
		return true
	default:
		return false
	}
}

func GetBlockFECScheme(id protocol.FECSchemeID) (block.BlockFECScheme, error) {
	switch id {
	case protocol.XORFECScheme:
		return &fec_schemes.XORFECScheme{}, nil
	default:
		return nil, fmt.Errorf("invalid block FEC Scheme ID: %d", id)
	}
}