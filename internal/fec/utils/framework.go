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
	switch id {
	case protocol.FECDisabled:
		return nil, nil, nil
	case protocol.XORFECScheme:
		if controller == nil {
			controller = block.NewDefaultRedundancyController()
		}
		if blockController, ok := controller.(block.RedundancyController); !ok {
			return nil, nil, fmt.Errorf("wrong redundancy controller: expected a BlockRedundancyController")
		} else {
			rfp := block.NewRepairFrameParser(symbolSize)
			sender, err := block.NewBlockFrameworkSender(&fec_schemes.XORFECScheme{}, blockController, rfp, symbolSize)
			return sender, rfp, err
		}
	default:
		return nil, nil, fmt.Errorf("invalid sender FECSchemeID: %d", id)
	}
}

func CreateFrameworkReceiverFromFECSchemeID(id protocol.FECSchemeID, symbolSize protocol.ByteCount) (fec.FrameworkReceiver, wire.RepairFrameParser, error) {
	switch id {
	case protocol.FECDisabled:
		return nil, nil, nil
	case protocol.XORFECScheme:
		rfp := block.NewRepairFrameParser(symbolSize)
		receiver, err := block.NewBlockFrameworkReceiver(&fec_schemes.XORFECScheme{}, rfp, symbolSize)
		return receiver, rfp, err
	default:
		return nil, nil, fmt.Errorf("invalid receiver FECSchemeID: %d", id)
	}
}
