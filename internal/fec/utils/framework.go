package fec_utils

import (
	"fmt"
	"github.com/lucas-clemente/quic-go/internal/fec"
	"github.com/lucas-clemente/quic-go/internal/fec/block"
	"github.com/lucas-clemente/quic-go/internal/fec/block/fec_schemes"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

func CreateFrameworkSenderFromFECSchemeID(id protocol.FECSchemeID, controller fec.RedundancyController, symbolSize uint16) (fec.FrameworkSender, error) {
	switch id {
	case protocol.XORFECScheme:
		if controller == nil {
			controller = block.NewDefaultRedundancyController()
		}
		if blockController, ok := controller.(block.RedundancyController); !ok {
			return nil, fmt.Errorf("wrong redundancy controller: expected a BlockRedundancyController")
		} else {
			return block.NewBlockFrameworkSender(&fec_schemes.XORFECScheme{}, blockController, symbolSize), nil
		}
	default:
		return nil, fmt.Errorf("invalid sender FECSchemeID: %d", id)
	}
}

func CreateFrameworkReceiverFromFECSchemeID(id protocol.FECSchemeID, symbolSize uint16) (fec.FrameworkReceiver, error) {
	switch id {
	case protocol.XORFECScheme:
		return block.NewBlockFrameworkReceiver(&fec_schemes.XORFECScheme{}, symbolSize), nil
	default:
		return nil, fmt.Errorf("invalid receiver FECSchemeID: %d", id)
	}
}
