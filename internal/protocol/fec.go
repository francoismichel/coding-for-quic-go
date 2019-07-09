package protocol

const FEC_SRC_FPI_FRAME_TYPE = 0x21
const REPAIR_FRAME_TYPE = 0x22
const RECOVERED_FRAME_TYPE = 0x23

type SourceFECPayloadID [4]byte

const MAX_FEC_SYMBOL_SIZE = MaxPacketSizeIPv6

const FEC_DEFAULT_SYMBOL_SIZE = 200

type FECSchemeID byte

const FECDisabled FECSchemeID = 0
const XORFECScheme FECSchemeID = 1
const ReedSolomonFECScheme FECSchemeID = 2
const RLCFECScheme FECSchemeID = 3

func (f FECSchemeID) String() string {
	switch f {
	case XORFECScheme:
		return "XOR"
	case ReedSolomonFECScheme:
		return "ReedSolomon"
	default:
		return "unknown"
	}
}