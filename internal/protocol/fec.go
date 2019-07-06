package protocol

const REPAIR_FRAME_TYPE = 42

type FECPayloadID	[8]byte

const MAX_FEC_SYMBOL_SIZE = MaxPacketSizeIPv6

type FECSchemeID = byte

const XORFECScheme FECSchemeID = 0
const ReedSolomonFECScheme FECSchemeID = 1
const RLCFECScheme FECSchemeID = 2
