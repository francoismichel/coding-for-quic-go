package wire

import (
	"bytes"
)

type RepairFrameParser interface {
	ParseRepairFrame(r *bytes.Reader) (*RepairFrame, error)
}
