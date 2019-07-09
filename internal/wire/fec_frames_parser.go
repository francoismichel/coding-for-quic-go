package wire

import (
	"bytes"
)

type FECFramesParser interface {
	ParseRecoveredFrame(r *bytes.Reader) (*RecoveredFrame, error)
	ParseRepairFrame(r *bytes.Reader) (*RepairFrame, error)
}
