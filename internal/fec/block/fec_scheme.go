package block

type FECScheme interface {
}

type BlockFECScheme interface {
	FECScheme
	GetRepairSymbols(block *FECBlock, numberOfSymbols uint) ([]*BlockRepairSymbol, error)
	RecoverSymbols(block *FECBlock) ([]*BlockSourceSymbol, error)
	CanRecoverSymbols(block *FECBlock) bool
}
