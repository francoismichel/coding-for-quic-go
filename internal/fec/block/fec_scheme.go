package block

type FECScheme interface {
}

type BlockFECScheme interface {
	FECScheme
	GetRepairSymbols(block *FECBlock, numberOfSymbols uint) ([]*BlockRepairSymbol, error)
	// recovers the missing source symbols of the block and returns them as a slice. The missing symbols (where == nil in
	// the block) must also be replaced by the recovered symbols in the block itself
	RecoverSymbols(block *FECBlock) ([]*BlockSourceSymbol, error)
	CanRecoverSymbols(block *FECBlock) bool
}