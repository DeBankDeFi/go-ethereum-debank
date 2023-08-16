package types

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

type NewAccount struct {
	Address  common.Hash  `json:"address"`
	Balance  *uint256.Int `json:"balance"`
	Nonce    uint64       `json:"nonce"`
	CodeHash common.Hash  `json:"codeHash"`
}

type NewCode struct {
	CodeHash common.Hash `json:"codeHash"`
	Code     []byte      `json:"code"`
}

type IndexValuePair struct {
	Index common.Hash
	Value *uint256.Int
}

type AccountStorageDiff struct {
	Address common.Hash
	Values  []IndexValuePair
}

type BlockStorageDiff struct {
	Hash            common.Hash
	ParentHash      common.Hash
	NewAccounts     []NewAccount
	DeletedAccounts []common.Hash
	StorageDiff     []AccountStorageDiff
	NewCodes        []NewCode
}
