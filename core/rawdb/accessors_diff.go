package rawdb

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

func WriteBlockStorageDiff(db ethdb.KeyValueWriter, root common.Hash, diff *types.BlockStorageDiff) {
	bytes, _ := rlp.EncodeToBytes(diff)
	err := db.Put(blockStorageDiffKey(root), bytes)
	if err != nil {
		log.Crit("Failed to store block storage diff", "err", err)
	}
}

func ReadBlockStorageDiff(db ethdb.KeyValueReader, root common.Hash) *types.BlockStorageDiff {
	bytes, _ := db.Get(blockStorageDiffKey(root))
	if len(bytes) == 0 {
		return nil
	}
	diff := new(types.BlockStorageDiff)
	err := rlp.DecodeBytes(bytes, diff)
	if err != nil {
		log.Crit("Failed to decode block storage diff", "err", err)
	}
	return diff
}

func ReadBlockStorageDiffRLP(db ethdb.KeyValueReader, root common.Hash) []byte {
	bytes, _ := db.Get(blockStorageDiffKey(root))
	if len(bytes) == 0 {
		return nil
	}
	return bytes
}

func RemoveBlockStorageDiff(db ethdb.KeyValueWriter, root common.Hash) {
	err := db.Delete(blockStorageDiffKey(root))
	if err != nil {
		log.Crit("Failed to delete block storage diff", "err", err)
	}
}
