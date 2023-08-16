package eth

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

type PublicLeafAgeAPI struct {
	e *Ethereum
}

func NewPublicLeafAgeAPI(e *Ethereum) *PublicLeafAgeAPI {
	return &PublicLeafAgeAPI{e: e}
}

func (api *PublicLeafAgeAPI) BlockDiff(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash, reExec bool) (hexutil.Bytes, error) {
	if api.e.blockchain == nil {
		return []byte{}, fmt.Errorf("blockchain corruput")
	}
	block, err := api.e.APIBackend.BlockByNumberOrHash(ctx, blockNrOrHash)
	if err != nil {
		log.Error("Failed to get block", "err", err)
		return nil, err
	}
	parentBlock, err := api.e.APIBackend.BlockByNumberOrHash(ctx, rpc.BlockNumberOrHash{BlockHash: &block.Header().ParentHash})
	if err != nil {
		log.Error("Failed to get parent block", "err", err)
		return nil, err
	}
	var blockStorageDiff *types.BlockStorageDiff
	if block.Root() == parentBlock.Root() {
		blockStorageDiff = &types.BlockStorageDiff{}
	} else {
		blockStorageDiff = api.e.blockchain.GetBlockStorageDiff(block.Root())
		if blockStorageDiff == nil {
			if reExec {
				statedb, err := api.e.blockchain.StateAt(parentBlock.Root())
				if err != nil {
					log.Error("Failed to get state", "err", err)
					return nil, err
				}
				_, _, _, err = api.e.blockchain.Processor().Process(block, statedb, vm.Config{})
				if err != nil {
					return nil, fmt.Errorf("processing block %d failed: %v", block.NumberU64(), err)
				}
				// Finalize the state so any modifications are written to the trie
				root, err := statedb.Commit(api.e.blockchain.Config().IsEIP158(block.Number()))
				if err != nil {
					return nil, fmt.Errorf("stateAtBlock commit failed, number %d root %v: %w",
						block.NumberU64(), block.Root().Hex(), err)
				}
				if root != block.Root() {
					return nil, fmt.Errorf("stateAtBlock reExec failed, number %d root %v != %v",
						block.NumberU64(), block.Root().Hex(), root.Hex())
				}
				blockStorageDiff = api.e.blockchain.GetBlockStorageDiff(block.Root())
			}
			if blockStorageDiff == nil {
				log.Info("Failed to get block storage diff", "block", block.NumberU64())
				return hexutil.Bytes{}, nil
			}
		}
	}
	blockStorageDiff.Hash = block.Hash()
	blockStorageDiff.ParentHash = block.ParentHash()
	buf, _ := rlp.EncodeToBytes(blockStorageDiff)
	return buf, nil
}
