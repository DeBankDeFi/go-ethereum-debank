package core

import (
	"sync"
	"time"

	rpb "github.com/DeBankDeFi/nodex/pkg/pb"
	rreader "github.com/DeBankDeFi/nodex/pkg/reader"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

type Syncer struct {
	syncClient *rreader.SyncClient
	chain      *BlockChain
	lastInfo   *rpb.BlockInfo
	sync.Mutex
}

func NewSyncer(chain *BlockChain, syncClient *rreader.SyncClient) *Syncer {
	return &Syncer{
		syncClient: syncClient,
		chain:      chain,
	}
}

func (s *Syncer) Init() error {
	err := s.syncClient.SyncInit()
	if err != nil {
		log.Error("SyncInit error", "err", err)
		return err
	}
	return nil
}

func (s *Syncer) Sync() {
	log.Info("Syncer start")
	go s.clientSync()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.chain.quit:
			s.Stop()
			return
		case <-ticker.C:
			s.timeSync()
		}
	}
}

func (s *Syncer) Stop() {
	if s.syncClient != nil {
		s.syncClient.Cancel()
	}
}

func (s *Syncer) clientSync() {
	for {
		select {
		case <-s.chain.quit:
			s.Stop()
			return
		default:
			s.streamSync()
		}
	}
}

func (s *Syncer) streamSync() {
	s.Lock()
	defer s.Unlock()
	block, err := s.syncClient.SyncNext()
	if err != nil {
		log.Error("SyncNext error", "err", err)
		time.Sleep(5 * time.Second)
		s.Init()
		return
	}
	s.cacheUpdate(common.HexToHash(block.Info.BlockHash))
	s.lastInfo = block.Info
}

func (s *Syncer) timeSync() {
	s.Lock()
	defer s.Unlock()
	if s.lastInfo == nil {
		return
	}
	head := s.LastBlockHeader()
	if head != nil {
		if head.Number.Int64() <= s.lastInfo.BlockNum+32 {
			return
		} else {
			s.Init()
		}
	}
}

func (s *Syncer) cacheUpdate(blockHash common.Hash) {
	if blockHash == (common.Hash{}) {
		return
	}
	currentBlock := s.chain.CurrentBlock()
	if currentBlock.Hash() == blockHash {
		return
	}
	incomeBlock := s.chain.GetBlockByHash(blockHash)
	if incomeBlock == nil {
		return
	}
	if s.chain.snaps != nil {
		err := s.chain.snaps.ReLoadTree(incomeBlock.Root())
		if err != nil {
			log.Error("ReLoadTree error", "err", err, "blockHash", blockHash, "root", incomeBlock.Root())
		}
	}
	// parent := s.chain.GetBlockByHash(incomeBlock.ParentHash())
	// parentBlock := s.chain.GetBlockByHash(parent.Hash())
	// throwaway, _ := state.New(parentBlock.Root(), s.chain.stateCache, s.chain.snaps)
	// if throwaway != nil {
	// var followupInterrupt uint32
	// s.chain.prefetcher.Prefetch(incomeBlock, throwaway, s.chain.vmConfig, &followupInterrupt)
	// }
	s.chain.hc.SetCurrentHeader(incomeBlock.Header())
	s.chain.currentSnapBlock.Store(incomeBlock.Header())
	headFastBlockGauge.Update(int64(incomeBlock.NumberU64()))

	s.chain.currentBlock.Store(incomeBlock.Header())
	headBlockGauge.Update(int64(incomeBlock.NumberU64()))
	log.Info("Sync success", "blockHash", blockHash, "blocknum", incomeBlock.NumberU64(), "root", incomeBlock.Root())
}

func (s *Syncer) LastBlockHeader() *types.Header {
	headHash := rawdb.ReadHeadBlockHash(s.chain.db)
	if headHash == (common.Hash{}) {
		return nil
	}
	headBlock := s.chain.GetBlockByHash(headHash)
	return headBlock.Header()
}
