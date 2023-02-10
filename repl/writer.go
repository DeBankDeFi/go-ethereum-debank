package repl

import (
	"sync"

	rdb "github.com/DeBankDeFi/db-replicator/pkg/db"
	rutils "github.com/DeBankDeFi/db-replicator/pkg/utils"
	rwriter "github.com/DeBankDeFi/db-replicator/pkg/writer"
	"github.com/ethereum/go-ethereum/log"
)

var Writer *replWriter

type replWriter struct {
	batchLayers []batchLayer
	pool        *rdb.DBPool
	count       int32
	writer      *rwriter.Writer
	sync.Mutex
}

type batchLayer struct {
	name   string
	batchs []rdb.BatchWithID
}

func InitreplWriter() error {
	pool := rdb.NewDBPool()
	Writer = &replWriter{
		batchLayers: make([]batchLayer, 0),
		pool:        pool,
	}
	return nil
}

func (w *replWriter) Register(path string, db rdb.DB) int32 {
	w.Lock()
	defer w.Unlock()
	w.pool.Register(w.count, path, "leveldb", db, w.count == 0)
	w.count += 1
	return w.count - 1
}

func (w *replWriter) Recovery() error {
	writer, err := rwriter.NewWriter(&rutils.Config{
		S3ProxyAddr: Cfg.S3ProxyAddr,
		KafkaAddr:   Cfg.KafkaAddr,
		RemoteAddr:  Cfg.RemoteAddr,
		ChainId:     Cfg.ChainId,
		Env:         Cfg.Env,
		Role:        Cfg.Role,
		ReorgDeep:   Cfg.ReorgDeep,
	}, Writer.pool)
	if err != nil {
		return err
	}
	Writer.writer = writer
	return Writer.writer.Recovery()
}

func (w *replWriter) CreateBatchLayer(name string) {
	w.Lock()
	defer w.Unlock()
	w.batchLayers = append(w.batchLayers, batchLayer{
		name:   name,
		batchs: make([]rdb.BatchWithID, 0),
	})
}

func (w *replWriter) AppendBatch(batch rdb.BatchWithID) {
	w.Lock()
	defer w.Unlock()
	if w.batchLayers == nil || len(w.batchLayers) == 0 {
		batch.B.Write()
	} else {
		w.batchLayers[len(w.batchLayers)-1].batchs = append(w.batchLayers[len(w.batchLayers)-1].batchs, batch)
	}
}

func (w *replWriter) WriteBlockWithState(blockNum int64, blockHash string, blockRoot string,
) {
	batchs := w.batchLayers[len(w.batchLayers)-1].batchs
	info := w.writer.PrepareBlockInfo(blockNum, blockHash, blockRoot)
	err := w.writer.WriteBlockToS3(info, batchs)
	if err != nil {
		log.Crit("WriteBlockToS3 error", "err", err)
	}
	err = w.writer.WriteBlockToDB(batchs)
	if err != nil {
		log.Crit("WriteBlockToDB error", "err", err)
	}
	log.Info("WriteBlockToDB success", "blockNum", blockNum, "blockHash", blockHash)
	w.batchLayers = w.batchLayers[:len(w.batchLayers)-1]
}

func (w *replWriter) WriteHeader(blockNum int64, blockHash string, blockRoot string) {
	batchs := w.batchLayers[len(w.batchLayers)-1].batchs
	info := w.writer.PrepareBlockInfo(blockNum, blockHash, blockRoot)
	err := w.writer.WriteBlockHeaderToS3(info, batchs)
	if err != nil {
		log.Crit("WriteBlockHeaderToS3 error", "err", err)
	}
	err = w.writer.WriteBlockHeaderToDB(info, batchs)
	if err != nil {
		log.Crit("WriteBlockHeaderToDB error", "err", err)
	}
	err = w.writer.WriteBlockHeaderToKafka()
	if err != nil {
		log.Crit("WriteBlockHeaderToKafka error", "err", err)
	}
	log.Info("WriteBlockHeaderToDB success", "blockNum", blockNum, "blockHash", blockHash)
	w.batchLayers = w.batchLayers[:len(w.batchLayers)-1]
}
