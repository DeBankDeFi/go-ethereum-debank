package ethdb

import (
	"fmt"

	"github.com/DeBankDeFi/db-replicator/pkg/reader"
	"github.com/ethereum/go-ethereum/repl"
)

var _ KeyValueStore = &remoteDB{}

type remoteDB struct {
	db *reader.Remote
}

func RemoteDB(file string) (KeyValueStore, error) {
	db, err := reader.OpenRemoteDB(repl.Cfg.RemoteAddr, "leveldb", file, true)
	if err != nil {
		return nil, err
	}
	fmt.Printf("open remote db success: %s", file)
	return NewRemoteDB(db), nil
}

func NewRemoteDB(db *reader.Remote) *remoteDB {
	return &remoteDB{db: db}
}

func (db *remoteDB) Has(key []byte) (bool, error) {
	return db.db.Has(key)
}

func (db *remoteDB) Get(key []byte) ([]byte, error) {
	return db.db.Get(key)
}

func (db *remoteDB) Put(key []byte, value []byte) error {
	return nil
}

func (db *remoteDB) Delete(key []byte) error {
	return nil
}

type remoteBatch struct {
}

func (b *remoteBatch) Put(key []byte, value []byte) error {
	return nil
}

func (b *remoteBatch) Delete(key []byte) error {
	return nil
}

func (b *remoteBatch) Write() error {
	return nil
}

func (b *remoteBatch) Reset() {

}

func (b *remoteBatch) ValueSize() int {
	return 0
}

func (b *remoteBatch) Replay(w KeyValueWriter) error {
	return nil
}

func (db *remoteDB) NewBatch() Batch {
	return &remoteBatch{}
}

func (db *remoteDB) NewBatchWithSize(size int) Batch {
	return &remoteBatch{}
}

func (db *remoteDB) NewIterator(prefix []byte, start []byte) Iterator {
	return db.db.NewIterator(prefix, start)
}

func (db *remoteDB) Stat(property string) (string, error) {
	return db.db.Stat(property)
}

func (db *remoteDB) Compact(start []byte, limit []byte) error {
	return db.db.Compact(start, limit)
}

func (db *remoteDB) NewSnapshot() (Snapshot, error) {
	return db.db.NewSnapshot()
}

func (db *remoteDB) Close() error {
	return nil
}
