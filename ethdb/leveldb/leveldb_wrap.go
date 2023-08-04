package leveldb

import (
	rdb "github.com/DeBankDeFi/nodex/pkg/db"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

var _ rdb.DB = &wrapDB{}

type wrapDB struct {
	db *Database
}

func (db *wrapDB) Close() error {
	return db.db.Close()
}

func (db *wrapDB) Has(key []byte) (bool, error) {
	return db.db.Has(key)
}

func (db *wrapDB) Get(key []byte) ([]byte, error) {
	return db.db.Get(key)
}

func (db *wrapDB) Put(key []byte, value []byte) error {
	return db.db.Put(key, value)
}

func (db *wrapDB) Delete(key []byte) error {
	return db.db.Delete(key)
}

type wrapBatch struct {
	batch *batch
}

func (b *wrapBatch) Put(key []byte, value []byte) error {
	return b.batch.Put(key, value)
}

func (b *wrapBatch) Delete(key []byte) error {
	return b.batch.Delete(key)
}

func (b *wrapBatch) Write() error {
	return b.batch.db.Write(b.batch.b, nil)
}

func (b *wrapBatch) Reset() {
	b.batch.Reset()
}

func (b *wrapBatch) ValueSize() int {
	return b.batch.ValueSize()
}

func (b *wrapBatch) Replay(w rdb.KeyValueWriter) error {
	return b.batch.Replay(w)
}

func (b *wrapBatch) Load(data []byte) error {
	return b.batch.Load(data)
}

func (b *wrapBatch) Dump() []byte {
	return b.batch.Dump()
}

func (db *wrapDB) NewBatch() rdb.Batch {
	return &wrapBatch{batch: &batch{
		db: db.db.db,
		b:  new(leveldb.Batch),
		id: db.db.id,
	}}
}

func (db *wrapDB) NewBatchWithSize(size int) rdb.Batch {
	return &wrapBatch{batch: &batch{
		db: db.db.db,
		b:  leveldb.MakeBatch(size),
		id: db.db.id,
	}}
}

func (db *wrapDB) NewIterator(prefix []byte, start []byte) rdb.Iterator {
	return db.db.NewIterator(prefix, start)
}

func (db *wrapDB) NewIteratorWithRange(start []byte, limit []byte) (rdb.Iterator, error) {
	return db.db.db.NewIterator(&util.Range{Start: start, Limit: limit}, nil), nil
}

func (db *wrapDB) NewSnapshot() (rdb.Snapshot, error) {
	return db.db.NewSnapshot()
}

func (db *wrapDB) Compact(start []byte, limit []byte) error {
	return db.db.Compact(start, limit)
}

func (db *wrapDB) Stats() (map[string]string, error) {
	panic("not implemented")
}

func (db *wrapDB) Stat(property string) (string, error) {
	return db.db.Stat(property)
}
