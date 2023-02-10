package snapshot

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

func (dl *diffLayer) journalSnapshot2(buffer *bytes.Buffer) error {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	if dl.Stale() {
		return ErrSnapshotStale
	}

	// Everything below was journalled, persist this layer too
	if err := rlp.Encode(buffer, dl.root); err != nil {
		return err
	}
	if err := rlp.Encode(buffer, dl.parent.Root()); err != nil {
		return err
	}
	destructs := make([]journalDestruct, 0, len(dl.destructSet))
	for hash := range dl.destructSet {
		destructs = append(destructs, journalDestruct{Hash: hash})
	}
	if err := rlp.Encode(buffer, destructs); err != nil {
		return err
	}
	accounts := make([]journalAccount, 0, len(dl.accountData))
	for hash, blob := range dl.accountData {
		accounts = append(accounts, journalAccount{Hash: hash, Blob: blob})
	}
	if err := rlp.Encode(buffer, accounts); err != nil {
		return err
	}
	storage := make([]journalStorage, 0, len(dl.storageData))
	for hash, slots := range dl.storageData {
		keys := make([]common.Hash, 0, len(slots))
		vals := make([][]byte, 0, len(slots))
		for key, val := range slots {
			keys = append(keys, key)
			vals = append(vals, val)
		}
		storage = append(storage, journalStorage{Hash: hash, Keys: keys, Vals: vals})
	}
	if err := rlp.Encode(buffer, storage); err != nil {
		return err
	}
	log.Debug("Journalled diff layer", "root", dl.root, "parent", dl.parent.Root())
	return nil
}

func (t *Tree) JournalSnapshot2(rootHash common.Hash) error {
	snapshot := t.Snapshot(rootHash).(*diffLayer)
	if snapshot == nil {
		return errors.New("snapshot not found")
	}
	// Otherwise, journal the snapshot
	buffer := new(bytes.Buffer)
	if err := snapshot.journalSnapshot2(buffer); err != nil {
		return err
	}
	batch := t.diskdb.NewBatch()
	rawdb.WriteSnapshotJournal2(batch, rootHash, buffer.Bytes())
	if err := batch.Write(); err != nil {
		log.Crit("Failed to write storage deletions", "err", err)
	}
	return nil
}

func (t *Tree) LoadSnapshotFromJournal2(rootHash common.Hash) (Snapshot, error) {
	snapshot := t.Snapshot(rootHash)
	if snapshot != nil {
		return snapshot, nil
	}

	journal := rawdb.ReadSnapshotJournal2(t.diskdb, rootHash)
	if len(journal) == 0 {
		log.Error("Snapshot journal not found", "root", rootHash)
		return nil, nil
	}

	r := rlp.NewStream(bytes.NewReader(journal), 0)
	// Read the next diff journal entry
	var root common.Hash
	if err := r.Decode(&root); err != nil {
		// The first read may fail with EOF, marking the end of the journal
		return nil, fmt.Errorf("load diff root: %v", err)
	}

	var parentRoot common.Hash
	if err := r.Decode(&parentRoot); err != nil {
		return nil, fmt.Errorf("load diff parent: %v", err)
	}

	_snapshot, err := t.LoadSnapshotFromJournal2(parentRoot)
	if err != nil {
		return nil, err
	}

	if _snapshot == nil {
		return nil, fmt.Errorf("parent snapshot not found: %x", parentRoot)
	}

	var destructs []journalDestruct
	if err := r.Decode(&destructs); err != nil {
		return nil, fmt.Errorf("load diff destructs: %v", err)
	}
	destructSet := make(map[common.Hash]struct{})
	for _, entry := range destructs {
		destructSet[entry.Hash] = struct{}{}
	}

	var accounts []journalAccount
	if err := r.Decode(&accounts); err != nil {
		return nil, fmt.Errorf("load diff accounts: %v", err)
	}
	accountData := make(map[common.Hash][]byte)
	for _, entry := range accounts {
		if len(entry.Blob) > 0 { // RLP loses nil-ness, but `[]byte{}` is not a valid item, so reinterpret that
			accountData[entry.Hash] = entry.Blob
		} else {
			accountData[entry.Hash] = nil
		}
	}

	var storage []journalStorage
	if err := r.Decode(&storage); err != nil {
		return nil, fmt.Errorf("load diff storage: %v", err)
	}
	storageData := make(map[common.Hash]map[common.Hash][]byte)
	for _, entry := range storage {
		slots := make(map[common.Hash][]byte)
		for i, key := range entry.Keys {
			if len(entry.Vals[i]) > 0 { // RLP loses nil-ness, but `[]byte{}` is not a valid item, so reinterpret that
				slots[key] = entry.Vals[i]
			} else {
				slots[key] = nil
			}
		}
		storageData[entry.Hash] = slots
	}
	log.Info("update snapshot", "root", root, "parentRoot", parentRoot)
	err = t.Update(root, parentRoot, destructSet, accountData, storageData)
	if err != nil {
		return nil, err
	}

	return t.Snapshot(rootHash), nil
}

func LoadTree(config Config, diskdb ethdb.KeyValueStore, triedb *trie.Database, root common.Hash) (*Tree, error) {
	// Create a new, empty snapshot tree
	snap := &Tree{
		config: config,
		diskdb: diskdb,
		triedb: triedb,
		layers: make(map[common.Hash]snapshot),
	}
	// Retrieve the block number and hash of the snapshot, failing if no snapshot
	// is present in the database (or crashed mid-update).
	baseRoot := rawdb.ReadSnapshotRoot(diskdb)
	if baseRoot == (common.Hash{}) {
		return nil, errors.New("missing or corrupted snapshot")
	}
	log.Info("Loaded base root", "root", baseRoot)
	base := &diskLayer{
		diskdb: diskdb,
		triedb: triedb,
		cache:  fastcache.New(config.CacheSize * 1024 * 1024),
		root:   baseRoot,
	}
	snap.layers[baseRoot] = base

	snapshot, err := snap.LoadSnapshotFromJournal2(root)
	if err != nil {
		return nil, err
	}

	if snapshot == nil || snapshot.Root() != root {
		return nil, fmt.Errorf("snapshot not found: %x", root)
	}

	return snap, nil
}

func (t *Tree) disklayer2() *diskLayer {
	var snap snapshot
	for _, s := range t.layers {
		snap = s
		break
	}
	if snap == nil {
		return nil
	}
	switch layer := snap.(type) {
	case *diskLayer:
		return layer
	case *diffLayer:
		return layer.origin
	default:
		return nil
	}
}

func (t *Tree) ReLoadTree(newRoot common.Hash) error {
	diskRoot := rawdb.ReadSnapshotRoot(t.diskdb)
	oldDiskRoot := t.diskRoot()
	if oldDiskRoot != diskRoot {
		newTree, err := LoadTree(t.config, t.diskdb, t.triedb, newRoot)
		if err != nil {
			log.Error("reload tree error", "err", err)
			return err
		}
		oldDisk := t.disklayer2()
		t.lock.Lock()
		defer t.lock.Unlock()
		t.layers = newTree.layers
		if oldDisk != nil {
			oldDisk.cache.Reset()
		}
		// Allow newTree to be garbage collected
		newTree.layers = nil
		runtime.GC()
	} else {
		_snapshot, err := t.LoadSnapshotFromJournal2(newRoot)
		if err != nil {
			log.Error("load snapshot from journal error", "err", err)
		}
		if _snapshot == nil {
			log.Error("load snapshot from journal error", "err", err)
		}
		log.Info("ReLoadTree", "newRoot", newRoot)
	}
	return nil
}
