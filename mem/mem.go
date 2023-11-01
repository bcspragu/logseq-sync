// Package mem implements an in-memory version of our DB interface, for quick
// iteration and local testing.
//
// Note that it has no synchronization built-in and really shouldn't be used
// concurrently.
//
// Also note that we return the actual underlying struct pointers, which is
// generally a terrible idea because the caller can accidentally (or
// intentionally) update fields and it'll change the thing here. I'm just too
// lazy to copy things everywhere.
package mem

import (
	"fmt"

	"github.com/bcspragu/logseq-sync/db"
	"github.com/google/uuid"
)

type DB struct {
	txs    map[db.GraphID]db.Tx
	graphs map[db.GraphID]*db.Graph
	salts  map[db.GraphID][]*db.GraphSalt
	keys   map[db.GraphID][]*db.GraphEncryptKey
	// We store the whole history of file metadata, for now.
	meta map[db.GraphID]map[db.FileID][]*db.FileMeta
}

func New() *DB {
	return &DB{
		txs:    make(map[db.GraphID]db.Tx),
		graphs: make(map[db.GraphID]*db.Graph),
		salts:  make(map[db.GraphID][]*db.GraphSalt),
		keys:   make(map[db.GraphID][]*db.GraphEncryptKey),
		meta:   make(map[db.GraphID]map[db.FileID][]*db.FileMeta),
	}
}

func (d *DB) CreateGraph(name string) (db.GraphID, db.Tx, error) {
	for _, g := range d.graphs {
		if name == g.Name {
			return "", 0, db.AlreadyExists("graph", "name")
		}
	}
	id := db.GraphID(uuid.NewString())
	d.graphs[id] = &db.Graph{
		ID:   id,
		Name: name,
	}
	d.salts[id] = []*db.GraphSalt{}
	d.keys[id] = []*db.GraphEncryptKey{}
	d.meta[id] = make(map[db.FileID][]*db.FileMeta)
	d.txs[id] = 0
	return id, d.txs[id], nil
}

func (d *DB) Graphs() ([]*db.Graph, error) {
	var out []*db.Graph
	for _, g := range d.graphs {
		out = append(out, g)
	}
	return out, nil
}

func (d *DB) Tx(id db.GraphID) (db.Tx, error) {
	tx, ok := d.txs[id]
	if !ok {
		return 0, db.NotExists("graph", id)
	}
	return tx, nil
}

func (d *DB) IncrementTx(id db.GraphID) (db.Tx, error) {
	tx, ok := d.txs[id]
	if !ok {
		return 0, db.NotExists("graph", id)
	}
	tx++
	d.txs[id] = tx
	return tx, nil
}

func (d *DB) SetTx(id db.GraphID, tx db.Tx) error {
	if _, ok := d.txs[id]; !ok {
		return db.NotExists("graph", id)
	}
	d.txs[id] = tx
	return nil
}

func (d *DB) Graph(id db.GraphID) (*db.Graph, error) {
	g, ok := d.graphs[id]
	if !ok {
		return nil, db.NotExists("graph", id)
	}
	return g, nil
}

func (d *DB) AddGraphSalt(id db.GraphID, salt *db.GraphSalt) error {
	salts, ok := d.salts[id]
	if !ok {
		return db.NotExists("graph", id)
	}
	d.salts[id] = append(salts, salt)
	return nil
}

func (d *DB) GraphSalts(id db.GraphID) ([]*db.GraphSalt, error) {
	salts, ok := d.salts[id]
	if !ok {
		return nil, db.NotExists("graph", id)
	}
	return salts, nil
}

func (d *DB) AddGraphEncryptKeys(id db.GraphID, gek *db.GraphEncryptKey) error {
	keys, ok := d.keys[id]
	if !ok {
		return db.NotExists("graph", id)
	}
	d.keys[id] = append(keys, gek)
	return nil
}

func (d *DB) GraphEncryptKeys(id db.GraphID) ([]*db.GraphEncryptKey, error) {
	keys, ok := d.keys[id]
	if !ok {
		return nil, db.NotExists("graph", id)
	}
	return keys, nil
}

func (d *DB) SetFileMeta(id db.GraphID, md *db.FileMeta) error {
	metas, ok := d.meta[id]
	if !ok {
		return db.NotExists("graph", id)
	}
	metas[md.ID] = append(metas[md.ID], md)
	d.meta[id] = metas
	return nil
}

func (d *DB) BatchFileMeta(id db.GraphID, fIDs []db.FileID) ([]*db.FileMeta, error) {
	metas, ok := d.meta[id]
	if !ok {
		return nil, db.NotExists("graph", id)
	}

	var out []*db.FileMeta
	for _, fID := range fIDs {
		mds, ok := metas[fID]
		if !ok {
			return nil, db.NotExists("file_meta", fID)
		}
		if len(mds) < 1 {
			// Note: This indicates some sort of logic error, not client error
			return nil, fmt.Errorf("no file metadata history found for %q", fID)
		}
		// Get the latest, which is the last one
		out = append(out, mds[len(mds)-1])
	}
	return out, nil
}
