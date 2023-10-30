// Package mem implements an in-memory version of our DB interface, for quick
// iteration and local testing. Note that it has no synchronization built-in and
// really shouldn't be used concurrently.
package mem

import (
	"github.com/bcspragu/logseq-sync/db"
	"github.com/google/uuid"
)

type DB struct {
	txs map[db.GraphID]db.Tx
	// graphs is a map from id -> name
	graphs map[db.GraphID]string
	salts  map[db.GraphID][]*db.GraphSalt
	keys   map[db.GraphID][]*db.GraphEncryptKey
}

func New() *DB {
	return &DB{
		txs:    make(map[db.GraphID]db.Tx),
		graphs: make(map[db.GraphID]string),
		salts:  make(map[db.GraphID][]*db.GraphSalt),
		keys:   make(map[db.GraphID][]*db.GraphEncryptKey),
	}
}

func (d *DB) CreateGraph(name string) (db.GraphID, db.Tx, error) {
	for _, gName := range d.graphs {
		if name == gName {
			return "", 0, db.AlreadyExists("graph", "name")
		}
	}
	id := db.GraphID(uuid.NewString())
	d.graphs[id] = name
	d.salts[id] = []*db.GraphSalt{}
	d.keys[id] = []*db.GraphEncryptKey{}
	d.txs[id] = 0
	return id, d.txs[id], nil
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

func (d *DB) Graph(id db.GraphID) (string, error) {
	name, ok := d.graphs[id]
	if !ok {
		return "", db.NotExists("graph", id)
	}
	return name, nil
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
