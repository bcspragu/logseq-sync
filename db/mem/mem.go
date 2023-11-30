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
	"context"
	"errors"
	"fmt"

	"github.com/bcspragu/logseq-sync/db"
	"github.com/google/uuid"
)

type graph struct {
	tx    db.Tx
	graph *db.Graph
	salts []*db.GraphSalt
	keys  []*db.GraphEncryptKey
	// We store the whole history of file metadata, for now.
	metas map[db.FileID][]*db.FileMeta
}

type DB struct {
	graphs map[db.GraphID]*graph
}

func New() *DB {
	return &DB{
		graphs: make(map[db.GraphID]*graph),
	}
}

func (d *DB) DeleteGraph(_ context.Context, id db.GraphID) error {
	if _, ok := d.graphs[id]; !ok {
		return db.NotExists("graph", id)
	}
	delete(d.graphs, id)
	return nil
}

func (d *DB) CreateGraph(_ context.Context, name string) (db.GraphID, db.Tx, error) {
	for _, g := range d.graphs {
		if name == g.graph.Name {
			return "", 0, db.AlreadyExists("graph", "name")
		}
	}
	id := db.GraphID(uuid.NewString())
	tx := db.Tx(0)
	d.graphs[id] = &graph{
		graph: &db.Graph{
			ID:   id,
			Name: name,
		},
		salts: []*db.GraphSalt{},
		keys:  []*db.GraphEncryptKey{},
		metas: make(map[db.FileID][]*db.FileMeta),
		tx:    tx,
	}
	return id, tx, nil
}

func (d *DB) Graphs(_ context.Context) ([]*db.Graph, error) {
	var out []*db.Graph
	for _, g := range d.graphs {
		out = append(out, g.graph)
	}
	return out, nil
}

func (d *DB) Tx(_ context.Context, id db.GraphID) (db.Tx, error) {
	g, ok := d.graphs[id]
	if !ok {
		return 0, db.NotExists("graph", id)
	}
	return g.tx, nil
}

func (d *DB) IncrementTx(_ context.Context, id db.GraphID) (db.Tx, error) {
	g, ok := d.graphs[id]
	if !ok {
		return 0, db.NotExists("graph", id)
	}
	g.tx++
	return g.tx, nil
}

func (d *DB) SetTx(_ context.Context, id db.GraphID, tx db.Tx) error {
	g, ok := d.graphs[id]
	if !ok {
		return db.NotExists("graph", id)
	}
	g.tx = tx
	return nil
}

func (d *DB) Graph(_ context.Context, id db.GraphID) (*db.Graph, error) {
	g, ok := d.graphs[id]
	if !ok {
		return nil, db.NotExists("graph", id)
	}
	return g.graph, nil
}

func (d *DB) AddGraphSalt(_ context.Context, id db.GraphID, salt *db.GraphSalt) error {
	g, ok := d.graphs[id]
	if !ok {
		return db.NotExists("graph", id)
	}
	g.salts = append(g.salts, salt)
	return nil
}

func (d *DB) GraphSalts(_ context.Context, id db.GraphID) ([]*db.GraphSalt, error) {
	g, ok := d.graphs[id]
	if !ok {
		return nil, db.NotExists("graph", id)
	}
	return g.salts, nil
}

func (d *DB) AddGraphEncryptKey(_ context.Context, id db.GraphID, gek *db.GraphEncryptKey) error {
	g, ok := d.graphs[id]
	if !ok {
		return db.NotExists("graph", id)
	}
	g.keys = append(g.keys, gek)
	return nil
}

func (d *DB) GraphEncryptKeys(_ context.Context, id db.GraphID) ([]*db.GraphEncryptKey, error) {
	g, ok := d.graphs[id]
	if !ok {
		return nil, db.NotExists("graph", id)
	}
	return g.keys, nil
}

func (d *DB) SetFileMeta(_ context.Context, id db.GraphID, md *db.FileMeta) error {
	if md.ID == "" {
		return errors.New("no file ID set on metadata")
	}
	g, ok := d.graphs[id]
	if !ok {
		return db.NotExists("graph", id)
	}
	g.metas[md.ID] = append(g.metas[md.ID], md)
	return nil
}

func (d *DB) BatchFileMeta(_ context.Context, id db.GraphID, fIDs []db.FileID) (map[db.FileID]*db.FileMeta, error) {
	g, ok := d.graphs[id]
	if !ok {
		return nil, db.NotExists("graph", id)
	}

	out := make(map[db.FileID]*db.FileMeta)
	for _, fID := range fIDs {
		mds, ok := g.metas[fID]
		if !ok {
			out[fID] = nil
			continue
		}
		if len(mds) < 1 {
			// Note: This indicates some sort of logic error, not client error
			return nil, fmt.Errorf("no file metadata history found for %q", fID)
		}
		// Get the latest, which is the last one
		out[fID] = mds[len(mds)-1]
	}
	return out, nil
}

func (d *DB) AllFileMeta(_ context.Context, id db.GraphID) ([]*db.FileMeta, error) {
	g, ok := d.graphs[id]
	if !ok {
		return nil, db.NotExists("graph", id)
	}

	var out []*db.FileMeta
	for _, metas := range g.metas {
		if len(metas) == 0 {
			continue
		}
		// Get the latest
		out = append(out, metas[len(metas)-1])
	}
	return out, nil
}
