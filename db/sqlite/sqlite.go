// Package sqlite provides a thin wrapper over the sqlc-generated SQLite wrapper
// to adhere to our server's DB interface.
package sqlite

import (
	"context"
	"errors"
	"fmt"

	"github.com/bcspragu/logseq-sync/db"
	"github.com/bcspragu/logseq-sync/db/sqlite/sqlitedb"
	"github.com/google/uuid"

	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	q *sqlitedb.Queries
}

func New(dbPath string) (*DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	return &DB{
		q: sqlitedb.New(db),
	}, nil
}

func (d *DB) IncrementTx(ctx context.Context, id db.GraphID) (db.Tx, error) {
	res, err := d.q.IncrementTx(ctx, string(id))
	if errors.Is(err, sql.ErrNoRows) {
		return 0, db.NotExists("graph", id)
	} else if err != nil {
		return 0, fmt.Errorf("failed to increment tx: %w", err)
	}
	return db.Tx(res), nil
}

func (d *DB) SetTx(ctx context.Context, id db.GraphID, tx db.Tx) error {
	if err := d.q.SetTx(ctx, sqlitedb.SetTxParams{
		CurrentTx: int64(tx),
		ID:        string(id),
	}); errors.Is(err, sql.ErrNoRows) {
		return db.NotExists("graph", id)
	} else if err != nil {
		return fmt.Errorf("failed to set tx: %w", err)
	}
	return nil
}

func (d *DB) Tx(ctx context.Context, id db.GraphID) (db.Tx, error) {
	g, err := d.q.Graph(ctx, string(id))
	if errors.Is(err, sql.ErrNoRows) {
		return 0, db.NotExists("graph", id)
	} else if err != nil {
		return 0, fmt.Errorf("failed to load graph: %w", err)
	}
	return db.Tx(g.CurrentTx), nil
}

func (d *DB) Graph(ctx context.Context, id db.GraphID) (*db.Graph, error) {
	g, err := d.q.Graph(ctx, string(id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, db.NotExists("graph", id)
	} else if err != nil {
		return nil, fmt.Errorf("failed to load graph: %w", err)
	}
	return toGraph(g), nil
}

func toGraph(g sqlitedb.Graph) *db.Graph {
	return &db.Graph{
		ID:   db.GraphID(g.ID),
		Name: g.Name,
	}
}

func convSlice[I any, O any](in []I, fn func(I) O) []O {
	out := make([]O, len(in))
	for i, v := range in {
		out[i] = fn(v)
	}
	return out
}

func (d *DB) Graphs(ctx context.Context) ([]*db.Graph, error) {
	gs, err := d.q.Graphs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load graphs: %w", err)
	}
	return convSlice(gs, toGraph), nil
}
func (d *DB) CreateGraph(ctx context.Context, name string) (db.GraphID, db.Tx, error) {
	id := uuid.NewString()
	tx, err := d.q.CreateGraph(ctx, sqlitedb.CreateGraphParams{
		ID:   id,
		Name: name,
	})
	if err != nil {
		return "", 0, fmt.Errorf("failed to create graph: %w", err)
	}
	return db.GraphID(id), db.Tx(tx), nil
}

func (d *DB) DeleteGraph(ctx context.Context, id db.GraphID) error {
	if err := d.q.DeleteGraph(ctx, string(id)); errors.Is(err, sql.ErrNoRows) {
		return db.NotExists("graph", id)
	} else if err != nil {
		return fmt.Errorf("failed to delete graph: %w", err)
	}
	return nil
}

func (d *DB) AddGraphSalt(ctx context.Context, gID db.GraphID, salt *db.GraphSalt) error {
	id := uuid.NewString()
	if err := d.q.AddGraphSalt(ctx, sqlitedb.AddGraphSaltParams{
		ID:        id,
		GraphID:   string(gID),
		Value:     salt.Value,
		ExpiresAt: salt.ExpiredAt,
	}); err != nil {
		return fmt.Errorf("failed to add graph salt: %w", err)
	}
	return nil
}

func (d *DB) GraphSalts(ctx context.Context, id db.GraphID) ([]*db.GraphSalt, error) {
	gss, err := d.q.GraphSalts(ctx, string(id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, db.NotExists("graph", id)
	} else if err != nil {
		return nil, fmt.Errorf("failed to load graph salts: %w", err)
	}
	return convSlice(gss, toGraphSalt), nil
}

func toGraphSalt(g sqlitedb.GraphSalt) *db.GraphSalt {
	return &db.GraphSalt{
		Value:     g.Value,
		ExpiredAt: g.ExpiresAt,
	}
}

func (d *DB) AddGraphEncryptKey(ctx context.Context, gID db.GraphID, gek *db.GraphEncryptKey) error {
	id := uuid.NewString()
	if err := d.q.AddGraphEncryptKey(ctx, sqlitedb.AddGraphEncryptKeyParams{
		ID:                  id,
		GraphID:             string(gID),
		EncryptedPrivateKey: gek.EncryptedPrivateKey,
		PublicKey:           gek.PublicKey,
	}); err != nil {
		return fmt.Errorf("failed to add graph encrypt key: %w", err)
	}
	return nil
}

func (d *DB) GraphEncryptKeys(ctx context.Context, id db.GraphID) ([]*db.GraphEncryptKey, error) {
	geks, err := d.q.GraphEncryptKeys(ctx, string(id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, db.NotExists("graph", id)
	} else if err != nil {
		return nil, fmt.Errorf("failed to load graph encrypt keys: %w", err)
	}
	return convSlice(geks, toGraphEncryptKey), nil
}

func toGraphEncryptKey(g sqlitedb.GraphEncryptKey) *db.GraphEncryptKey {
	return &db.GraphEncryptKey{
		EncryptedPrivateKey: g.EncryptedPrivateKey,
		PublicKey:           g.PublicKey,
	}
}

func (d *DB) SetFileMeta(ctx context.Context, gID db.GraphID, md *db.FileMeta) error {
	if md.ID == "" {
		return errors.New("no file ID set on metadata")
	}

	id := uuid.NewString()
	err := d.q.SetFileMeta(ctx, sqlitedb.SetFileMetaParams{
		ID:             id,
		GraphID:        string(gID),
		FileID:         string(md.ID),
		BlobPath:       md.BlobPath,
		Checksum:       md.Checksum,
		Size:           md.Size,
		LastModifiedTx: int64(md.LastModifiedTX),
	})
	if err != nil {
		return fmt.Errorf("failed to set file metadata: %w", err)
	}
	return nil
}

// Because the Logseq client can/will request files it hasn't uploaded yet, the
// map will contain nil entries for requested files that don't exist
func (d *DB) BatchFileMeta(ctx context.Context, id db.GraphID, fIDs []db.FileID) (map[db.FileID]*db.FileMeta, error) {
	fms, err := d.q.BatchFileMetas(ctx, sqlitedb.BatchFileMetasParams{
		GraphID: string(id),
		FileIds: convSlice(fIDs, func(id db.FileID) string { return string(id) }),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to batch load file metadata: %w", err)
	}
	out := make(map[db.FileID]*db.FileMeta)
	for _, fm := range fms {
		out[db.FileID(fm.FileID)] = toFileMeta(fm)
	}
	return out, nil
}

func toFileMeta(fm sqlitedb.FileMeta) *db.FileMeta {
	return &db.FileMeta{
		ID:             db.FileID(fm.FileID),
		BlobPath:       fm.BlobPath,
		Checksum:       fm.Checksum,
		Size:           fm.Size,
		LastModifiedAt: fm.LastModifiedAt,
		LastModifiedTX: db.Tx(fm.LastModifiedTx),
	}
}

func (d *DB) AllFileMeta(ctx context.Context, id db.GraphID) ([]*db.FileMeta, error) {
	fms, err := d.q.AllFileMeta(ctx, string(id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, db.NotExists("graph", id)
	} else if err != nil {
		return nil, fmt.Errorf("failed to load all file metadata for graph: %w", err)
	}
	return convSlice(fms, toFileMeta), nil
}
