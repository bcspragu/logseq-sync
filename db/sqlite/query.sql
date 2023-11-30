-- name: CreateGraph :one
INSERT INTO graphs (
  id, name, current_tx
) VALUES (
  ?, ?, 0
)
RETURNING current_tx;

-- name: DeleteGraph :exec
DELETE FROM graphs
WHERE id = ?;

-- name: Graphs :many
SELECT id, name, current_tx
FROM graphs;

-- name: SetTx :exec
UPDATE graphs
SET current_tx = ?
WHERE id = ?;

-- name: IncrementTx :one
UPDATE graphs
SET current_tx = current_tx + 1
WHERE id = ?
RETURNING current_tx;

-- name: Graph :one
SELECT id, name, current_tx
FROM graphs
WHERE id = ?;

-- name: AddGraphSalt :exec
INSERT INTO graph_salts (
  id, graph_id, value, expires_at
) VALUES (
  ?, ?, ?, ?
);

-- name: GraphSalts :many
SELECT id, graph_id, value, expires_at
FROM graph_salts
WHERE graph_id = ?;

-- name: AddGraphEncryptKey :exec
INSERT INTO graph_encrypt_keys (
  id, graph_id, encrypted_private_key, public_key
) VALUES (
  ?, ?, ?, ?
);

-- name: GraphEncryptKeys :many
SELECT id, graph_id, encrypted_private_key, public_key
FROM graph_encrypt_keys
WHERE graph_id = ?;

-- name: SetFileMeta :exec
INSERT INTO file_metas (id, graph_id, file_id, blob_path, checksum, size, last_modified_at, last_modified_tx)
  VALUES(?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?);

-- name: BatchFileMetas :many
SELECT id, graph_id, file_id, blob_path, checksum, size, last_modified_at, last_modified_tx
FROM file_metas
WHERE graph_id = ?
  AND file_id IN (sqlc.slice('file_ids'));

-- name: AllFileMeta :many
SELECT id, graph_id, file_id, blob_path, checksum, size, last_modified_at, last_modified_tx
FROM file_metas
WHERE graph_id = ?;

