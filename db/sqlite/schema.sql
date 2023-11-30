CREATE TABLE graphs (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  current_tx INTEGER NOT NULL
);

CREATE TABLE file_metas (
	id TEXT PRIMARY KEY NOT NULL,
  graph_id TEXT NOT NULL,
  file_id TEXT NOT NULL,
	blob_path TEXT NOT NULL,
	checksum BLOB NOT NULL,
	size INTEGER NOT NULL,
	last_modified_at TIMESTAMP NOT NULL,
	last_modified_tx INTEGER NOT NULL,
  UNIQUE(graph_id, file_id) ON CONFLICT REPLACE,
  FOREIGN KEY (graph_id) REFERENCES graphs (id)
);

CREATE TABLE graph_salts (
  id TEXT PRIMARY KEY NOT NULL,
  graph_id TEXT NOT NULL,
  value BLOB NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  FOREIGN KEY (graph_id) REFERENCES graphs (id)
);

CREATE TABLE graph_encrypt_keys (
  id TEXT PRIMARY KEY NOT NULL,
  graph_id TEXT NOT NULL,
  encrypted_private_key TEXT NOT NULL,
  public_key TEXT NOT NULL,
  FOREIGN KEY (graph_id) REFERENCES graphs (id)
);
