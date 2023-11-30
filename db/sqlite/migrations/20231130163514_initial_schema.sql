-- Create "graphs" table
CREATE TABLE `graphs` (`id` text NOT NULL, `name` text NOT NULL, `current_tx` integer NOT NULL, PRIMARY KEY (`id`));
-- Create "file_metas" table
CREATE TABLE `file_metas` (`id` text NOT NULL, `graph_id` text NOT NULL, `file_id` text NOT NULL, `blob_path` text NOT NULL, `checksum` blob NOT NULL, `size` integer NOT NULL, `last_modified_at` timestamp NOT NULL, `last_modified_tx` integer NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `0` FOREIGN KEY (`graph_id`) REFERENCES `graphs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create "graph_salts" table
CREATE TABLE `graph_salts` (`id` text NOT NULL, `graph_id` text NOT NULL, `value` blob NOT NULL, `expires_at` timestamp NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `0` FOREIGN KEY (`graph_id`) REFERENCES `graphs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create "graph_encrypt_keys" table
CREATE TABLE `graph_encrypt_keys` (`id` text NOT NULL, `graph_id` text NOT NULL, `encrypted_private_key` text NOT NULL, `public_key` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `0` FOREIGN KEY (`graph_id`) REFERENCES `graphs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
