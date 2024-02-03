# Logseq Sync

An attempt at an open-source version of the [Logseq Sync](https://blog.logseq.com/how-to-setup-and-use-logseq-sync/) service, intended for individual, self-hosted use.

It's vaguely functional (see [What Works?](#user-content-what-works) below), but decidedly pre-alpha software. Definitely don't try to point a real, populated Logseq client at it, I have no idea what will happen.

## What's Done/Exists?

Right now, the repo contains (in [`cmd/server`](/cmd/server)) a mostly implemented version of the Logseq API, including credentialed blob uploads, signed blob downloads, a SQLite database for persistence, and most of the API surface at least somewhat implemented.

Currently, running any of this requires a modified version of the Logseq codebase ([here](https://github.com/logseq/logseq/blob/05a82a5f268fb77b01f9b8b2a454f5dc15573e70/src/main/frontend/config.cljs#L40-L41)), and [the `@logseq/rsapi` package](https://www.npmjs.com/package/@logseq/rsapi) ([here](https://github.com/logseq/rsapi/blob/18bd98cfc4d084182b534c1c72a6e473a7174b45/sync/src/sync.rs#L26-L28))

On that note, many thanks to the Logseq Team [for open-sourcing `rsapi` recently](https://github.com/logseq/logseq/issues/9311), it made this project significantly easier to work with.

### What Works?

With a modified Logseq, you can use the local server to

1. Create a graph
2. Upload (passphrase-encrypted) encryption keys
3. Get temporary AWS credentials to upload your encrypted files to your private S3 bucket
4. Upload your encrypted files

And that's basically the full end-to-end flow! The big remaining things are:

- [ ] Implement the WebSockets protocol
  - There's [some documentation](/docs/WEBSOCKET.md) for it
- [ ] Figure out how/when to increment the transaction (`tx`) counter

### API Documentation

There's some documentation for the API in [docs/API.md](/docs/API.md). This is the area I could benefit the most from having more information/help on, see [Contributing](#contributing) below

## Open Questions

### S3 API

The real Logseq Sync API gets temp S3 credentials and uploads files direct to S3. I haven't looked closely enough to see if we can swap this out for something S3-compatible like [s3proxy](https://github.com/gaul/s3proxy) or [MinIO](https://github.com/minio/minio), see [#2 for a bit more discussion](https://github.com/bcspragu/logseq-sync/issues/2).

Currently, [`amazonaws.com` is hardcoded in the client](https://docs.rs/crate/s3-presign/latest/source/src/lib.rs), so that'll be part of a larger discussion on how to make all of this configurable in the long run.

## Associated Changes to Logseq

Being able to connect to a self-hosted sync server requires some changes to Logseq as well, namely to specify where your sync server can be accessed. Those changes are in a rough, non-functional state here: https://github.com/logseq/logseq/compare/master...bcspragu:logseq:brandon/settings-hack

## Adding a database migration

The self-hosted sync backend has rudimentary support for persistence in a SQLite database. We use [sqlc](https://sqlc.dev) to do Go codegen for SQL queries, and [Atlas](https://github.com/ariga/atlas) to manage generating diffs.

The process for changing the database schema looks like:

1. Update [`db/sqlite/schema.sql`](/db/sqlite/schema.sql) with your desired changes
2. Run `./scripts/add_migration.sh <name of migration>` to generate the relevant migration
3. Run `./scripts/apply_migrations.sh` to apply the migrations to your SQLite database

### Why do it this way?

With this workflow, the `db/sqlite/migrations/` directory is more or less unused by both `sqlc` and the actual server program. The reason it's structured this way is to keep a more reviewable audit log of the changes to a database, which a single `schema.sql` doesn't give you.

## Contributing

If you're interested in contributing, thanks! I sincerely appreciate it. There's a few main avenues for contributions:

### Getting official buy-in from Logseq

The main blocker right now is getting buy-in from the Logseq team, as I don't want to do the work to add self-hosting settings to the Logseq codebase if they won't be accepted upstream. I've [raised the question on the Logseq forums](https://discuss.logseq.com/t/building-a-self-hostable-sync-implementation/21850/17), as well as in [a GitHub Discussion on the Logseq repo](https://github.com/logseq/logseq/discussions/10733), but have received no official response.

### Understanding/documenting the API

One area where I would love help is specifying the official API more accurately. My API docs are based on a dataset of one, my own account. So there are areas that are underspecified, unknown, or where I just don't understand the flow. Any help there would be great!

Specifically, I'd like to understand:

1. The details of the WebSocket protocol ([doc started here](/docs/WEBSOCKET.md)), and
2. How and when to update the transaction counter, `tx` in the API

### Debugging S3 signature issues

I believe there's a bug ([filed upstream](https://github.com/logseq/rsapi/issues/2), [initially here](https://github.com/bcspragu/logseq-sync/issues/1)) in the `s3-presign` crate used by [Logseq's `rsapi` component](https://github.com/logseq/rsapi), which handles the actual sync protocol bits (encryption, key generation, S3 upload, etc).

The bug causes flaky uploads with self-hosted, AWS-backed (i.e. S3 + STS) servers, but I haven't had the time to investigate the exact root cause. The source code for the `s3-presign` crate [is available here](https://docs.rs/s3-presign/latest/src/s3_presign/lib.rs.html), [the GitHub repo itself](https://github.com/andelf/s3-presign) doesn't appear to be public.
