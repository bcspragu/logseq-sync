# Logseq Sync

An attempt at an open-source version of the [Logseq Sync](https://blog.logseq.com/how-to-setup-and-use-logseq-sync/) service, intended for individual, self-hosted use.

It's not currently functional! Definitely don't try to point a real, populated Logseq client at it, I have no idea what will happen.

## What's Done/Exists?

Right now, the repo contains (in [`cmd/server`](/cmd/server)) a mostly implemented version of the Logseq API, including credentialed blob uploads, signed blob downloads, an in-memory database (for testing only, will likely write a SQLite backend as the first persistent DB), and most of the API surface at least somewhat implemented.

Currently, running any of this requires a modified version of the Logseq codebase ([here](https://github.com/logseq/logseq/blob/05a82a5f268fb77b01f9b8b2a454f5dc15573e70/src/main/frontend/config.cljs#L40-L41)), and [the `@logseq/rsapi` package](https://www.npmjs.com/package/@logseq/rsapi) ([here](https://github.com/logseq/rsapi/blob/18bd98cfc4d084182b534c1c72a6e473a7174b45/sync/src/sync.rs#L26-L28))

On that note, many thanks to the Logseq Team [for open-sourcing `rsapi` recently](https://github.com/logseq/logseq/issues/9311), it made this project significantly easier to work with.

### What Works?

With a modified Logseq, you can use the local server to create a graph, upload (passphrase-encrypted) encryption keys, and get temporary AWS credentials to upload your encrypted files to your private S3 bucket.

...aaaand that's where things start failing. The current issue I'm working on is [figuring out why signed uploads are failing](#1). Once that's done, the whole process _might_ actually work end-to-end, and only require upstream tweaks to allow custom configurations.

### API Documentation

There's some documentation for the API in [docs/API.md](/docs/API.md). This is the area I could benefit the most from having more information/help on, see [Contributing](#contributing) below

## Open Questions

### S3 API

The real Logseq Sync API gets temp S3 credentials and uploads files direct to S3. I haven't looked closely enough to see if we can swap this out for something S3-compatible like [s3proxy](https://github.com/gaul/s3proxy) or [minio](https://github.com/minio/minio). I get the sense that `amazonaws.com` may be encoded in the client somewhere, but more testing is required.

## Associated Changes to Logseq

Being able to connect to a self-hosted sync server requires some changes to Logseq as well, namely to specify where your sync server can be accessed. Those changes are in a rough, non-functional state here: https://github.com/logseq/logseq/compare/master...bcspragu:logseq:brandon/settings-hack

## Contributing

If you're interested in contributing, thanks! I sincerely appreciate it. That said, at this stage in the project, there's not a lot of work that can be parallelized, I need to clean some stuff up before people can start implementing features, fixing bugs etc.

One area where I would love help is specifying the official API more accurately. My API docs are based on a dataset of one, my own account. So there are areas that are underspecified, unknown, or where I just don't understand the flow. Any help there would be great!
