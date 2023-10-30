# Logseq Sync

Note: This project/repo is brand new, nothing works yet.

An attempt at an open-source version of the [Logseq Sync](https://blog.logseq.com/how-to-setup-and-use-logseq-sync/) service, intended for individual, self-hosted use.

## What's Done/Exists?

Right now, the repo contains some basic tools for inspecting traffic from the Logseq client, and some documentation for the API in [docs/API.md](/docs/API.md). The server in [`cmd/server`](/cmd/server) has stubs for most of the known Logseq Sync API endpoints, and basic functionality for a few endpoints, backed by an in-memory database for testing.

## Open Questions

## S3 API

The real Logseq Sync API gets temp S3 credentials and uploads files direct to S3. I haven't looked closely enough to see if we can swap this out for something S3-compatible like [s3proxy](https://github.com/gaul/s3proxy) or [minio](https://github.com/minio/minio). I get the sense that `amazonaws.com` may be encoded in the client somewhere, but more testing is required.

## Associated Changes to Logseq

Being able to connect to a self-hosted sync server requires some changes to Logseq as well, namely to specify where your sync server can be accessed. Those changes are in a rough, non-functional state here: https://github.com/logseq/logseq/compare/master...bcspragu:logseq:brandon/settings-hack
