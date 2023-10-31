# Terraform

NOTE: None of this Terraform is tested, definitely don't use it yet!

This directory contains configuration for AWS resources currently needed by the application. The Logseq Sync protocol has the client upload blobs to a S3-compatible blob store, this is a codified version of the infrastructure needed to set that up.

Longer term, I still need to figure out if other blob stores (MinIO, other S3-compatible stores) can be used, or if assumptions about S3 are baked into the protocol, but to get things working end-to-end first, I figured it prudent to start with what the official implementation does.
