# Logseq Sync API

Some notes on how I think the API works from observing traffic.

## Request sources

* `fetch` - Standard JavaScript `fetch`
  * The majority of API requests come through here I think
* `electron` - Requests coming from the Electron app itself
  * I don't actually know how this differs from `fetch`
* `rsapi` - A Rust-based (!!) wrapper around some sync + encryption functionality, [currently not open-source](https://github.com/logseq/logseq/issues/9311)
  * I assume this one compiles to WASM, though not sure how HTTP requests from a WASM runtime work.
  * I couldn't get this one working with [my proxy](/cmd/server), but was able to inspect traffic by using [`mitmproxy`](https://mitmproxy.org/)

## Endpoints

All endpoints are HTTP `POST` and prefixed with `https://<API-DOMAIN>/file-sync/<api path>` unless otherwise noted.

### `/get_files_meta`

Request

```
{
  "Files":["e.<random hex>"],
  "GraphUUID":"<uuid>"
}
```

Response

```
[
  {
    "FilePath":"e.<same random hex>",
    "Checksum":"<16-byte hex checksum>",
    "LastModified": <unix timestamp milliseconds>,
    "Size":343,
    "Txid":1
  }
]
```

Can also return `not found`, I think for new files

```
[
  {
    "FilePath":"e.<random hex>",
    "Error":"not found <user uuid>/<graph uuid>/e.<same random hex>"
  }
]
```

### `/user_info`

Request: `{}`

Response

```
{
  "ExpireTime":<unix timestamp seconds>,
  "UserGroups":[<group labels>],
  "ProUser":<bool>,
  "StorageLimit":<some number of bytes>,
  "GraphCountLimit":<n>,
  "LemonRenewsAt":null,
  "LemonEndsAt":null,
  "LemonStatus":null
}
```

### `/list_graphs`

Request: `null`

Response

```
{
  "Graphs":[
    {
      "GraphStorageLimit":<large number of bytes>,
      "GraphName":<graph name>,
      "GraphUUID":<graph uuid>,
      "GraphStorageUsage":<smaller number of bytes>
    }
  ]
}
```

### `/create_graph`

Request: `{"GraphName":<graph name>}`
Response: `{"graphuuid":"<graph uuid","txid":0}`

Or if the graph already exists: `{"message":"graph[<graph name>] already exists "}`

# `/delete_graph`

Request: `{"GraphUUID":"<graph uuid>"}`

No response body, HTTP 200

# `/get_graph_encrypt_keys`

Request: `{"GraphUUID":"<graph uuid>"}`

Response is HTTP 404 with no body if it doesn't exist

# `/get_graph_salt`

Request: `{"GraphUUID":"<graph uuid>"}`

Response is HTTP 410 with no body, I think if it doesn't exist?

# `/create_graph_salt`

Request: `{"GraphUUID":"<graph uuid>"}`

Response

```
{
  "value":"<64-byte Base64 salt>",
  "expired-at":<unix timestamp milliseconds>
} 
```

# `/upload_graph_encrypt_keys`

Request

```
{
  "encrypted-private-key":"-----BEGIN AGE ENCRYPTED FILE-----\n<base64 encrypted data, starts with "age-encryption.org/v1">\n-----END AGE ENCRYPTED FILE-----\n",
  "GraphUUID":"<graph uuid>",
  "public-key":"age<age public key>"
}
```

Response is HTTP 200 with no body

# `/get_all_files`

Request: `{"GraphUUID":"<graph uuid>"}`

Response

```
{
  "Objects": [
    {
      "Key": "<user uuid>/<graph uuid>/e.<35-bytes hex-encoded>",
      "LastModified": <unix ts millis>,
      "checksum": "<16-bytes hex-encoded>",
      "Size": <size in bytes>,
      "Txid": <tx num>
    },
    {
      "Key": "<user uuid>/<graph uuid>/e.<35-bytes hex-encoded>",
      "LastModified": <unix ts millis>,
      "checksum": "<16-bytes hex-encoded>",
      "Size": <size in bytes>,
      "Txid": <tx num>
    },
    {
      "Key": "<user uuid>/<graph uuid>/e.<35-bytes hex-encoded>",
      "LastModified": <unix ts millis>,
      "checksum": "<16-bytes hex-encoded>",
      "Size": <size in bytes>,
      "Txid": <tx num>
    },
    {
      "Key": "<user uuid>/<graph uuid>/e.<35-bytes hex-encoded>",
      "LastModified": <unix ts millis>,
      "checksum": "<16-bytes hex-encoded>",
      "Size": <size in bytes>,
      "Txid": <tx num>
    },
    {
      "Key": "<user uuid>/<graph uuid>/e.<35-bytes hex-encoded>",
      "LastModified": <unix ts millis>,
      "checksum": "<16-bytes hex-encoded>",
      "Size": <size in bytes>,
      "Txid": <tx num>
    }
  ],
  "NextContinuationToken": ""
}
```

Notes:

* Keys are all different
* Txid not all the same either

### `/get_txid`

Request: `{"GraphUUID":"<graph uuid>"}`
Response: `{"TXId":<a number>}`

### /get_deletion_log_v20221212

Request

```
{
  "GraphUUID":"<graph uuid>",
  "FromTXId":<a number>
}
```

Response: `{"Transactions":[]}`


### `/get_files`

Note: This comes from `rsapi`

Request

```
{
  "Files":["e.<hex>"],
  "GraphUUID":"<graph uuid>"
}
```

Response

```
{
  "PresignedFileUrls": {
    "e.<file>": "https://logseq-file-sync-bucket-prod.s3.amazonaws.com/<user>/<graph>/e.<file>?<lots of params for temporary access to read from S3>"
  }
}
```

### `/get_temp_credential`

Response

```
{
  "Credentials": {
    "AccessKeyId": "<AWS key ID",
    "Expiration": "YYYY-MM-DDTHH:MM:SSZ",
    "SecretKey": "<random string>",
    "SessionToken": "<long string>"
  },
  "S3Prefix": "logseq-file-sync-bucket-prod/temp/us-east-1:<random uuid>"
}
```

I think this gives access to some random scratchpad to upload files, which are then moved into place?

### Known endpoints to finish documenting

I have data on these ones and just need to clean it up a bit.

- [ ] `GET https://<API-DOMAIN>/logseq/version`
- [ ] `/update_files`

### Known missing

I'm aware of these ones and just need to capture them better

- [ ] /delete_files
- [ ] /rename_files
