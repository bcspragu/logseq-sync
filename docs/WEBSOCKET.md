# Logseq Sync WebSocket Endpoint

The Logseq Sync protocol features a WebSocket-based endpoint at `/file-sync?graphuuid=<graph ID>`, which serves to notify a client of changes from other clients (and itself).

- The default websocket URL used in Logseq is `wss://ws.logseq.com/file-sync?graphuuid=%s`
  - The `graphuuid` query param is the UUID of the graph, which makes sense
- The official Logseq Sync implementation doesn't verify that a graph with the given UUID exists
  - It does error out when the `graphuuid` query param is missing
- The client periodically (how frequently?) sends a PING request to the server
  - Likely just to serve as a heartbeat, [PING/PONG are built into WebSockets](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#pings_and_pongs_the_heartbeat_of_websockets)
- When an update occurs (on what endpoint?), the server sends a message to all the clients (including the one which triggered the update) that have an open WebSocket connection for the updated graph
  - The format of the message is same as the response from the `/get_txid` api call, e.g `{"TXId":<a number>}`
