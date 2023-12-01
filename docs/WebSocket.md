# WebSocket Server

- The websocket server is used to update clients of any updates. The default websocket url used in logseq is wss://ws.logseq.com/file-sync?graphuuid=%s
- The call to the URL takes the graphuuid as a query param
- The current official implementation doesn't verify if the graph with the given UUID exists and just establishes a connection.
- The server does error out when the `graphuuid` query param is missing
- The client keeps sending a PING request to the server (Need to figure out what this implies)
- The server sends a message to all the clients(including the one which triggered the update) which currently has the graph open when the transaction id is updated and contains the updated transaction id.
- The format of the message is same as the response from the `/get_txid` api call.
message: `{"TXId":<a number>}`