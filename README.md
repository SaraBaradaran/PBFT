# PBFT
### Model Summary
This implementation assumes that given `N` distributed nodes, among which at most `f` ones are faulty, in the beginning, each node tries to connect to other nodes by calling the method `connect_to_peer`. Similarly, the client also connects to all the nodes within the network by establishing a TCP connection. Upon connecting with each peer or client, the two sides of the connection will exchange their public keys. Now, the system is ready to get the client's request and execute the operations requested. For simplicity, I assume the state of each node is shown by a string `state`. The client, each time, will get a string `o` from stdin and send a request (`<REQUEST, o, t, id>` signed by the client) to the primary. This request means appending the string `o` at the end of the string `state`, which is kept and changed independently by each node.

Upon receiving a client's request (<`m`> signed by the client), the primary will broadcast a message (`<PRE-PREPARE, v, n, d>` signed by the primary, `<m>` signed by the client) to all the nodes within the network. Each node, when it receives the PRE-PREPARE message, checks whether the `<PRE-PREPARE, v, n, d>` and `<m>` are both valid (by verifying their signatures). It also checks whether `h < n < H`, `v` is equal to its current view, `d` is equal to the `m`'s digest, and ensures there is no previous PRE-PREPARE message with the same `n` and `v` but with different `d`. If all the constraints above become satisfied, then the node accepts the PRE-PREPARE message, adds both `<PRE-PREPARE, v, n, d>` and `<m>` to its logs, and broadcasts a PREPARE message to all the nodes within the network. This PREPARE message is in form (`<PREPARE, v, n, d, i>` signed by the node `i`). The node also adds PREPARE message sent to its logs. When a node receives a PREPARE message, it first verifies the message's signature and checks whether `h < n < H` and `v` is equal to its current view. If so, the node accepts the PREPARE message and adds it to its logs. 

After accepting the PRE-PREPARE message by a non-primary replica or after broadcasting the PRE-PREPARE message by the primary, two treads start running. One thread continuously checks whether the predicate `prepared(m, v, n, i)` is true, meaning that replica `i` has inserted in its log: the request `m`, a PRE-PREPARE for `m` in view `v` with sequence number `n`, and `2f` PREPARE from different backups that match the aforementioned PRE-PREPARE. If `prepared(m, v, n, i)` is true, the replica `i` broadcasts a COMMIT message to all the nodes within the network as well as adding it to its log. This COMMIT message is in form (`<COMMIT, v, n, d, i>` signed by the node `i`). When a node receives a COMMIT message, it first verifies the message's signature and checks whether `h < n < H` and `v` is equal to its current view. If so, the node accepts the COMMIT message and adds it to its logs. The second thread, mentioned above, continuously checks whether the predicate `committed-local(m, v, n, i)` is true, meaning that `prepared(m, v, n, i)` is true and replica `i` has accepted `2f+1` COMMIT messages (including its own) from different replicas that match the PRE-PREPARE for `m`. If `committed-local(m, v, n, i)` becomes true, then the replica `i` will concatenate its `state` with the requested `o` and send a REPLY message directly to the client. The REPLY is in form (`<REPLY, v, t, c, i, r>` signed by replica `i`), where `v` is the current view of the replica, `t` is the timestamp of the corresponding request, and `r` is the result of executing the requested operation (i.e., the value of string `state` after concatenating the requested `o`).

After sending a request, the client runs a thread to continuously check if `f+1` REPLY messages has been received from different nodes with valid signatures, the same `t` as it was in the request, and the same result `r.`  This means that the requested operation has been done successfully, and the client is ready to get another request from stdin and send it to the primary again.

### How to run the protocol?
There is a file `init.py` in this repository using which you can specify the total number of nodes and the maximum number of Byzantine nodes.
To run the system and PBFT protocol, run the following command:
```
python3 init.py
```
