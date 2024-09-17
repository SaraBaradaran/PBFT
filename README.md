# PBFT
### Model Summary
This implementation assumes that given `N` distributed nodes, among which at most `f` ones are faulty, in the beginning, each node tries to connect to other nodes by calling the method `connect_to_peer`. Similarly, the client also connects to all the nodes within the network by establishing a TCP connection. Upon connecting with each peer or client, the two sides of the connection will exchange their public keys. Now, the system is ready to get the client's request and execute the operations requested. For simplicity, I assume the state of each node is shown by a string `state`. The client, each time, will get a string `o` from stdin and send a request (`<REQUEST, o, t, id>` signed by the client) to the primary. This request means appending the string `o` at the end of the string `state`, which is kept and changed independently by each node.

Upon receiving the client's request, the primary will broadcast a message (`<PRE-PREPARE, v, n, d>` signed by the primary, `<m>` signed by the client) to all the nodes within the network. Each node, when receives the PRE-PREPARE message, checks whether the `<PRE-PREPARE, v, n, d>` and `<m>` are both valid (by verifying their signitures). It also checks whether `h < n < H`, `v` is equal to its current view, `d` is equal to the `m`'s digest, and ensures there is no previous PRE-PREPARE message with the same `n` and `v` but with different `d`.


To run the system and PBFT protocol, run the following command:
```
python3 init.py
```
