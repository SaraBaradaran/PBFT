# PBFT
### Model Summary
This implementation assumes that given N distributed nodes, among which at most f ones are faulty, in the beginning, each node tries to connect to other nodes by calling the method `connect_to_peer`. Similarly, the client also connects to all the nodes within the network by establishing a TCP connection. Upon connecting with each peer or client, the two sides of the connection will exchange their public keys. Now, the system is ready to get the client's request and execute the operations requested. For simplicity, I assume the state of each node is shown by a string `state`. The client, each time, will get a string `o` from stdin and send a request (`<REQUEST, o, t, id>` signed by the client) to the primary. This request means appending the string `o` at the end of the string `state`, which is kept and changed independently by each node.


To run the system and PBFT protocol, run the following command:
```
python3 init.py
```
