import socket
import threading
import time
import json
import hashlib
import sys
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
GREEN = "\033[92m"; RED = "\033[91m"; BLUE = "\033[34m"; RESET = "\033[0m"

client_public_key = ""; client_connectin = ""
h = 1; H = 20; seq_no = 1
max_faulty_nodes = 0

class Node:
    def __init__(self, node_id, nodes_num):
        self.node_id = node_id
        self.message_log = []
        self.state = "$"
        self.view = 0
        self.is_primary = (self.view % nodes_num == node_id)
        self.peers = {}
        self.private_key, self.public_key = self.generate_rsa_keys()

    def generate_rsa_keys(self):
        """generate the pair of public key and private key"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_message(self, string_message):
        """sign the message to ensure its validity."""
        byte_message = string_message.encode('utf-8')
        signature = self.private_key.sign(byte_message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
        ); signature_base64 = base64.b64encode(signature).decode('utf-8')
        return signature_base64

    def verify_signature(self, public_key, string_message, signature_base64):
        """check the validity of the message by verifying its signature."""
        try:
            byte_message = string_message.encode('utf-8')
            signature = base64.b64decode(signature_base64.encode('utf-8'))
            public_key.verify(signature, byte_message,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
            ); return True
        except Exception as e: return False

    def get_string_public_key(self):
        """get the node's public key to send it to other nodes."""
        public_key_pem = self.public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_key_pem_base64 = base64.b64encode(public_key_pem).decode('utf-8')
        return public_key_pem_base64
    
    def receive_public_key(self, conn):
        """receive the public key of each node or client."""
        message = conn.recv(1024).decode('utf-8')
        json_message = json.loads(message)
        print(f"{GREEN}Node {self.node_id} received the public key of the node conncted!{RESET}")
        public_key_pem = base64.b64decode(json_message["public-key"].encode('utf-8'))
        public_key = serialization.load_pem_public_key(public_key_pem)
        return public_key

    def start(self, host, port):
        """start the node and listen for incoming connections."""
        server_thread = threading.Thread(target=self.listen_for_connections, args=(host, port))
        server_thread.start()

    def listen_for_connections(self, host, port):
        """listen for incoming messages from other nodes or client."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(10)
        print(f"Node {self.node_id} listening on port {port}")

        while True:
            conn, addr = server_socket.accept()
            ip_, port_ = addr
            public_key_pem = self.receive_public_key(conn)
            if port_ == (self.node_id + base_port + 1000):
                global client_public_key; client_public_key = public_key_pem
                global client_connectin; client_connectin = conn
                self.send_message_to_client({"public-key" : self.get_string_public_key()})
                print(f"{BLUE}Node {self.node_id} sent its public key to the clinet{RESET}")
            # for each connected node, we will run a thread to continuesly receive the messsages
            # and handle them based on the message type (PREPARE, COMMIT, etc).
            threading.Thread(target=self.handle_message, args=(conn, public_key_pem)).start()
    
    def handle_message(self, conn, public_key_pem):
        """receive the messages from other nodes or client."""
        while True:
            message = conn.recv(1024).decode('utf-8')
            message = json.loads(message)
            print(f"Node {self.node_id} received message: {message}")
            # process each message based on its type and the state of the protocol
            threading.Thread(target=self.process_message, args=(message, public_key_pem)).start()
        
    def connect_to_peer(self, peer_host, peer_port):
        """connect to a peer node and send the public key."""
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((peer_host, peer_port))
            self.peers[peer_port] = peer_socket
            print(f"Node {self.node_id} connected to peer {peer_port}")
            self.send_message(peer_port, {"public-key" : self.get_string_public_key()})
            print(f"{BLUE}Node {self.node_id} sent its public key to peer {peer_port}{RESET}")
        except Exception as e:
            print(f"{RED}Node {self.node_id} failed to connect to peer {peer_port}: {e}{RESET}")

    def send_message(self, peer_port, json_message):
        """send a message to a peer."""
        try:
            self.peers[peer_port].sendall(json.dumps(json_message).encode('utf-8'))
            print(f"{BLUE}Node {self.node_id} sent message to peer {peer_port}: {json_message}{RESET}")
        except Exception as e:
            print(f"{RED}Failed to send message to peer {peer_port}: {e}{RESET}")

    def send_message_to_client(self, json_message): 
        """send a message to the client."""
        try:
            client_connectin.sendall(json.dumps(json_message).encode('utf-8'))
            print(f"{BLUE}Node {self.node_id} sent message to the client: {json_message}{RESET}")
        except Exception as e:
            print(f"{RED}Failed to send message to the client: {e}{RESET}")                      
    
    def get_digest(self, json_message):
        """get the message digest produced by collision-resistant hash function"""
        string_message = json.dumps(json_message)
        input_bytes = string_message.encode('utf-8')
        sha256_hash = hashlib.sha256()
        sha256_hash.update(input_bytes)
        return sha256_hash.hexdigest()

    def broadcast_preprepare_message(self, client_req):
        """broadcast the pre-prepare message to all peers."""
        print(f"{GREEN}Node {self.node_id} is going to broadcast PRE-PREPARE message{RESET}")
        global seq_no; seq_no = seq_no + 1
        json_request = json.loads(client_req["message"])
        self.message_log.append(json_request)
        json_message = {"phase": "PRE-PREPARE",
                        "v": self.view,
                        "n": seq_no,
                        "d": self.get_digest(json_request)}
        self.message_log.append(json_message)
        string_message = json.dumps(json_message)
        signed_message = self.sign_message(string_message)
        for peer_port in self.peers:
            self.send_message(peer_port, {"signed_message": signed_message,
                                          "message": string_message, 
                                          "client_req": client_req})
        # run a thread to continuously check whether prepared(m, v, n, i) is true
        threading.Thread(target=self.check_for_commit, 
            args=(json_request, json_message["v"], json_message["n"])).start()
        # run a thread to continuously check whether commited-local(m, v, n, i) is true
        threading.Thread(target=self.check_for_execution, 
            args=(json_request, json_message["v"], json_message["n"])).start()
    
    def broadcast_prepare_message(self, preprepare_msg):
        """broadcast the prepare message to all peers."""
        print(f"{GREEN}Node {self.node_id} is going to broadcast PREPARE message{RESET}")
        json_request = json.loads(preprepare_msg["client_req"]["message"])
        self.message_log.append(json_request)
        json_preprepare_msg = json.loads(preprepare_msg["message"])
        self.message_log.append(json_preprepare_msg)
        json_message = {"phase": "PREPARE",
                        "v": json_preprepare_msg["v"],
                        "n": json_preprepare_msg["n"],
                        "d": json_preprepare_msg["d"],
                        "i": self.node_id}
        string_message = json.dumps(json_message)
        signed_message = self.sign_message(string_message)
        self.message_log.append(json_message)
        for peer_port in self.peers:
            self.send_message(peer_port, {"signed_message": signed_message,
                                          "message": string_message})
            
    def broadcast_commit_message(self, v, n, d):
        """broadcast the commit message to all peers."""
        print(f"{GREEN}Node {self.node_id} is going to broadcast COMMIT message{RESET}")
        json_message = {"phase": "COMMIT",
                        "v": v,
                        "n": n,
                        "d": d,
                        "i": self.node_id}
        string_message = json.dumps(json_message)
        signed_message = self.sign_message(string_message)
        self.message_log.append(json_message)
        for peer_port in self.peers:
            self.send_message(peer_port, {"signed_message": signed_message,
                                          "message": string_message}) 

    def check_for_commit(self, m, v, n):
        d = self.get_digest(m)
        json_message = {"phase": "PRE-PREPARE",
                        "v": v,
                        "n": n,
                        "d": d}
        while True:
            t = self.count_logs(v, n, d, "PREPARE")
            predicate = (m in self.message_log and json_message in self.message_log and t >= 2 * max_faulty_nodes)
            print(f"prepared(m, {v}, {n}, {self.node_id}) = {predicate}")
            time.sleep(1)
            if predicate: self.broadcast_commit_message(v, n, d); return

    def check_for_execution(self, m, v, n):            
        d = self.get_digest(m)
        json_message = {"phase": "PRE-PREPARE",
                        "v": v,
                        "n": n,
                        "d": d}
        while True:
            t1 = self.count_logs(v, n, d, "PREPARE")
            t2 = self.count_logs(v, n, d,  "COMMIT")
            predicate = (m in self.message_log and json_message in self.message_log 
                            and t1 >= 2 * max_faulty_nodes and t2 >= (2 * max_faulty_nodes + 1))
            print(f"committed-local(m, {v}, {n}, {self.node_id}) = {predicate}")
            time.sleep(1)
            if predicate: 
                print(f"{RED}Hey! Node {self.node_id} successfully executed the operation!{RESET}"); 
                self.state += m["o"]
                print(f"{RED}The current state of node {self.node_id} is {self.state}!{RESET}"); 
                self.send_reply_message(m); return
            
    def send_reply_message(self, client_req):
        json_reply = {"phase": "REPLY",
                      "v": self.view,
                      "t": client_req["t"],
                      "c": client_req["c"],
                      "i": self.node_id,
                      "r": self.state}
        string_reply = json.dumps(json_reply)
        signed_reply = self.sign_message(string_reply)
        self.send_message_to_client({"signed_message": signed_reply,
                                     "message": string_reply})

    def count_logs(self, v, n, d, phase):
        count = 0
        for log in self.message_log:
            if (log["phase"] == phase and log["v"] == v 
                and log["n"] == n and log["d"] == d):
                count = count + 1
        return count
            
    def process_message(self, packet, public_key_pem):
        """process the PBFT message based on the phase."""
        json_message = json.loads(packet["message"])
        phase = json_message["phase"]

        if phase == "REQUEST" and self.is_primary:
            print(f"{GREEN}Node {self.node_id} received the client request{RESET}")
            self.broadcast_preprepare_message(packet)
        elif phase == "PRE-PREPARE" and not self.is_primary:
            if self.accept_preprepare_message(packet, public_key_pem):
                print(f"{GREEN}Node {self.node_id} accepted the PRE-PREPARE message{RESET}")
                self.broadcast_prepare_message(packet)
                json_request = json.loads(packet["client_req"]["message"])
                # run a thread to continuously check whether prepared(m, v, n, i) is true
                threading.Thread(target=self.check_for_commit, 
                    args=(json_request, json_message["v"], json_message["n"])).start()
                # run a thread to continuously check whether commited-local(m, v, n, i) is true
                threading.Thread(target=self.check_for_execution, 
                    args=(json_request, json_message["v"], json_message["n"])).start()
        elif phase == "PREPARE":
            if self.accept_prepare_message(packet, public_key_pem):
                self.message_log.append(json_message)
                print(f"{GREEN}Node {self.node_id} accepted the PREPARE message{RESET}")
        elif phase == "COMMIT":
            if self.accept_commit_message(packet, public_key_pem):
                self.message_log.append(json_message)
                print(f"{GREEN}Node {self.node_id} accepted the COMMIT message{RESET}")

    def accept_preprepare_message(self, packet, primary_public_key):
        signed_message = packet["signed_message"]
        json_message = json.loads(packet["message"])
        string_message = json.dumps(json_message)
        
        client_req = packet["client_req"]
        signed_request = client_req["signed_message"]
        json_request = json.loads(client_req["message"])
        string_request = json.dumps(json_request)

        valid_primary_msg = self.verify_signature(primary_public_key, string_message, signed_message)
        valid_request = self.verify_signature(client_public_key, string_request, signed_request)
        valid_digest = (self.get_digest(json_request) == json_message["d"])
        valid_sequence = (h < json_message["n"] and json_message["n"] < H)
        valid_view = (self.view == json_message["v"])
        no_previous_request = True
        for log in self.message_log:
            if (log["phase"] == "PRE-PREPARE" and log["d"] != json_message["d"] 
            and log["v"] == json_message["v"] and log["n"] == json_message["n"]):
                no_previous_request = False
        if (valid_primary_msg and valid_request and no_previous_request
            and valid_view and valid_digest and valid_sequence): return True
        else: return False

    def accept_prepare_message(self, packet, replica_public_key):
        signed_message = packet["signed_message"]
        json_message = json.loads(packet["message"])
        string_message = json.dumps(json_message)
        
        valid_msg = self.verify_signature(replica_public_key, string_message, signed_message)
        valid_view = (self.view == json_message["v"])
        valid_sequence = (h < json_message["n"] and json_message["n"] < H)

        if valid_msg and valid_view and valid_sequence: return True
        else: return False
    
    def accept_commit_message(self, packet, replica_public_key):
        signed_message = packet["signed_message"]
        json_message = json.loads(packet["message"])
        string_message = json.dumps(json_message)
        
        valid_msg = self.verify_signature(replica_public_key, string_message, signed_message)
        valid_view = (self.view == json_message["v"])
        valid_sequence = (h < json_message["n"] and json_message["n"] < H)

        if valid_msg and valid_view and valid_sequence: return True
        else: return False

if __name__ == '__main__':
    nodes_num = int(sys.argv[1])
    base_port = int(sys.argv[2])
    node_id = int(sys.argv[3])
    max_faulty_nodes = int(sys.argv[4])
    
    node_port = base_port + node_id
    node = Node(node_id=node_id, nodes_num=nodes_num)
    node.start('localhost', node_port)
    time.sleep(3)
    
    # connect nodes to each other
    for i in range(nodes_num):
        if i != node_id:
            node.connect_to_peer('localhost', base_port + i)
