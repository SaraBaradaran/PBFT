import socket
import threading
import time
import json
import sys
import base64
from collections import defaultdict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
GREEN = "\033[92m"; RED = "\033[91m"; BLUE = "\033[34m"; RESET = "\033[0m"

max_faulty_nodes = 0

class Client:
    def __init__(self, client_id):
        self.client_id = client_id
        self.server_nodes = {}
        self.reply_log = []
        self.private_key, self.public_key = self.generate_rsa_keys()

    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_message(self, string_message):
        byte_message = string_message.encode('utf-8')
        signature = self.private_key.sign(byte_message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
        ); 
        signature_base64 = base64.b64encode(signature).decode('utf-8')
        return signature_base64

    def verify_signature(self, public_key, string_message, signature_base64):
        try:
            byte_message = string_message.encode('utf-8')
            signature = base64.b64decode(signature_base64.encode('utf-8'))
            public_key.verify(signature, byte_message,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
            ); return True
        except Exception as e:
            return False

    def get_string_public_key(self):
        public_key_pem = self.public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_key_pem_base64 = base64.b64encode(public_key_pem).decode('utf-8')
        return public_key_pem_base64

    def receive_public_key(self, node_port):
        """receive the public key of each node or client."""
        message = self.server_nodes[node_port].recv(1024).decode('utf-8')
        json_message = json.loads(message)
        print(f"{GREEN}Client {self.client_id} received the public key of the node conncted!{RESET}")
        public_key_pem = base64.b64decode(json_message["public-key"].encode('utf-8'))
        public_key = serialization.load_pem_public_key(public_key_pem)
        return public_key
    
    def connect_to_server(self, node_host, node_port):
        """connect to a server nodes."""
        try:
            node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_ip = 'localhost'
            client_port = node_port + 1000
            node_socket.bind((client_ip, client_port))
            node_socket.connect((node_host, node_port))
            self.server_nodes[node_port] = node_socket
            print(f"Client {self.client_id} connected to node {node_port}")
            self.send_message(node_port, {"public-key" : self.get_string_public_key()})
            print(f"{BLUE}Client {self.client_id} sent its public key to replica {node_port}{RESET}")
            public_key_pem = self.receive_public_key(node_port)
            threading.Thread(target=self.handle_message, args=(node_port, public_key_pem)).start()
        except Exception as e:
            print(f"{RED}Client {self.client_id} failed to connect to node {node_port}: {e}{RESET}")

    def send_message(self, node_port, json_message):
        """send a message to a node."""
        try:
            self.server_nodes[node_port].sendall(json.dumps(json_message).encode('utf-8'))
            print(f"{BLUE}Client {self.client_id} sent message to node {node_port}: {json_message}{RESET}")
        except Exception as e:
            print(f"{RED}Failed to send message to node {node_port}: {e}{RESET}")
    
    def handle_message(self, node_port, public_key_pem):
        """receive the messages from nodes."""
        while True:
            message = self.server_nodes[node_port].recv(1024).decode('utf-8')
            message = json.loads(message)
            print(f"Client {self.client_id} received message from {node_port}: {message}")
            threading.Thread(target=self.process_message, args=(message, public_key_pem)).start()

    def process_message(self, packet, public_key_pem):
        """process the PBFT message reply."""
        json_message = json.loads(packet["message"])
        phase = json_message["phase"]
        if phase == "REPLY":
            if self.accept_reply_message(packet, public_key_pem):
                print(f"{GREEN}Client received a REPLY message{RESET}")
                self.reply_log.append(json_message)

    def accept_reply_message(self, packet, replica_public_key):
        signed_message = packet["signed_message"]
        json_message = json.loads(packet["message"])
        string_message = json.dumps(json_message)
        
        valid_msg = self.verify_signature(replica_public_key, string_message, signed_message)

        if valid_msg: return True
        else: return False
    
    def check_for_enough_replies(self, t):
        while True:
            tt =  self.count_max_replies(t)
            predicate = (tt >= max_faulty_nodes + 1)
            print(f"enough_replies({t}) = {predicate}")
            time.sleep(1)
            if predicate: 
                print(f"{RED}Client received at least f + 1 = {max_faulty_nodes + 1} replies from replicas{RESET}"); 
                self.reply_log.clear(); return
        
    def count_max_replies(self, t):
        r_count = defaultdict(int)
        for log in self.reply_log:
            if log["phase"] == "REPLY": r_count[log["r"]] += 1
        return max(r_count.values(), default=0)

if __name__ == '__main__':
    client_id = int(sys.argv[1])
    nodes_num = int(sys.argv[2])
    base_port = int(sys.argv[3])
    max_faulty_nodes = int(sys.argv[4])
    curr_view = 0
    primary_id = curr_view % nodes_num

    client = Client(client_id=client_id)
   
    # connect client to each node
    for i in range(nodes_num):
        client.connect_to_server('localhost', base_port + i)
    
    while True:
        o = input("Enter a request as a string : ")
        json_request = {"phase": "REQUEST",
                        "o": o,
                        "t": time.time(),
                        "c": client_id}
        string_request = json.dumps(json_request)
        signed_request = client.sign_message(string_request)
        client.send_message(base_port + primary_id, {"signed_message": signed_request,
                                                     "message": string_request})
        threading.Thread(target=client.check_for_enough_replies, 
                                            args=(json_request["t"],)).start()
