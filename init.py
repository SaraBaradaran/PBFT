import subprocess
import time

def open_replica_terminals(nodes_num, base_port, max_faulty_nodes):
    for i in range(0, nodes_num):
        command = f"python3 node.py {nodes_num} {base_port} {i} {max_faulty_nodes}"
        subprocess.Popen(["osascript", "-e", f'tell application "Terminal" to do script "{command}"'])

def open_client_terminal(nodes_num, base_port, max_faulty_nodes):
    command = f"python3 client.py 1 {nodes_num} {base_port} {max_faulty_nodes}"
    subprocess.Popen(["osascript", "-e", f'tell application "Terminal" to do script "{command}"'])

max_faulty_nodes = 1
nodes_num = 3 * max_faulty_nodes + 1
base_port = 5055
open_replica_terminals(nodes_num, base_port, max_faulty_nodes)
time.sleep(5)
open_client_terminal(nodes_num, base_port, max_faulty_nodes)
