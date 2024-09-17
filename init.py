import subprocess
import time

def open_terminals(nodes_num, base_port):
    for i in range(0, nodes_num):
        command = f"python3 node.py {nodes_num} {base_port} {i}"
        subprocess.Popen(["osascript", "-e", f'tell application "Terminal" to do script "{command}"'])

def open_client_terminal(nodes_num, base_port):
    command = f"python3 client.py 1 {nodes_num} {base_port}"
    subprocess.Popen(["osascript", "-e", f'tell application "Terminal" to do script "{command}"'])

nodes_num = 4
base_port = 5045
open_terminals(nodes_num, base_port)
time.sleep(5)
open_client_terminal(nodes_num, base_port)


