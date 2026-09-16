"""
EtherNet/IP stub listener for the OT simulation environment.
Listens on TCP 44818 (standard EtherNet/IP port) and accepts connections.
Does NOT implement CIP — flagged for replacement when protocol banner
fingerprinting is added.
"""
import socket
import time

HOST = "0.0.0.0"
PORT = 44818

print(f"[*] EtherNet/IP stub listening on {HOST}:{PORT}")
print("[!] Note: CIP protocol not implemented — stub for OUI fingerprinting only")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(5)

while True:
    try:
        conn, addr = s.accept()
        conn.close()
    except Exception:
        time.sleep(0.1)
