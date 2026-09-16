"""
"""BACnet/IP stub listener for the OT simulation environment.
Listens on UDP 47808 (standard BACnet/IP port).

NOTE: Real BACnet broadcast behavior requires BBMD (BACnet Broadcast
Management Device) setup or bacpypes3 foreign device configuration.
This stub produces visible UDP traffic on the correct port so Scrutics
can observe and classify it during simulation runs.
OUI-based fingerprinting only. Flagged for proper BACnet/IP implementation
in a later phase.
"""
import socket
import time

HOST = "0.0.0.0"
PORT = 47808

print(f"[*] BACnet/IP stub listening on UDP {HOST}:{PORT}")
print("[!] Note: BBMD/broadcast not implemented — stub for OUI fingerprinting only")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))

while True:
    try:
        data, addr = s.recvfrom(1024)
    except Exception:
        time.sleep(0.1)
