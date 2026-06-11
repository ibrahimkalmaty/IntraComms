import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.100.13"
PORT = 9999
CHUNK = 65536

print(f"Connecting to {HOST}:{PORT} ...")

try:
    with socket.socket() as s:
        s.connect((HOST, PORT))
        print("Connected. Receiving data...\n")
        received = 0
        start = time.perf_counter()
        while True:
            data = s.recv(CHUNK)
            if not data:
                break
            received += len(data)
            mb = received / 1_048_576
            elapsed = time.perf_counter() - start
            speed = mb / elapsed if elapsed > 0 else 0
            print(f"\r  Received: {mb:6.1f} MB   Speed: {speed:6.1f} MB/s", end="", flush=True)
        elapsed = time.perf_counter() - start
        mb = received / 1_048_576
        speed_mb = mb / elapsed
        speed_mbit = speed_mb * 8
        print(f"\n\n  Total:   {mb:.1f} MB")
        print(f"  Time:    {elapsed:.2f} s")
        print(f"  Speed:   {speed_mb:.1f} MB/s  ({speed_mbit:.0f} Mbit/s)")
except ConnectionRefusedError:
    print(f"Could not connect to {HOST}:{PORT} — is transfer_server.py running?")
except KeyboardInterrupt:
    print("\nCancelled.")
