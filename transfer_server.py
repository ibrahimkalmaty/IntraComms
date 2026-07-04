import socket
import time

HOST = "0.0.0.0"
PORT = 9999
CHUNK = 65536
DATA_MB = 100

with socket.socket() as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"Transfer speed test server — listening on port {PORT}")
    print(f"Will send {DATA_MB} MB per connection. Ctrl+C to quit.\n")

    while True:
        conn, addr = s.accept()
        print(f"Connected: {addr[0]}:{addr[1]}")
        payload = b"x" * CHUNK
        total = DATA_MB * 1024 * 1024
        sent = 0
        start = time.perf_counter()
        with conn:
            while sent < total:
                conn.sendall(payload)
                sent += CHUNK
        elapsed = time.perf_counter() - start
        speed_mb = DATA_MB / elapsed
        speed_mbit = speed_mb * 8
        print(f"  Sent:    {DATA_MB} MB")
        print(f"  Time:    {elapsed:.2f} s")
        print(f"  Speed:   {speed_mb:.1f} MB/s  ({speed_mbit:.0f} Mbit/s)\n")
