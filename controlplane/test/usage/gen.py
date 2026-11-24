"""Traffic generator run inside a client container, through the device's sing-box SOCKS inbound (127.0.0.1:2080).
Prints one JSON object with the payload bytes the exit should attribute to this device:

  short N UP DOWN      N sequential short-lived connections, each a sized transfer
  parallel N UP DOWN   N concurrent sized transfers
  stream SECONDS       one long echo connection sending 1000 bytes every 20 ms until SECONDS pass or it is cut
"""
import json
import socket
import struct
import sys
import threading
import time

SINK = ("10.99.1.10", 9000)


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed during SOCKS handshake")
        data += chunk
    return data


def socks():
    sock = socket.create_connection(("127.0.0.1", 2080), timeout=30)
    sock.sendall(b"\x05\x01\x00")
    if recv_exact(sock, 2) != b"\x05\x00":
        raise ConnectionError("SOCKS method refused")
    sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(SINK[0]) + struct.pack(">H", SINK[1]))
    reply = recv_exact(sock, 10)
    if reply[1] != 0:
        raise ConnectionError("SOCKS connect failed: %d" % reply[1])
    return sock


def sized(up, down):
    sock = socks()
    header = ("u %d d %d\n" % (up, down)).encode()
    sock.sendall(header + b"x" * up)
    got = 0
    while True:
        data = sock.recv(65536)
        if not data:
            break
        got += len(data)
    sock.close()
    if got != down:
        raise RuntimeError("expected %d bytes back, got %d" % (down, got))
    return len(header) + up, got


def main(argv):
    mode = argv[0]
    total = {"up": 0, "down": 0, "connections": 0}
    if mode == "short":
        n, up, down = map(int, argv[1:4])
        for _ in range(n):
            u, d = sized(up, down)
            total["up"] += u
            total["down"] += d
            total["connections"] += 1
    elif mode == "parallel":
        n, up, down = map(int, argv[1:4])
        lock, errors = threading.Lock(), []

        def one():
            try:
                u, d = sized(up, down)
                with lock:
                    total["up"] += u
                    total["down"] += d
                    total["connections"] += 1
            except Exception as e:  # reported below
                errors.append(repr(e))

        threads = [threading.Thread(target=one) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if errors:
            raise RuntimeError("; ".join(errors))
    elif mode == "stream":
        seconds = float(argv[1])
        sock = socks()
        sock.settimeout(5)
        header = b"e\n"
        sock.sendall(header)
        total["up"] += len(header)
        total["connections"] = 1
        chunk, deadline, cut = b"z" * 1000, time.time() + seconds, False
        while time.time() < deadline:
            try:
                sock.sendall(chunk)
                total["up"] += len(chunk)
                need = len(chunk)
                while need:
                    data = sock.recv(need)
                    if not data:
                        raise ConnectionError("closed")
                    total["down"] += len(data)
                    need -= len(data)
            except (OSError, ConnectionError):
                cut = True
                break
            time.sleep(0.02)
        total["cut"] = cut
        sock.close()
    else:
        raise SystemExit("unknown mode " + mode)
    print(json.dumps(total))


if __name__ == "__main__":
    main(sys.argv[1:])
