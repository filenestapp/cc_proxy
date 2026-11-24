"""TCP target for the usage e2e. The first line selects the mode:

  "u <n> d <m>\\n"  read exactly n more bytes, answer exactly m bytes, then close (sized transfer)
  "e\\n"            echo everything until the client closes (a long-lived connection)
"""
import socketserver


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        line = b""
        while not line.endswith(b"\n"):
            chunk = conn.recv(1)
            if not chunk:
                return
            line += chunk
        words = line.split()
        if words[:1] == [b"e"]:
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                conn.sendall(data)
        up, down = int(words[1]), int(words[3])
        while up > 0:
            data = conn.recv(min(up, 65536))
            if not data:
                return
            up -= len(data)
        block = b"y" * 65536
        while down > 0:
            n = min(down, len(block))
            conn.sendall(block[:n])
            down -= n


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


Server(("0.0.0.0", 9000), Handler).serve_forever()
