#!/usr/bin/env python3

import sys
import socket
import struct

    # TODO: Construct a socket that connects to the mathserver
    #       that can recieve a question from the server, answer it, 
    #       and send it back to the server. If the answer is correct, 
    #       the server will send you the secret code.

def recv_exactly(sock, n):
    # Read exactly n bytes from sock, handling partial TCP delivers.
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Server closed connection unexpectedly")
        buf += chunk
    return buf

def main():
    try:
        host = sys.argv[1]
        port = int(sys.argv[2])
    except (IndexError, ValueError):
        print(f'Usage: {sys.argv[0]} HOST PORT', file=sys.stderr)
        sys.exit(1)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))

        while True:
            msg = recv_exactly(sock, 9)
            msg_type = msg[0]

            if msg_type == ord('Q'):
                a, b = struct.unpack(">II", msg[1:])
                sock.sendall(struct.pack(">I", a + b))

            elif msg_type == ord('S'):
                print(msg[1:].decode())
                break

if __name__ == '__main__':
    main()