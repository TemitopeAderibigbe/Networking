#!/usr/bin/env python3

import sys
import ssl
import socket
import struct
import subprocess
import os


def generate_keypair(private_key_path: str) -> str:
    """Generate an Ed25519 keypair if one doesn't exist. Returns PEM-encoded public key."""
    if not os.path.exists(private_key_path):
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ed25519", "-out", private_key_path],
            check=True,
            capture_output=True,
        )

    # Extract public key in PKIX PEM format
    result = subprocess.run(
        ["openssl", "pkey", "-in", private_key_path, "-pubout"],
        check=True,
        capture_output=True,
    )
    return result.stdout.decode("utf-8")


def encode_field(data: bytes) -> bytes:
    """Encode a variable-length field as 2-byte big-endian length + value."""
    return struct.pack(">H", len(data)) + data


def build_request(username: str, password: str, public_key_pem: str) -> bytes:
    """Build the binary MDM protocol request."""
    username_bytes = username.encode("utf-8")
    password_bytes = password.encode("utf-8")
    pubkey_bytes = public_key_pem.encode("utf-8")

    return (
        encode_field(username_bytes)
        + encode_field(password_bytes)
        + encode_field(pubkey_bytes)
    )


def recv_response(sock: ssl.SSLSocket) -> str:
    """Read the length-prefixed response and return as string."""
    # Read 2-byte big-endian length
    length_bytes = b""
    while len(length_bytes) < 2:
        chunk = sock.recv(2 - len(length_bytes))
        if not chunk:
            raise ConnectionError("Connection closed before length received")
        length_bytes += chunk

    data_length = struct.unpack(">H", length_bytes)[0]

    # Read exactly data_length bytes
    data = b""
    while len(data) < data_length:
        chunk = sock.recv(data_length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed before data fully received")
        data += chunk

    return data.decode("utf-8")


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>", file=sys.stderr)
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    username = "mararmst"
    password = "leanne"
    private_key_path = "private.pem"

    # Generate keypair if needed, get public key
    public_key_pem = generate_keypair(private_key_path)

    # Build request
    request = build_request(username, password, public_key_pem)

    # Connect over TLS
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port)) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            tls_sock.sendall(request)
            response = recv_response(tls_sock)

    print(response)


if __name__ == "__main__":
    main()
