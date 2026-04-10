#!/usr/bin/env python3

import sys
import ssl
import socket
import struct


def encode_domain_name(domain: str) -> bytes:
    result = b""
    # Strip trailing dot if present
    domain = domain.rstrip(".")
    for label in domain.split("."):
        encoded = label.encode("utf-8")
        result += bytes([len(encoded)]) + encoded
    result += b"\x00"  # root label
    return result


def build_query(domain: str) -> bytes:
    # Header fields
    msg_id = 0x1337          # arbitrary ID
    flags = 0x0000           # QR=0 (query), Opcode=0, RD=0, all zeros
    qdcount = 1              # one question
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack(">HHHHHH",
        msg_id, flags, qdcount, ancount, nscount, arcount)

    # Question section
    qname = encode_domain_name(domain)
    qtype = 255   # ANY
    qclass = 1    # IN (internet)
    question = qname + struct.pack(">HH", qtype, qclass)

    return header + question


def decode_domain_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    visited = set()  # guard against infinite loops in compression

    while True:
        if offset >= len(data):
            break

        length = data[offset]

        # Check for compression pointer (top two bits set = 0xC0)
        if (length & 0xC0) == 0xC0:
            if offset in visited:
                break
            visited.add(offset)
            # Pointer: next byte gives lower 8 bits of target offset
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            # Follow pointer — but don't advance offset further after this
            ptr_labels, _ = decode_domain_name(data, pointer)
            # ptr_labels already has trailing dot, strip it to extend
            labels.append(ptr_labels.rstrip("."))
            return ".".join(labels) + ".", offset

        # Normal label
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("utf-8"))
        offset += length

    return ".".join(labels) + ".", offset


def parse_response(data: bytes) -> list[tuple]:
    offset = 0

    # Parse header
    msg_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(">HHHHHH", data, offset)
    offset += 12

    # Skip questions
    for _ in range(qdcount):
        _, offset = decode_domain_name(data, offset)
        offset += 4  # QTYPE + QCLASS

    # Parse answer records
    records = []
    total_rrs = ancount + nscount + arcount
    for _ in range(total_rrs):
        name, offset = decode_domain_name(data, offset)
        rtype, rclass, ttl, rdlength = struct.unpack_from(">HHIH", data, offset)
        offset += 10  # 2+2+4+2
        rdata = data[offset:offset + rdlength]
        offset += rdlength

        if rtype == 1:  # A record
            ip = ".".join(str(b) for b in rdata)
            records.append((name, "A", ip))

        elif rtype == 16:  # TXT record
            # TXT rdata: one or more length-prefixed strings
            txt_offset = 0
            parts = []
            while txt_offset < len(rdata):
                txt_len = rdata[txt_offset]
                txt_offset += 1
                parts.append(rdata[txt_offset:txt_offset + txt_len].decode("utf-8"))
                txt_offset += txt_len
            records.append((name, "TXT", "".join(parts)))

    return records


def main():
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <chain.pem> <private.pem> <nameserver_host> <port>",
              file=sys.stderr)
        sys.exit(1)

    chain_file = sys.argv[1]
    key_file   = sys.argv[2]
    host       = sys.argv[3]
    port       = int(sys.argv[4])
    domain     = "evil-corp.ink"

    # Build DNS ANY query
    query = build_query(domain)

    # DNS-over-TLS: prepend 2-byte length
    dot_message = struct.pack(">H", len(query)) + query

    # Set up mTLS context with our client cert
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile=chain_file, keyfile=key_file)

    with socket.create_connection((host, port)) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            tls_sock.sendall(dot_message)

            # Read 2-byte length prefix
            length_bytes = b""
            while len(length_bytes) < 2:
                chunk = tls_sock.recv(2 - len(length_bytes))
                if not chunk:
                    raise ConnectionError("Connection closed reading length")
                length_bytes += chunk
            response_length = struct.unpack(">H", length_bytes)[0]

            # Read full response
            response = b""
            while len(response) < response_length:
                chunk = tls_sock.recv(response_length - len(response))
                if not chunk:
                    raise ConnectionError("Connection closed reading response")
                response += chunk

    records = parse_response(response)
    for name, rtype, rdata in records:
        print(f"{name} {rtype} {rdata}")


if __name__ == "__main__":
    main()
