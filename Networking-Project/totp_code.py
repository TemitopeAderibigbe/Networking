#!/usr/bin/env python3

import sys
import hmac
import hashlib
import time
import math
import struct
from urllib.parse import urlparse, parse_qs
import base64

# QR code parsing is provided - uses pyzbar/PIL
def parse_qr_code(filename: str) -> str:
    """Parse a QR code image and return the otpauth URI."""
    from PIL import Image
    from pyzbar.pyzbar import decode
    img = Image.open(filename)
    decoded = decode(img)
    if not decoded:
        raise ValueError("No QR code found in image")
    return decoded[0].data.decode("utf-8")


def parse_otpauth_uri(uri: str) -> dict:
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)

    # Defaults per the otpauth spec
    secret_b32 = params["secret"][0]
    digits = int(params.get("digits", ["6"])[0])
    period = int(params.get("period", ["30"])[0])
    algorithm = params.get("algorithm", ["SHA1"])[0].upper()

    # Decode base32 secret (case-insensitive, strip padding issues)
    secret = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))

    return {
        "secret": secret,
        "digits": digits,
        "period": period,
        "algorithm": algorithm,
    }


def hotp(key: bytes, counter: int, digits: int, algorithm: str) -> str:
    # HMAC: counter as 8-byte big-endian
    counter_bytes = struct.pack(">Q", counter)

    hash_func = getattr(hashlib, algorithm.lower().replace("-", ""))
    mac = hmac.new(key, counter_bytes, hash_func).digest()

    # Truncate:
    # 1. offset = last 4 bits of mac
    offset = mac[-1] & 0x0F

    # 2. n = 4 bytes at offset, interpreted as big-endian int
    n = struct.unpack(">I", mac[offset:offset + 4])[0]

    # 3. Clear highest bit
    n = n & 0x7FFFFFFF

    # 4. d-digit code with leading zeros
    code = n % (10 ** digits)
    return str(code).zfill(digits)


def totp(key: bytes, digits: int, period: int, algorithm: str) -> str:
    unix_time = int(time.time())
    t = unix_time // period
    return hotp(key, t, digits, algorithm)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <qr_code_image.png>", file=sys.stderr)
        sys.exit(1)

    qr_file = sys.argv[1]

    uri = parse_qr_code(qr_file)
    params = parse_otpauth_uri(uri)

    code = totp(
        key=params["secret"],
        digits=params["digits"],
        period=params["period"],
        algorithm=params["algorithm"],
    )

    print(code)


if __name__ == "__main__":
    main()
