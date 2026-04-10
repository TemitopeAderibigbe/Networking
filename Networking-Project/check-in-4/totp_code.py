# Some imports that we think may be useful to you.
from PIL import Image
from pyzbar.pyzbar import decode
from urllib.parse import parse_qs, urlparse
import base64
import hmac
import sys
import time


def hotp(k, c, digits):
    # TODO: implement HOTP algorithm, then use it to implement TOTP
    return 0


contents = decode(Image.open(sys.argv[1]))[0].data
print(contents)
