# Networking & Protocol Security

Independent research into network protocol analysis, binary protocol implementation, and multi-layer enterprise authentication systems. Work covers packet forensics, password cracking, custom protocol engineering, DNS internals, and TOTP cryptography.

## Contents

| | |
|---|---|
| [`lab4.py`](Python-Socket-Lab/lab4.py) | TCP socket client implementing a custom binary protocol |
| [`get_client_cert.py`](Networking-Project/check-in-2/get_client_cert.py) | mTLS certificate enrollment via a custom length-value protocol over TLS |
| [`any_query.py`](Networking-Project/any_query.py) | DNS-over-TLS client with mTLS, built from raw RFC 1035 wire format |
| [`totp_code.py`](Networking-Project/totp_code.py) | TOTP code generator implementing HOTP/TOTP from scratch |

---

## Lab 4 — TCP Socket Programming

A Python client that connects to a server over raw TCP, parses a binary protocol, and answers a variable number of arithmetic challenges before extracting a secret phrase.

### Protocol

Two packet types, distinguished by a leading type byte:

```
Question:      Q | uint32 | uint32      (9 bytes)
Secret phrase: S | 8-byte phrase        (9 bytes)
```

The client unpacks the two integers, computes their sum, packs it as a big-endian `uint32`, and sends it back — looping until the server sends an `S` packet.

### The core challenge: TCP is a stream

A single `recv()` call is not guaranteed to return a complete packet. The client uses a `recv_exact(n)` helper that loops until exactly `n` bytes have been accumulated, a pattern that carries through every subsequent project:

```python
def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf
```

---

## Project 4 — Network Forensics & Enterprise Exploitation

End-to-end reconstruction of a corporate network breach through packet analysis, credential recovery, and exploitation of multiple authentication layers. The investigation follows the attacker's path through five progressive stages.

### Stage 0 — Packet Forensics

**Goal:** Identify the attacker's IP from a network capture of Evil Corp's infrastructure.

Wireshark's Endpoint statistics immediately surface `62.88.14.179` as anomalous — the only external IP conducting a real bidirectional session rather than routine TLS handshakes. That session is over **Telnet (port 23)** — an unencrypted legacy protocol — making the entire attacker session readable in plaintext.

Following the TCP stream reveals the attacker running as root and exfiltrating `/etc/shadow` (117 user accounts) before executing `cat /check-in-password`. The use of Telnet meant no encryption, no authentication challenge, and a complete audit trail visible to any network observer.

### Stage 1 — Credential Recovery

**Goal:** Crack a password from the shadow dump and find the admin panel.

The shadow file uses **SHA-512crypt** (`$6$`, 5000 rounds) — a memory-hard algorithm designed to be slow. Despite this, weak passwords remain recoverable via wordlist attack:

```bash
john --wordlist=rockyou.txt shadow.txt
# → mararmst:leanne
```

HTTP traffic in the pcap confirmed the admin panel at `admin.evil-corp.ink/login` and, critically, that it uses **plain HTTP** — credentials would be transmitted in the clear to anyone on the network path. Internal documentation discovered post-login described the remaining infrastructure.

### Stage 2 — MDM Certificate Enrollment

**Goal:** Obtain a client certificate from the MDM service to authenticate to deeper infrastructure.

The MDM service at `mdm.evil-corp.ink:443` uses a custom **length-value binary protocol** over TLS. Each field is prefixed by a 2-byte big-endian length:

```
[2B username_len][username][2B password_len][password][2B pubkey_len][pubkey_pem]
```

The response is the same structure, containing a PEM-encoded certificate chain on success. An Ed25519 keypair is generated locally; the public key is submitted with the cracked credentials; the returned certificate binds the identity `mararmst@evil-corp.ink` to that keypair for future authentication.

This is the **mTLS enrollment pattern** — converting ephemeral credentials into a long-lived, stateless certificate. The certificate contained a custom X.509 extension carrying out-of-band data, illustrating how arbitrary metadata can be embedded in the certificate structure.

### Stage 3 — Internal DNS Enumeration

**Goal:** Query Evil Corp's internal DNS resolver to map the network.

The resolver at `ns.evil-corp.ink:853` requires a valid client certificate (from Stage 2) to connect — **mutual TLS**. The DNS protocol itself was implemented from scratch per RFC 1035.

**DNS message structure:**
```
Header (12 bytes): ID | flags | QDCOUNT | ANCOUNT | NSCOUNT | ARCOUNT
Question: encoded_domain | QTYPE (ANY=255) | QCLASS (IN=1)
```

**Domain name encoding** uses length-prefixed labels terminated by `\x00`:
```
evil-corp.ink → \x08evil-corp\x03ink\x00
```

**DNS-over-TLS** requires a 2-byte length prefix on every message (TCP provides no framing). Response parsing handles **compression pointers** (top bits `0xC0` redirect to an earlier offset) and dispatches on record type.

ANY query results for `evil-corp.ink`:
```
evil-corp.ink.               A    143.215.130.109
admin.evil-corp.ink.         A    143.215.130.109
mfa-test.evil-corp.ink.      A    143.215.130.109   ← new target
mdm.evil-corp.ink.           A    143.215.130.109
ns.evil-corp.ink.            A    143.215.130.109
check-in-password.evil-corp.ink.  TXT  [redacted]
```

### Stage 4 — TOTP Bypass

**Goal:** Bypass MFA on the admin panel using a debug enrollment backdoor.

`mfa-test.evil-corp.ink` is an internal tool that issues TOTP QR codes for any user — a debugging backdoor left in production. The QR code encodes an `otpauth://` URI with a base32 secret, period, and digit count.

**TOTP implementation** (RFC 6238 over RFC 4226):

```python
# Counter derived from current time
t = int(time.time()) // period

# HOTP: HMAC-SHA1 keyed on secret, message is counter as 8-byte big-endian
mac = hmac.new(secret, struct.pack(">Q", t), hashlib.sha1).digest()

# Truncate to human-readable code
offset = mac[-1] & 0x0F
n = struct.unpack(">I", mac[offset:offset+4])[0] & 0x7FFFFFFF
code = str(n % 10**digits).zfill(digits)
```

The time-based counter means both parties independently derive the same value without stored state, as long as clocks are synchronized. Submitting the code granted access to the admin panel — which had already been defaced by the attackers.

### Full Attack Chain

```
Telnet (plaintext) → /etc/shadow exfiltrated
  └─ Wordlist attack → mararmst:leanne
       └─ MDM enrollment → client certificate (Ed25519)
            └─ DoT + mTLS → internal DNS enumerated
                 └─ mfa-test backdoor → TOTP enrolled
                      └─ Admin panel accessed (already defaced)
```

### Security Findings

| Finding | Root Cause |
|---|---|
| Full session visible to attacker | Telnet in production — no transport encryption |
| 117 password hashes exfiltrated | Root access with no detection or egress filtering |
| Password cracked from dump | Weak underlying password despite slow hash algorithm |
| Admin panel credentials in plaintext | HTTP instead of HTTPS for login endpoint |
| Client cert issued to attacker | No second factor on MDM credential check |
| Internal network fully mapped | DNS resolver accessible to any cert holder |
| MFA bypassed | Debug enrollment tool left in production |

---

## Technical Stack

Python standard library throughout — `socket`, `ssl`, `struct`, `hmac`, `hashlib`, `subprocess`. No third-party networking or cryptography libraries used. DNS, TOTP, and the MDM binary protocol all implemented from wire-level specifications.
