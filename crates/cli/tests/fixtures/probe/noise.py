"""The keyward plugin protocol's channel, in the standard library alone.

Every message between the daemon and a plugin is sealed with Noise:
`Noise_NN_25519_ChaChaPoly_BLAKE2s`, prologue `keyward plugin v2`. The daemon
opens the handshake, the plugin answers; then each message travels as a sealed
header (its length, four bytes big-endian) followed by sealed chunks of at most
65519 bytes, every piece in a frame of its own: two bytes of length,
big-endian, then the Noise message.

X25519 (RFC 7748) and ChaCha20-Poly1305 (RFC 8439) are written out here because
Python's standard library has neither; BLAKE2s comes from `hashlib`. This is a
reference for plugin authors and it is slow — fine for a plugin's messages, not
for bulk data. A plugin in Rust uses `keyward-plugin-stdio` instead.
"""

import hashlib
import hmac
import os
import struct

PROTOCOL_NAME = b"Noise_NN_25519_ChaChaPoly_BLAKE2s"
PROLOGUE = b"keyward plugin v2"
MAX_NOISE = 65535
TAG = 16
CHUNK = MAX_NOISE - TAG
MAX_MESSAGE = 4 * 1024 * 1024


# --- X25519 (RFC 7748) -------------------------------------------------------

_P = 2**255 - 19
_A24 = 121665


def _decode_scalar(k):
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def x25519(k, u):
    scalar = _decode_scalar(k)
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        bit = (scalar >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % _P, (x2 - z2) % _P
        aa, bb = a * a % _P, b * b % _P
        e = (aa - bb) % _P
        c, d = (x3 + z3) % _P, (x3 - z3) % _P
        da, cb = d * a % _P, c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def _keypair():
    private = os.urandom(32)
    return private, x25519(private, (9).to_bytes(32, "little"))


# --- ChaCha20-Poly1305 (RFC 8439) ---------------------------------------------

def _rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 7)


def _chacha_block(key, counter, nonce):
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state += [counter] + list(struct.unpack("<3I", nonce))
    s = state[:]
    for _ in range(10):
        _quarter(s, 0, 4, 8, 12); _quarter(s, 1, 5, 9, 13); _quarter(s, 2, 6, 10, 14); _quarter(s, 3, 7, 11, 15)
        _quarter(s, 0, 5, 10, 15); _quarter(s, 1, 6, 11, 12); _quarter(s, 2, 7, 8, 13); _quarter(s, 3, 4, 9, 14)
    return struct.pack("<16I", *((s[i] + state[i]) & 0xFFFFFFFF for i in range(16)))


def _chacha(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        block = _chacha_block(key, counter + i // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[i:i + 64], block))
    return bytes(out)


def _poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p, acc = (1 << 130) - 5, 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = (acc + n) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b):
    return b"\x00" * (-len(b) % 16)


def _aead_tag(key, nonce, ad, ciphertext):
    otk = _chacha_block(key, 0, nonce)[:32]
    mac = ad + _pad16(ad) + ciphertext + _pad16(ciphertext) + struct.pack("<QQ", len(ad), len(ciphertext))
    return _poly1305(otk, mac)


def _nonce(n):
    return b"\x00\x00\x00\x00" + struct.pack("<Q", n)


def encrypt(key, n, ad, plaintext):
    nonce = _nonce(n)
    ciphertext = _chacha(key, 1, nonce, plaintext)
    return ciphertext + _aead_tag(key, nonce, ad, ciphertext)


def decrypt(key, n, ad, sealed):
    if len(sealed) < TAG:
        raise ValueError("a sealed piece shorter than its tag")
    nonce = _nonce(n)
    ciphertext, tag = sealed[:-TAG], sealed[-TAG:]
    if not hmac.compare_digest(_aead_tag(key, nonce, ad, ciphertext), tag):
        raise ValueError("a piece that does not open")
    return _chacha(key, 1, nonce, ciphertext)


# --- The Noise symmetric state ---------------------------------------------------

def _hash(data):
    return hashlib.blake2s(data).digest()


def _hmac(key, data):
    return hmac.new(key, data, hashlib.blake2s).digest()


def _hkdf(ck, ikm):
    temp = _hmac(ck, ikm)
    first = _hmac(temp, b"\x01")
    return first, _hmac(temp, first + b"\x02")


class _CipherState:
    def __init__(self, key=None):
        self.key, self.n = key, 0

    def encrypt(self, ad, plaintext):
        if self.key is None:
            return plaintext
        out = encrypt(self.key, self.n, ad, plaintext)
        self.n += 1
        return out

    def decrypt(self, ad, sealed):
        if self.key is None:
            return sealed
        out = decrypt(self.key, self.n, ad, sealed)
        self.n += 1
        return out


class _Handshake:
    def __init__(self):
        self.h = PROTOCOL_NAME.ljust(32, b"\x00") if len(PROTOCOL_NAME) <= 32 else _hash(PROTOCOL_NAME)
        self.ck = self.h
        self.cipher = _CipherState()
        self.mix_hash(PROLOGUE)

    def mix_hash(self, data):
        self.h = _hash(self.h + data)

    def mix_key(self, ikm):
        self.ck, key = _hkdf(self.ck, ikm)
        self.cipher = _CipherState(key)

    def encrypt_and_hash(self, plaintext):
        out = self.cipher.encrypt(self.h, plaintext)
        self.mix_hash(out)
        return out

    def decrypt_and_hash(self, sealed):
        out = self.cipher.decrypt(self.h, sealed)
        self.mix_hash(sealed)
        return out

    def split(self):
        first, second = _hkdf(self.ck, b"")
        return _CipherState(first), _CipherState(second)


# --- Frames and the channel ----------------------------------------------------

def _read_exact(stream, n):
    data = b""
    while len(data) < n:
        chunk = stream.read(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _read_frame(stream):
    head = _read_exact(stream, 2)
    if head is None:
        return None
    body = _read_exact(stream, struct.unpack(">H", head)[0])
    if body is None:
        raise EOFError("the pipe closed inside a frame")
    return body


def _write_frame(stream, frame):
    stream.write(struct.pack(">H", len(frame)) + frame)


class Channel:
    """An open channel over a plugin's `stdin` and `stdout` (their binary
    buffers)."""

    def __init__(self, reader, writer, receive, send):
        self._reader, self._writer = reader, writer
        self._receive, self._send = receive, send

    def send(self, message):
        header = self._send.encrypt(b"", struct.pack(">I", len(message)))
        _write_frame(self._writer, header)
        for i in range(0, len(message), CHUNK):
            _write_frame(self._writer, self._send.encrypt(b"", message[i:i + CHUNK]))
        self._writer.flush()

    def recv(self):
        """The next message, or `None` when the daemon closed the pipe."""
        frame = _read_frame(self._reader)
        if frame is None:
            return None
        header = self._receive.decrypt(b"", frame)
        if len(header) != 4:
            raise ValueError("a header that is not a length")
        total = struct.unpack(">I", header)[0]
        if total > MAX_MESSAGE:
            raise ValueError("a message over the limit")
        out = b""
        while len(out) < total:
            frame = _read_frame(self._reader)
            if frame is None:
                raise EOFError("the pipe closed inside a message")
            out += self._receive.decrypt(b"", frame)
        if len(out) != total:
            raise ValueError("a message longer than its header")
        return out


def respond(reader, writer):
    """The plugin's side of the handshake: the daemon speaks first."""
    hs = _Handshake()
    first = _read_frame(reader)
    if first is None or len(first) < 32:
        raise ValueError("no handshake from the daemon")
    remote_e = first[:32]
    hs.mix_hash(remote_e)
    if hs.decrypt_and_hash(first[32:]):
        raise ValueError("a handshake with a payload is another protocol")
    private, public = _keypair()
    hs.mix_hash(public)
    hs.mix_key(x25519(private, remote_e))
    reply = public + hs.encrypt_and_hash(b"")
    _write_frame(writer, reply)
    writer.flush()
    to_plugin, to_daemon = hs.split()
    return Channel(reader, writer, receive=to_plugin, send=to_daemon)
