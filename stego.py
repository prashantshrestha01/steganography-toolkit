#!/usr/bin/env python3
"""Hide AES-encrypted messages inside PNG images using LSB steganography.

The payload is encrypted with Fernet (AES-128-CBC + HMAC) using a key
derived from a user password via PBKDF2-HMAC-SHA256, THEN embedded into
the least-significant bits of the image's RGB channels.

Frame layout embedded in the image (in order):
    MAGIC  (4 bytes, b"STG1")
    LEN    (4 bytes, big-endian uint32: byte length of PAYLOAD)
    PAYLOAD = SALT (16 bytes) || Fernet token (bytes)

A pre-flight capacity check runs before embedding: if the frame does not
fit in the image's available LSBs, encoding is refused with a clear error.
Decoding with the wrong password fails cleanly (Fernet authentication),
never with garbage output.
"""

import argparse
import base64
import getpass
import os
import struct
import sys

from PIL import Image
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"STG1"
SALT_LEN = 16
HEADER_LEN = len(MAGIC) + 4  # magic + uint32 length prefix
PBKDF2_ITERATIONS = 480_000


class StegoError(Exception):
    """Any clean, user-facing failure."""


class CapacityError(StegoError):
    """Payload does not fit in the carrier image."""


# --------------------------------------------------------------------------
# Crypto
# --------------------------------------------------------------------------

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet key from a password + salt via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_payload(message: bytes, password: str) -> bytes:
    """Encrypt message; returns SALT || Fernet-token bytes."""
    salt = os.urandom(SALT_LEN)
    token = Fernet(derive_key(password, salt)).encrypt(message)
    return salt + token


def decrypt_payload(payload: bytes, password: str) -> bytes:
    """Reverse encrypt_payload. Wrong password -> StegoError, not garbage."""
    if len(payload) <= SALT_LEN:
        raise StegoError("embedded payload is truncated or corrupt")
    salt, token = payload[:SALT_LEN], payload[SALT_LEN:]
    try:
        return Fernet(derive_key(password, salt)).decrypt(token)
    except InvalidToken:
        raise StegoError(
            "decryption failed: wrong password or corrupted image"
        ) from None


# --------------------------------------------------------------------------
# LSB embedding
# --------------------------------------------------------------------------

def capacity_bytes(img: Image.Image) -> int:
    """How many bytes fit in this image (1 bit per RGB channel value)."""
    w, h = img.size
    return (w * h * 3) // 8


def _embed_bytes(img: Image.Image, data: bytes) -> Image.Image:
    flat = bytearray(img.convert("RGB").tobytes())
    if len(data) * 8 > len(flat):
        raise CapacityError(
            f"payload needs {len(data)} bytes but this image only holds "
            f"{len(flat) // 8} bytes"
        )
    idx = 0
    for byte in data:
        for shift in range(7, -1, -1):
            flat[idx] = (flat[idx] & 0xFE) | ((byte >> shift) & 1)
            idx += 1
    return Image.frombytes("RGB", img.size, bytes(flat))


def _extract_bytes(img: Image.Image, n: int) -> bytes:
    flat = img.convert("RGB").tobytes()
    if n * 8 > len(flat):
        raise StegoError("declared payload length exceeds image capacity")
    out = bytearray()
    for i in range(n):
        byte = 0
        base = i * 8
        for j in range(8):
            byte = (byte << 1) | (flat[base + j] & 1)
        out.append(byte)
    return bytes(out)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def encode_image(input_path: str, output_path: str, message: bytes,
                 password: str) -> int:
    """Encrypt message and embed it into a copy of input_path.

    Returns the framed payload size in bytes. Raises CapacityError before
    touching the output file if the message does not fit.
    """
    img = Image.open(input_path)
    payload = encrypt_payload(message, password)
    frame = MAGIC + struct.pack(">I", len(payload)) + payload

    cap = capacity_bytes(img)
    if len(frame) > cap:
        raise CapacityError(
            f"payload is {len(frame)} bytes framed, but "
            f"{os.path.basename(input_path)} only holds {cap} bytes "
            f"({img.size[0]}x{img.size[1]} PNG). "
            "Use a larger image or a shorter message."
        )

    out = _embed_bytes(img, frame)
    out.save(output_path, format="PNG")
    return len(frame)


def decode_image(input_path: str, password: str) -> bytes:
    """Extract and decrypt the message hidden in input_path."""
    img = Image.open(input_path)
    if capacity_bytes(img) < HEADER_LEN:
        raise StegoError("image is too small to contain a hidden payload")
    header = _extract_bytes(img, HEADER_LEN)
    if header[:len(MAGIC)] != MAGIC:
        raise StegoError("no hidden payload found (magic header missing)")
    (length,) = struct.unpack(">I", header[len(MAGIC):HEADER_LEN])
    if length == 0 or HEADER_LEN + length > capacity_bytes(img):
        raise StegoError("embedded payload length is invalid or corrupt")
    payload = _extract_bytes(img, HEADER_LEN + length)[HEADER_LEN:]
    return decrypt_payload(payload, password)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _password(args) -> str:
    pw = args.password or os.environ.get("STEGO_PASSWORD")
    if not pw:
        pw = getpass.getpass("Password: ")
    if not pw:
        raise StegoError("empty password")
    return pw


def cmd_encode(args) -> int:
    if args.message is not None:
        message = args.message.encode("utf-8")
    elif args.message_file:
        with open(args.message_file, "rb") as fh:
            message = fh.read()
    else:
        raise StegoError("provide --message or --message-file")
    used = encode_image(args.input, args.output, message, _password(args))
    print(f"embedded {used} framed bytes into {args.output}")
    return 0


def cmd_decode(args) -> int:
    message = decode_image(args.input, _password(args))
    if args.output:
        with open(args.output, "wb") as fh:
            fh.write(message)
        print(f"wrote {len(message)} bytes to {args.output}")
    else:
        sys.stdout.write(message.decode("utf-8", errors="replace") + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stego",
        description="Hide AES-encrypted messages in PNG images (LSB steganography).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encode", help="encrypt a message and hide it in a PNG")
    enc.add_argument("-i", "--input", required=True, help="carrier PNG")
    enc.add_argument("-o", "--output", required=True, help="output PNG")
    enc.add_argument("-m", "--message", help="message text")
    enc.add_argument("--message-file", help="file whose contents are the message")
    enc.add_argument("-p", "--password",
                     help="password (or set STEGO_PASSWORD; prompt otherwise)")
    enc.set_defaults(func=cmd_encode)

    dec = sub.add_parser("decode", help="extract and decrypt a hidden message")
    dec.add_argument("-i", "--input", required=True, help="PNG with hidden payload")
    dec.add_argument("-o", "--output", help="write message to file instead of stdout")
    dec.add_argument("-p", "--password",
                     help="password (or set STEGO_PASSWORD; prompt otherwise)")
    dec.set_defaults(func=cmd_decode)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except StegoError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
