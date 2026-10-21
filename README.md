# steganography-toolkit

Hide AES-encrypted messages inside PNG images using LSB steganography, from the command line.

## What it does

- Encrypts the message first, embeds second: the payload is encrypted with Fernet (AES-128-CBC + HMAC) under a key derived from your password via PBKDF2-HMAC-SHA256 (480k iterations, random 16-byte salt per message).
- Embeds the encrypted frame into the least-significant bits of the PNG's RGB channels. Frame format: `STG1` magic header + 4-byte big-endian length prefix + payload (salt || Fernet token).
- Pre-flight capacity check: encoding refuses oversized payloads up front with the exact byte counts, instead of failing halfway or truncating.
- Wrong password on decode = one clean error line. Fernet's HMAC verifies before anything is printed, so you never get garbage output.

## Quick start

```bash
pip install -r requirements.txt

# hide a message
python stego.py encode -i photo.png -o photo_secret.png \
    -m "meet at the usual place" -p "your password"

# get it back
python stego.py decode -i photo_secret.png -p "your password"

# longer payloads from a file
python stego.py encode -i photo.png -o out.png --message-file notes.txt
```

Password can also come from the `STEGO_PASSWORD` environment variable, or you'll be prompted (no echo).

## Tests

```bash
python -m pytest tests/ -v
```

Tests generate their own carrier images with Pillow (no binary samples in the repo) and cover: round-trip encode → decode, wrong-password refusal, capacity refusal on a too-small image, plain image with no payload, and the CLI end to end.

## Layout

```
stego.py            CLI + library (encode/decode subcommands, argparse)
requirements.txt    Pillow, cryptography, pytest
tests/test_stego.py
samples/            intentionally empty — tests generate images on the fly
```

## Design notes

Custom choices that shape this tool:

- **Encrypt-then-embed, always.** There is no plaintext mode. Anyone extracting the LSBs still faces AES + HMAC.
- **Magic header + length prefix** instead of scanning for a terminator: extraction knows exactly how many bytes to read, and a plain image is rejected immediately.
- **Salt travels with the payload** (first 16 bytes of the frame body), so the same password produces different ciphertext every encode and no separate key file is needed.
- **Capacity math is 1 bit per channel value**: a WxH RGB image holds `W*H*3/8` bytes. The framed payload (ciphertext + salt + 8 header bytes) must fit — Fernet adds ~57+ bytes of overhead, and the check accounts for all of it.
- Output is always PNG. Re-saving as JPEG would destroy the LSBs (lossy), so the tool neither reads nor writes JPEG for payloads.

## Limits

This hides data from casual view; it is not undetectable. Statistical steganalysis can flag LSB embedding, and anyone with the password + this tool extracts the message. Use it for learning and CTF-style work, not as a secrecy guarantee.

*Built by Prashant Shrestha · Mississauga, ON 🇨🇦 · [LinkedIn](https://www.linkedin.com/in/cto-prashant/)*
