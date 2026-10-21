"""Tests for stego.py — run with: python -m pytest tests/ -v

Tests generate their own carrier images with Pillow; no sample image
files are stored in the repo (PNGs are binary).
"""

import subprocess
import sys
from pathlib import Path

import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import stego  # noqa: E402

PASSWORD = "correct horse battery staple"


def make_carrier(path: Path, size=(240, 240)) -> Path:
    """Deterministic gradient image, big enough for test payloads."""
    img = Image.new("RGB", size)
    pixels = img.load()
    for y in range(size[1]):
        for x in range(size[0]):
            pixels[x, y] = (x % 256, y % 256, (x + y) % 256)
    img.save(path, format="PNG")
    return path


def test_round_trip(tmp_path):
    carrier = make_carrier(tmp_path / "carrier.png")
    out = tmp_path / "out.png"
    message = b"meet at the usual place, 19:00"
    stego.encode_image(str(carrier), str(out), message, PASSWORD)
    assert stego.decode_image(str(out), PASSWORD) == message


def test_wrong_password_fails_cleanly(tmp_path):
    carrier = make_carrier(tmp_path / "carrier.png")
    out = tmp_path / "out.png"
    stego.encode_image(str(carrier), str(out), b"secret", PASSWORD)
    with pytest.raises(stego.StegoError, match="wrong password"):
        stego.decode_image(str(out), "not the password")


def test_capacity_refusal(tmp_path):
    tiny = make_carrier(tmp_path / "tiny.png", size=(8, 8))  # holds 24 bytes
    out = tmp_path / "out.png"
    with pytest.raises(stego.CapacityError):
        stego.encode_image(str(tiny), str(out), b"x" * 500, PASSWORD)
    assert not out.exists()  # refused before writing anything


def test_plain_image_has_no_payload(tmp_path):
    carrier = make_carrier(tmp_path / "plain.png")
    with pytest.raises(stego.StegoError, match="magic header"):
        stego.decode_image(str(carrier), PASSWORD)


def test_cli_round_trip(tmp_path):
    carrier = make_carrier(tmp_path / "carrier.png")
    out = tmp_path / "out.png"
    enc = subprocess.run(
        [sys.executable, str(ROOT / "stego.py"), "encode",
         "-i", str(carrier), "-o", str(out),
         "-m", "hello from the cli", "-p", PASSWORD],
        capture_output=True, text=True,
    )
    assert enc.returncode == 0, enc.stderr
    dec = subprocess.run(
        [sys.executable, str(ROOT / "stego.py"), "decode",
         "-i", str(out), "-p", PASSWORD],
        capture_output=True, text=True,
    )
    assert dec.returncode == 0, dec.stderr
    assert "hello from the cli" in dec.stdout
    bad = subprocess.run(
        [sys.executable, str(ROOT / "stego.py"), "decode",
         "-i", str(out), "-p", "wrong"],
        capture_output=True, text=True,
    )
    assert bad.returncode == 2
    assert "wrong password" in bad.stderr
    assert "hello" not in bad.stdout  # no garbage output on failure
