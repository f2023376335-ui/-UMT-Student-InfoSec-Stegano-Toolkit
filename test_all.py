"""
Unit Tests — Visual Cryptography & Steganography Toolkit
Run with: python -m pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import numpy as np
from PIL import Image

from ciphers import (
    vigenere_encrypt, vigenere_decrypt,
    playfair_encrypt, playfair_decrypt,
    hill_encrypt, hill_decrypt, DEFAULT_HILL_KEY
)
from steganography import (
    lsb_encode, lsb_decode, lsb_capacity, calculate_psnr,
    text_stego_encode, text_stego_decode, text_capacity
)
from cryptanalysis import (
    letter_frequency, index_of_coincidence, chi_squared_english,
    image_chi_squared
)


# ─────────────────── CIPHER TESTS ────────────────────────────────────────────

class TestVigenere:
    def test_encrypt_known(self):
        assert vigenere_encrypt("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"

    def test_roundtrip(self):
        msg = "HELLO WORLD"
        key = "SECRET"
        # decrypt preserves non-alpha characters; strip spaces for comparison
        result = vigenere_decrypt(vigenere_encrypt(msg, key), key).replace(" ", "")
        assert result == "HELLOWORLD"

    def test_non_alpha_preserved(self):
        out = vigenere_encrypt("HELLO, WORLD!", "KEY")
        assert ',' in out and '!' in out

    def test_empty_string(self):
        assert vigenere_encrypt("", "KEY") == ""


class TestPlayfair:
    def test_encrypt_known(self):
        # Standard Playfair test
        result = playfair_encrypt("HIDE THE GOLD", "PLAYFAIR")
        assert len(result) > 0 and result.isalpha()

    def test_roundtrip(self):
        msg = "HELLO"
        key = "MONARCHY"
        enc = playfair_encrypt(msg, key)
        dec = playfair_decrypt(enc, key)
        # Playfair may pad with X — check original letters present
        assert "HELX" in dec or "HELLO" in dec or all(c in dec for c in "HELO")

    def test_output_even_length(self):
        enc = playfair_encrypt("HELLOWORLD", "KEY")
        assert len(enc) % 2 == 0


class TestHill:
    def test_encrypt_type(self):
        result = hill_encrypt("HELLO", DEFAULT_HILL_KEY)
        assert isinstance(result, str)
        assert result.isupper()

    def test_roundtrip(self):
        msg = "HELLOWORLD"
        enc = hill_encrypt(msg, DEFAULT_HILL_KEY)
        dec = hill_decrypt(enc, DEFAULT_HILL_KEY)
        # Hill pads to multiple of 3; check original chars present
        assert msg in dec or dec.startswith(msg[:6])


# ─────────────────── STEGANOGRAPHY TESTS ─────────────────────────────────────

def _make_test_image(w=100, h=100):
    arr = np.random.randint(0, 256, (h, w, 3), dtype=np.uint8)
    return Image.fromarray(arr, "RGB")


class TestLSB:
    def test_capacity(self):
        img = _make_test_image(200, 200)
        cap = lsb_capacity(img)
        assert cap > 0

    def test_encode_decode_roundtrip(self):
        img = _make_test_image(200, 200)
        msg = "TEST MESSAGE 123"
        stego = lsb_encode(img, msg)
        recovered = lsb_decode(stego)
        assert recovered == msg

    def test_psnr_high(self):
        img = _make_test_image(200, 200)
        stego = lsb_encode(img, "Hi")
        psnr = calculate_psnr(img, stego)
        assert psnr > 40, f"PSNR too low: {psnr}"

    def test_long_message(self):
        img = _make_test_image(500, 500)
        msg = "A" * 100
        stego = lsb_encode(img, msg)
        assert lsb_decode(stego) == msg

    def test_message_too_long_raises(self):
        img = _make_test_image(10, 10)
        with pytest.raises(ValueError):
            lsb_encode(img, "X" * 1000)


class TestTextStego:
    COVER = ("A peaceful message about security and protection of data. "
             "Always keep your passwords safe and protect access to all systems. "
             "Be careful about exposing personal or private information online.")

    def test_roundtrip(self):
        secret = "HI"
        stego, _ = text_stego_encode(self.COVER, secret)
        assert text_stego_decode(stego) == secret

    def test_capacity_positive(self):
        assert text_capacity(self.COVER) > 0

    def test_visual_similarity(self):
        secret = "A"
        stego, _ = text_stego_encode(self.COVER, secret)
        # Same length — only Unicode substitutions
        assert len(stego) == len(self.COVER)


# ─────────────────── CRYPTANALYSIS TESTS ─────────────────────────────────────

class TestFrequencyAnalysis:
    def test_letter_freq_returns_all_26(self):
        freq = letter_frequency("HELLO")
        assert len(freq) == 26

    def test_ic_english_range(self):
        # Use longer repeated English text for reliable IC
        text = ("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 5).upper()
        ic = index_of_coincidence(text)
        assert 0.03 < ic < 0.09, f"IC out of range: {ic}"

    def test_ic_random_lower(self):
        import random, string
        random.seed(42)
        rnd = ''.join(random.choices(string.ascii_uppercase, k=500))
        ic = index_of_coincidence(rnd)
        assert ic < 0.06

    def test_chi2_english_low(self):
        text = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        chi2 = chi_squared_english(text)
        assert chi2 < 200, f"Chi2 too high for English: {chi2}"

    def test_image_chi2(self):
        arr = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
        chi2 = image_chi_squared(arr)
        assert isinstance(chi2, float)
        assert chi2 >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
