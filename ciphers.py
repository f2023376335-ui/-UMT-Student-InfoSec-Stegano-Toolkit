"""
Classical Cipher Implementations
Vigenere, Playfair, Hill ciphers with encrypt/decrypt support
"""
import numpy as np
import string


# ─────────────────────────────── VIGENÈRE ────────────────────────────────────

def vigenere_encrypt(plaintext: str, key: str) -> str:
    key = key.upper().replace(" ", "")
    result = []
    ki = 0
    for ch in plaintext.upper():
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
            ki += 1
        else:
            result.append(ch)
    return "".join(result)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    key = key.upper().replace(" ", "")
    result = []
    ki = 0
    for ch in ciphertext.upper():
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            result.append(chr((ord(ch) - ord('A') - shift) % 26 + ord('A')))
            ki += 1
        else:
            result.append(ch)
    return "".join(result)


# ─────────────────────────────── PLAYFAIR ────────────────────────────────────

def _build_playfair_table(key: str):
    """Build 5×5 Playfair key table (J merged with I)."""
    key = key.upper().replace("J", "I").replace(" ", "")
    seen = []
    for ch in key + string.ascii_uppercase.replace("J", ""):
        if ch not in seen:
            seen.append(ch)
    return [seen[i:i+5] for i in range(0, 25, 5)]


def _find_pos(table, ch):
    for r, row in enumerate(table):
        for c, cell in enumerate(row):
            if cell == ch:
                return r, c
    raise ValueError(f"Character {ch!r} not in table")


def _prepare_playfair(text: str):
    text = text.upper().replace("J", "I").replace(" ", "")
    digrams = []
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 >= len(text):
            digrams.append((a, 'X'))
            i += 1
        elif text[i] == text[i+1]:
            digrams.append((a, 'X'))
            i += 1
        else:
            digrams.append((a, text[i+1]))
            i += 2
    return digrams


def playfair_encrypt(plaintext: str, key: str) -> str:
    table = _build_playfair_table(key)
    digrams = _prepare_playfair(plaintext)
    result = []
    for a, b in digrams:
        ra, ca = _find_pos(table, a)
        rb, cb = _find_pos(table, b)
        if ra == rb:
            result += [table[ra][(ca+1)%5], table[rb][(cb+1)%5]]
        elif ca == cb:
            result += [table[(ra+1)%5][ca], table[(rb+1)%5][cb]]
        else:
            result += [table[ra][cb], table[rb][ca]]
    return "".join(result)


def playfair_decrypt(ciphertext: str, key: str) -> str:
    table = _build_playfair_table(key)
    digrams = [(ciphertext[i], ciphertext[i+1]) for i in range(0, len(ciphertext), 2)]
    result = []
    for a, b in digrams:
        ra, ca = _find_pos(table, a)
        rb, cb = _find_pos(table, b)
        if ra == rb:
            result += [table[ra][(ca-1)%5], table[rb][(cb-1)%5]]
        elif ca == cb:
            result += [table[(ra-1)%5][ca], table[(rb-1)%5][cb]]
        else:
            result += [table[ra][cb], table[rb][ca]]
    return "".join(result)


# ──────────────────────────────── HILL ───────────────────────────────────────

def _mod_inverse_matrix(matrix, mod=26):
    """Compute modular inverse of a matrix (2×2 or 3×3)."""
    det = int(round(np.linalg.det(matrix))) % mod
    # Extended Euclidean for det inverse
    for i in range(mod):
        if (det * i) % mod == 1:
            det_inv = i
            break
    else:
        raise ValueError("Matrix is not invertible mod 26")
    n = matrix.shape[0]
    adj = np.zeros_like(matrix)
    for r in range(n):
        for c in range(n):
            minor = np.delete(np.delete(matrix, r, axis=0), c, axis=1)
            adj[c][r] = ((-1)**(r+c)) * int(round(np.linalg.det(minor)))
    return (det_inv * adj % mod).astype(int)


def hill_encrypt(plaintext: str, key_matrix: np.ndarray) -> str:
    n = key_matrix.shape[0]
    text = plaintext.upper().replace(" ", "")
    # Pad to multiple of n
    while len(text) % n != 0:
        text += 'X'
    nums = [ord(c) - ord('A') for c in text if c.isalpha()]
    result = []
    for i in range(0, len(nums), n):
        vec = np.array(nums[i:i+n])
        enc = (key_matrix @ vec) % 26
        result.extend([chr(int(v) + ord('A')) for v in enc])
    return "".join(result)


def hill_decrypt(ciphertext: str, key_matrix: np.ndarray) -> str:
    inv_key = _mod_inverse_matrix(key_matrix)
    return hill_encrypt(ciphertext, inv_key)


# ──────────────────────────────── DEFAULT HILL KEY ───────────────────────────

DEFAULT_HILL_KEY = np.array([[6, 24, 1],
                              [13, 16, 10],
                              [20, 17, 15]])
