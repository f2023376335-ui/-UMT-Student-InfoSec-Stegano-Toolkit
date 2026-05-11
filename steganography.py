"""
Steganography Implementations
1. LSB (Least Significant Bit) — images
2. DCT-coefficient-based hints for JPEG steganography
3. Text steganography via Unicode homoglyphs
"""
from PIL import Image
import numpy as np
import io
import base64


# ─────────────────────────────── LSB STEGO ───────────────────────────────────

DELIMITER = "$$END$$"


def lsb_encode(image: Image.Image, message: str) -> Image.Image:
    """Hide a UTF-8 message in the LSB of R channel pixels."""
    img = image.convert("RGB")
    arr = np.array(img, dtype=np.uint8)

    full_msg = message + DELIMITER
    bits = ''.join(f'{b:08b}' for b in full_msg.encode('utf-8'))

    flat = arr.flatten()
    if len(bits) > len(flat):
        raise ValueError(f"Image too small: needs {len(bits)} pixels, has {len(flat)}")

    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | int(bit)

    result = flat.reshape(arr.shape)
    return Image.fromarray(result.astype(np.uint8))


def lsb_decode(image: Image.Image) -> str:
    """Extract LSB-hidden message from image."""
    arr = np.array(image.convert("RGB"))
    flat = arr.flatten()
    bits = ''.join(str(p & 1) for p in flat)

    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = bits[i:i+8]
        chars.append(chr(int(byte, 2)))
        joined = ''.join(chars)
        if joined.endswith(DELIMITER):
            return joined[:-len(DELIMITER)]
    return ''.join(chars)


def lsb_capacity(image: Image.Image) -> int:
    """Return max characters storable in image."""
    arr = np.array(image.convert("RGB"))
    return (arr.size - len(DELIMITER) * 8) // 8


def calculate_psnr(original: Image.Image, stego: Image.Image) -> float:
    """Peak Signal-to-Noise Ratio (higher = less detectable)."""
    a = np.array(original.convert("RGB"), dtype=float)
    b = np.array(stego.convert("RGB"), dtype=float)
    mse = np.mean((a - b) ** 2)
    if mse == 0:
        return float('inf')
    return 20 * np.log10(255.0 / np.sqrt(mse))


def detectability_score(psnr: float) -> dict:
    """Convert PSNR to a human-readable detectability score."""
    if psnr == float('inf'):
        level, label, color = 0, "No change", "green"
    elif psnr >= 45:
        level, label, color = 1, "Imperceptible (safe)", "green"
    elif psnr >= 35:
        level, label, color = 2, "Low detectability", "lightgreen"
    elif psnr >= 25:
        level, label, color = 3, "Moderate detectability", "orange"
    else:
        level, label, color = 4, "Highly detectable", "red"
    return {"psnr": round(psnr, 2), "level": level, "label": label, "color": color}


# ─────────────────────────── DCT-BASED STEGO ──────────────────────────────────

def dct_encode_demo(image: Image.Image, message: str) -> tuple[Image.Image, dict]:
    """
    Simplified DCT steganography demonstration.
    Encodes message bits into the sign of DCT coefficients in 8x8 blocks.
    Returns the stego image and metadata.
    """
    img = image.convert("L")  # grayscale
    arr = np.array(img, dtype=float)

    h, w = arr.shape
    # Pad to multiple of 8
    ph = (8 - h % 8) % 8
    pw = (8 - w % 8) % 8
    arr = np.pad(arr, ((0, ph), (0, pw)), mode='edge')
    H, W = arr.shape

    msg_bits = ''.join(f'{b:08b}' for b in (message + DELIMITER).encode('utf-8'))
    bit_idx = 0
    stego = arr.copy()
    blocks_used = 0

    for row in range(0, H, 8):
        for col in range(0, W, 8):
            if bit_idx >= len(msg_bits):
                break
            block = arr[row:row+8, col:col+8]
            dct_block = _dct2(block)
            # Encode into coefficient [4,4] (mid-frequency)
            coef = dct_block[4][4]
            bit = int(msg_bits[bit_idx])
            if bit == 1:
                dct_block[4][4] = abs(coef) if coef != 0 else 1.0
            else:
                dct_block[4][4] = -abs(coef) if coef != 0 else -1.0
            stego[row:row+8, col:col+8] = _idct2(dct_block)
            bit_idx += 1
            blocks_used += 1

    stego = np.clip(stego[:h, :w], 0, 255).astype(np.uint8)
    result_img = Image.fromarray(stego).convert("RGB")

    metadata = {
        "bits_encoded": bit_idx,
        "blocks_used": blocks_used,
        "total_blocks": (H // 8) * (W // 8),
        "algorithm": "DCT mid-frequency coefficient sign modulation"
    }
    return result_img, metadata


def dct_decode_demo(image: Image.Image) -> str:
    """Decode DCT-hidden message."""
    arr = np.array(image.convert("L"), dtype=float)
    H, W = arr.shape
    ph = (8 - H % 8) % 8
    pw = (8 - W % 8) % 8
    arr = np.pad(arr, ((0, ph), (0, pw)), mode='edge')
    AH, AW = arr.shape

    bits = []
    for row in range(0, AH, 8):
        for col in range(0, AW, 8):
            block = arr[row:row+8, col:col+8]
            dct_block = _dct2(block)
            coef = dct_block[4][4]
            bits.append('1' if coef >= 0 else '0')

    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = ''.join(bits[i:i+8])
        try:
            chars.append(chr(int(byte, 2)))
            if ''.join(chars).endswith(DELIMITER):
                return ''.join(chars)[:-len(DELIMITER)]
        except Exception:
            pass
    return ''.join(chars)


def _dct2(block):
    """2D DCT using separable 1D DCTs."""
    from scipy.fft import dct
    return dct(dct(block.T, norm='ortho').T, norm='ortho')


def _idct2(block):
    """2D IDCT."""
    from scipy.fft import idct
    return idct(idct(block.T, norm='ortho').T, norm='ortho')


# ─────────────────────────── TEXT STEGANOGRAPHY ──────────────────────────────

# Unicode homoglyph map: Latin → visually-similar Unicode
HOMOGLYPHS = {
    'a': '\u0430',  # Cyrillic а
    'c': '\u0441',  # Cyrillic с
    'e': '\u0435',  # Cyrillic е
    'o': '\u043e',  # Cyrillic о
    'p': '\u0440',  # Cyrillic р
    'x': '\u0445',  # Cyrillic х
    'A': '\u0391',  # Greek Alpha
    'B': '\u0392',  # Greek Beta
    'E': '\u0395',  # Greek Epsilon
    'H': '\u0397',  # Greek Eta
}
REVERSE_HOMOGLYPHS = {v: k for k, v in HOMOGLYPHS.items()}
AVAILABLE_CHARS = list(HOMOGLYPHS.keys())


def text_stego_encode(cover_text: str, secret: str) -> str:
    """
    Hide a binary secret in cover text by substituting letters with homoglyphs.
    1 = homoglyph substitution, 0 = keep original Latin.
    """
    secret_bits = ''.join(f'{b:08b}' for b in secret.encode('utf-8')) + '0' * 8  # null terminator
    result = list(cover_text)
    bit_idx = 0

    for i, ch in enumerate(cover_text):
        if bit_idx >= len(secret_bits):
            break
        if ch in HOMOGLYPHS:
            if secret_bits[bit_idx] == '1':
                result[i] = HOMOGLYPHS[ch]
            bit_idx += 1

    capacity_used = bit_idx
    return ''.join(result), capacity_used


def text_stego_decode(stego_text: str) -> str:
    """Extract hidden bits from homoglyph-substituted text and decode."""
    bits = []
    for ch in stego_text:
        if ch in REVERSE_HOMOGLYPHS:
            bits.append('1')
        elif ch in HOMOGLYPHS:
            bits.append('0')

    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = ''.join(bits[i:i+8])
        val = int(byte, 2)
        if val == 0:
            break
        chars.append(chr(val))
    return ''.join(chars)


def text_capacity(cover_text: str) -> int:
    """How many secret characters can be hidden in this cover text."""
    encodable = sum(1 for ch in cover_text if ch in HOMOGLYPHS)
    return encodable // 8
