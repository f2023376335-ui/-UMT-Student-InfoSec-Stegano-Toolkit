"""
Cryptanalysis Tools
- Letter frequency analysis
- Index of Coincidence (IC)
- Kasiski test length estimator
- Chi-squared test for steganalysis
- Detectability scoring
"""
import string
from collections import Counter
import numpy as np

# English letter frequencies (%)
ENGLISH_FREQ = {
    'A': 8.17, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.70,
    'F': 2.23, 'G': 2.02, 'H': 6.09, 'I': 6.97, 'J': 0.15,
    'K': 0.77, 'L': 4.03, 'M': 2.41, 'N': 6.75, 'O': 7.51,
    'P': 1.93, 'Q': 0.10, 'R': 5.99, 'S': 6.33, 'T': 9.06,
    'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15, 'Y': 1.97,
    'Z': 0.07
}


def letter_frequency(text: str) -> dict:
    """Return letter frequency counts and percentages."""
    text = text.upper()
    counts = Counter(c for c in text if c.isalpha())
    total = sum(counts.values()) or 1
    freq = {}
    for letter in string.ascii_uppercase:
        cnt = counts.get(letter, 0)
        freq[letter] = {
            "count": cnt,
            "percent": round(cnt / total * 100, 2),
            "expected": ENGLISH_FREQ[letter]
        }
    return freq


def index_of_coincidence(text: str) -> float:
    """
    IC ≈ 0.065 for English, ≈ 0.038 for random (encrypted).
    Useful for identifying substitution ciphers.
    """
    text = ''.join(c for c in text.upper() if c.isalpha())
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    numerator = sum(f * (f - 1) for f in counts.values())
    return numerator / (n * (n - 1))


def chi_squared_english(text: str) -> float:
    """
    Chi-squared statistic vs expected English frequencies.
    Lower = more English-like (not encrypted).
    """
    text = ''.join(c for c in text.upper() if c.isalpha())
    n = len(text)
    if n == 0:
        return 0.0
    counts = Counter(text)
    chi2 = 0.0
    for letter in string.ascii_uppercase:
        observed = counts.get(letter, 0)
        expected = ENGLISH_FREQ[letter] / 100 * n
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected
    return round(chi2, 2)


def kasiski_key_length(ciphertext: str, trigram_count: int = 10) -> list:
    """
    Estimate Vigenère key length using Kasiski test.
    Returns list of candidate key lengths sorted by likelihood.
    """
    text = ''.join(c for c in ciphertext.upper() if c.isalpha())
    distances = []
    for i in range(len(text) - 3):
        trigram = text[i:i+3]
        for j in range(i+3, len(text) - 2):
            if text[j:j+3] == trigram:
                distances.append(j - i)

    if not distances:
        return []

    from math import gcd
    from functools import reduce

    def count_factors(n):
        factors = []
        for d in range(2, min(n+1, 20)):
            if n % d == 0:
                factors.append(d)
        return factors

    factor_counts = Counter()
    for d in distances:
        factor_counts.update(count_factors(d))

    return [k for k, _ in factor_counts.most_common(5)]


def analyze_cipher(plaintext: str, ciphertext: str) -> dict:
    """Side-by-side analysis of plaintext vs ciphertext."""
    return {
        "plaintext": {
            "text": plaintext,
            "frequencies": letter_frequency(plaintext),
            "ic": round(index_of_coincidence(plaintext), 4),
            "chi2": chi_squared_english(plaintext),
            "length": len([c for c in plaintext if c.isalpha()])
        },
        "ciphertext": {
            "text": ciphertext,
            "frequencies": letter_frequency(ciphertext),
            "ic": round(index_of_coincidence(ciphertext), 4),
            "chi2": chi_squared_english(ciphertext),
            "length": len([c for c in ciphertext if c.isalpha()])
        },
        "kasiski_lengths": kasiski_key_length(ciphertext)
    }


def image_chi_squared(image_array: np.ndarray) -> float:
    """
    Chi-squared steganalysis on LSB pairs.
    High value suggests LSB steganography is present.
    """
    flat = image_array.flatten().astype(int)
    pairs = Counter()
    for p in flat:
        pairs[p | 1] += 1  # Group pixels with same upper bits

    chi2 = 0.0
    for val in range(0, 256, 2):
        n1 = pairs.get(val, 0)
        n2 = pairs.get(val + 1, 0)
        total = n1 + n2
        if total > 0:
            expected = total / 2
            chi2 += (n1 - expected) ** 2 / expected + (n2 - expected) ** 2 / expected
    return round(chi2, 2)


def lsb_detectability(original_array: np.ndarray, stego_array: np.ndarray) -> dict:
    """Comprehensive detectability report for LSB steganography."""
    chi_orig = image_chi_squared(original_array)
    chi_stego = image_chi_squared(stego_array)

    mse = float(np.mean((original_array.astype(float) - stego_array.astype(float)) ** 2))
    psnr = 20 * np.log10(255.0 / np.sqrt(mse)) if mse > 0 else float('inf')

    lsb_orig = np.array(original_array & 1, dtype=float)
    lsb_stego = np.array(stego_array & 1, dtype=float)
    lsb_diff_rate = float(np.mean(lsb_orig != lsb_stego))

    return {
        "psnr_db": round(psnr, 2),
        "mse": round(mse, 4),
        "chi2_original": chi_orig,
        "chi2_stego": chi_stego,
        "lsb_change_rate": round(lsb_diff_rate * 100, 2),
        "verdict": "Likely detectable by chi-squared" if chi_stego > chi_orig * 1.5 else "Low detection risk"
    }
