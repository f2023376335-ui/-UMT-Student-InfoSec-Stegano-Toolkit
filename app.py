"""
Visual Cryptography & Steganography Toolkit
UMT AI Department — Information Security, Spring 2026
Category B, Tier B Project
"""
import streamlit as st
import numpy as np
from PIL import Image
import io
import base64
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
def _show_frequency_chart(analysis, pt, ct):
    import matplotlib.pyplot as plt
    import string

    letters = list(string.ascii_uppercase)
    pt_pct  = [analysis["plaintext"]["frequencies"][l]["percent"] for l in letters]
    ct_pct  = [analysis["ciphertext"]["frequencies"][l]["percent"] for l in letters]
    eng_pct = [analysis["plaintext"]["frequencies"][l]["expected"] for l in letters]

    fig, axes = plt.subplots(1, 2, figsize=(14, 4), facecolor="#0e1117")
    for ax, pct, title, color in [
        (axes[0], pt_pct,  "Plaintext Frequency",  "#4fc3f7"),
        (axes[1], ct_pct,  "Ciphertext Frequency", "#ef5350")
    ]:
        ax.set_facecolor("#1a1a2e")
        ax.bar(letters, pct, color=color, alpha=0.8, label="Observed")
        ax.plot(letters, eng_pct, "w--", linewidth=1, label="English baseline")
        ax.set_title(title, color="white")
        ax.tick_params(colors="white", labelsize=8)
        ax.spines[:].set_color("#444")
        ax.legend(facecolor="#1a1a2e", labelcolor="white", fontsize=8)

    plt.tight_layout()
    st.pyplot(fig)
    plt.close()


def _show_ic_table(analysis):
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Plaintext IC",   f"{analysis['plaintext']['ic']:.4f}",
                help="~0.065 = English, ~0.038 = random")
    col2.metric("Ciphertext IC",  f"{analysis['ciphertext']['ic']:.4f}")
    col3.metric("Plaintext χ²",   f"{analysis['plaintext']['chi2']}")
    col4.metric("Ciphertext χ²",  f"{analysis['ciphertext']['chi2']}")
    st.caption("IC close to 0.065 → monoalphabetic cipher · IC close to 0.038 → polyalphabetic/transposition")
from ciphers import (
    vigenere_encrypt, vigenere_decrypt,
    playfair_encrypt, playfair_decrypt,
    hill_encrypt, hill_decrypt, DEFAULT_HILL_KEY
)
from steganography import (
    lsb_encode, lsb_decode, lsb_capacity, calculate_psnr, detectability_score,
    dct_encode_demo, dct_decode_demo,
    text_stego_encode, text_stego_decode, text_capacity
)
from cryptanalysis import (
    letter_frequency, index_of_coincidence, chi_squared_english,
    analyze_cipher, lsb_detectability, image_chi_squared
)

# ── PAGE CONFIG ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CryptoStego Toolkit",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        padding: 20px; border-radius: 12px; text-align: center; margin-bottom: 20px;
    }
    .main-header h1 { color: #e94560; font-size: 2rem; margin: 0; }
    .main-header p  { color: #a8b2d8; margin: 4px 0 0; }
    .metric-card {
        background: #1a1a2e; border: 1px solid #e94560; border-radius: 8px;
        padding: 12px; text-align: center;
    }
    .success-box { background: #0d3b27; border-left: 4px solid #00d26a;
                   padding: 10px 14px; border-radius: 4px; }
    .warning-box { background: #3b2000; border-left: 4px solid #ffa500;
                   padding: 10px 14px; border-radius: 4px; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="main-header">
  <h1>🔐 Visual Cryptography & Steganography Toolkit</h1>
  <p>UMT AI Department · Information Security Spring 2026 · Category B Tier B</p>
</div>
""", unsafe_allow_html=True)

# ── SIDEBAR NAV ───────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("📚 Navigation")
    section = st.radio("Choose Module", [
        "🏠 Home",
        "🔑 Classical Ciphers",
        "🖼️ Image Steganography (LSB)",
        "🎛️ DCT Steganography",
        "📝 Text Steganography",
        "📊 Cryptanalysis"
    ])
    st.markdown("---")
    st.caption("Techniques implemented:\n"
               "• Vigenère · Playfair · Hill\n"
               "• LSB · DCT · Unicode Stego\n"
               "• Frequency Analysis · IC · χ²")

# ── HOME ─────────────────────────────────────────────────────────────────────
if section == "🏠 Home":
    c1, c2, c3 = st.columns(3)
    with c1:
        st.info("**3 Classical Ciphers**\nVigenère · Playfair · Hill")
    with c2:
        st.info("**3 Stego Techniques**\nLSB · DCT · Unicode Homoglyphs")
    with c3:
        st.info("**Cryptanalysis**\nFrequency · IC · Chi-squared")

    st.markdown("### 📖 What this toolkit covers")
    st.markdown("""
| Module | Technique | Description |
|---|---|---|
| Cipher | Vigenère | Polyalphabetic substitution — key-based shift |
| Cipher | Playfair | Digraph substitution using a 5×5 key square |
| Cipher | Hill | Matrix multiplication over modulo 26 |
| Stego | LSB | Hides bits in least significant pixel bits |
| Stego | DCT | Encodes in DCT mid-frequency coefficients (JPEG-style) |
| Stego | Unicode | Substitutes letters with homoglyphs to hide binary data |
| Analysis | Frequency | Letter count & % vs English baseline |
| Analysis | IC | Index of Coincidence to identify cipher type |
| Analysis | Chi-squared | Statistical detectability test |
""")

# ── CLASSICAL CIPHERS ─────────────────────────────────────────────────────────
elif section == "🔑 Classical Ciphers":
    st.header("🔑 Classical Ciphers")
    cipher_type = st.selectbox("Select Cipher", ["Vigenère", "Playfair", "Hill"])
    mode = st.radio("Mode", ["Encrypt", "Decrypt"], horizontal=True)

    plaintext = st.text_area("Input Text", value="HELLO WORLD", height=100)

    if cipher_type == "Vigenère":
        key = st.text_input("Key (alphabetic)", value="SECRET")
        if st.button("Run Vigenère", type="primary"):
            try:
                if mode == "Encrypt":
                    out = vigenere_encrypt(plaintext, key)
                else:
                    out = vigenere_decrypt(plaintext, key)

                col1, col2 = st.columns(2)
                col1.text_area("Input", plaintext, height=80)
                col2.text_area("Output", out, height=80)

                # Side-by-side analysis
                analysis = analyze_cipher(plaintext, out)
                st.subheader("📊 Side-by-Side Cryptanalysis")
                _show_frequency_chart(analysis, plaintext, out)
                _show_ic_table(analysis)
            except Exception as e:
                st.error(f"Error: {e}")

    elif cipher_type == "Playfair":
        key = st.text_input("Key (alphabetic)", value="MONARCHY")
        if st.button("Run Playfair", type="primary"):
            try:
                if mode == "Encrypt":
                    out = playfair_encrypt(plaintext, key)
                else:
                    out = playfair_decrypt(plaintext, key)

                col1, col2 = st.columns(2)
                col1.text_area("Input", plaintext, height=80)
                col2.text_area("Output", out, height=80)

                analysis = analyze_cipher(plaintext, out)
                st.subheader("📊 Side-by-Side Cryptanalysis")
                _show_frequency_chart(analysis, plaintext, out)
                _show_ic_table(analysis)
            except Exception as e:
                st.error(f"Error: {e}")

    elif cipher_type == "Hill":
        st.info("Using default 3×3 Hill key matrix:\n```\n[[6,24,1],[13,16,10],[20,17,15]]\n```")
        if st.button("Run Hill", type="primary"):
            try:
                if mode == "Encrypt":
                    out = hill_encrypt(plaintext, DEFAULT_HILL_KEY)
                else:
                    out = hill_decrypt(plaintext, DEFAULT_HILL_KEY)

                col1, col2 = st.columns(2)
                col1.text_area("Input", plaintext, height=80)
                col2.text_area("Output", out, height=80)

                analysis = analyze_cipher(plaintext, out)
                _show_frequency_chart(analysis, plaintext, out)
                _show_ic_table(analysis)
            except Exception as e:
                st.error(f"Error: {e}")


# ── LSB STEGANOGRAPHY ─────────────────────────────────────────────────────────
elif section == "🖼️ Image Steganography (LSB)":
    st.header("🖼️ LSB Image Steganography")
    tab1, tab2 = st.tabs(["🔒 Encode", "🔓 Decode"])

    with tab1:
        uploaded = st.file_uploader("Upload cover image (PNG/BMP recommended)", type=["png","bmp","jpg"])
        message = st.text_area("Secret message to hide", value="This is a secret message!", height=80)

        if uploaded:
            img = Image.open(uploaded)
            cap = lsb_capacity(img)
            st.caption(f"Image capacity: **{cap} characters** | Message length: **{len(message)}**")

            if len(message) > cap:
                st.error("Message too long for this image!")
            elif st.button("Encode Message", type="primary"):
                stego = lsb_encode(img, message)
                psnr = calculate_psnr(img, stego)
                score = detectability_score(psnr)

                col1, col2, col3 = st.columns([1, 1, 1])
                with col1:
                    st.image(img, caption="Original", use_column_width=True)
                with col2:
                    st.image(stego, caption="Stego Image", use_column_width=True)
                with col3:
                    st.metric("PSNR", f"{score['psnr']} dB")
                    st.markdown(f"**Detectability:** :{score['color']}[{score['label']}]")

                # Download
                buf = io.BytesIO()
                stego.save(buf, format="PNG")
                st.download_button("⬇️ Download Stego Image", buf.getvalue(),
                                   file_name="stego_output.png", mime="image/png")

                # Chi-squared analysis
                orig_arr = np.array(img.convert("RGB"))
                stego_arr = np.array(stego)
                det = lsb_detectability(orig_arr, stego_arr)
                st.subheader("📊 Detectability Report")
                d1, d2, d3 = st.columns(3)
                d1.metric("PSNR", f"{det['psnr_db']} dB")
                d2.metric("LSB Change Rate", f"{det['lsb_change_rate']}%")
                d3.metric("Chi² Stego", f"{det['chi2_stego']:.1f}")
                st.info(f"**Verdict:** {det['verdict']}")

    with tab2:
        uploaded2 = st.file_uploader("Upload stego image", type=["png","bmp","jpg"],
                                     key="decode_upload")
        if uploaded2:
            stego_img = Image.open(uploaded2)
            if st.button("Decode Message", type="primary"):
                try:
                    recovered = lsb_decode(stego_img)
                    st.success(f"**Recovered message:** {recovered}")
                except Exception as e:
                    st.error(f"Could not decode: {e}")


# ── DCT STEGANOGRAPHY ─────────────────────────────────────────────────────────
elif section == "🎛️ DCT Steganography":
    st.header("🎛️ DCT-Based Steganography")
    st.info("Encodes data into DCT mid-frequency coefficients (JPEG-style). "
            "More robust to compression than LSB.")

    tab1, tab2 = st.tabs(["🔒 Encode", "🔓 Decode"])

    with tab1:
        uploaded = st.file_uploader("Upload image", type=["png","bmp","jpg"],
                                    key="dct_enc")
        message = st.text_input("Secret message", value="DCT hidden data")

        if uploaded and st.button("DCT Encode", type="primary"):
            img = Image.open(uploaded)
            try:
                stego, meta = dct_encode_demo(img, message)
                col1, col2 = st.columns(2)
                col1.image(img, caption="Original")
                col2.image(stego, caption="DCT Stego")

                st.subheader("Encoding Metadata")
                m1, m2, m3 = st.columns(3)
                m1.metric("Bits Encoded", meta["bits_encoded"])
                m2.metric("Blocks Used", meta["blocks_used"])
                m3.metric("Total Blocks", meta["total_blocks"])
                st.caption(f"Algorithm: {meta['algorithm']}")

                buf = io.BytesIO()
                stego.save(buf, format="PNG")
                st.download_button("⬇️ Download DCT Stego", buf.getvalue(),
                                   "dct_stego.png", "image/png")
            except Exception as e:
                st.error(str(e))

    with tab2:
        uploaded2 = st.file_uploader("Upload DCT stego image", type=["png","bmp"],
                                     key="dct_dec")
        if uploaded2 and st.button("DCT Decode", type="primary"):
            img = Image.open(uploaded2)
            result = dct_decode_demo(img)
            if result:
                st.success(f"**Decoded:** {result[:200]}")
            else:
                st.warning("No decodable message found.")


# ── TEXT STEGANOGRAPHY ────────────────────────────────────────────────────────
elif section == "📝 Text Steganography":
    st.header("📝 Text Steganography — Unicode Homoglyphs")
    st.markdown("""
**How it works:** Certain Latin letters are replaced with visually identical Unicode 
characters (e.g., Cyrillic `а` instead of Latin `a`). The pattern of substituted 
vs original characters encodes binary data. Invisible to the naked eye!
    """)

    tab1, tab2 = st.tabs(["🔒 Encode", "🔓 Decode"])

    with tab1:
        cover = st.text_area("Cover text (must contain encodable letters: a,c,e,o,p,x,A,B,E,H)",
                             value="A peaceful message about security and protection of data. "
                                   "Always keep your passwords safe and protect access to systems.",
                             height=120)
        secret = st.text_input("Secret message to hide", value="SECURE")
        cap = text_capacity(cover)
        st.caption(f"Capacity: **{cap} characters** | Need: **{len(secret)}**")

        if st.button("Encode in Text", type="primary"):
            if len(secret) > cap:
                st.error("Secret too long for this cover text!")
            else:
                stego_text, bits_used = text_stego_encode(cover, secret)
                st.subheader("Stego Text (looks identical to original):")
                st.code(stego_text, language=None)
                st.success(f"Encoded {bits_used} bits. "
                           f"Text looks {'identical' if stego_text == cover else 'visually identical'} to original.")

                # Show what changed
                changes = [(i, c, stego_text[i]) for i, c in enumerate(cover)
                           if c != stego_text[i]]
                if changes:
                    st.caption(f"Characters substituted: {len(changes)} (invisible to reader)")

    with tab2:
        stego_in = st.text_area("Paste stego text here", height=120)
        if st.button("Decode Hidden Message", type="primary"):
            result = text_stego_decode(stego_in)
            if result:
                st.success(f"**Hidden message:** `{result}`")
            else:
                st.warning("No hidden message detected.")


# ── CRYPTANALYSIS ─────────────────────────────────────────────────────────────
elif section == "📊 Cryptanalysis":
    st.header("📊 Cryptanalysis Dashboard")
    ana_tab1, ana_tab2 = st.tabs(["Text Analysis", "Image Chi-squared"])

    with ana_tab1:
        col1, col2 = st.columns(2)
        with col1:
            pt = st.text_area("Plaintext / Sample A", value="HELLO WORLD THIS IS ENGLISH TEXT", height=100)
        with col2:
            ct = st.text_area("Ciphertext / Sample B",
                              value=vigenere_encrypt("HELLO WORLD THIS IS ENGLISH TEXT", "KEY"),
                              height=100)

        if st.button("Analyse Both Texts", type="primary"):
            analysis = analyze_cipher(pt, ct)
            _show_frequency_chart(analysis, pt, ct)
            _show_ic_table(analysis)

            st.subheader("Kasiski Key Length Estimate")
            kl = analysis.get("kasiski_lengths", [])
            if kl:
                st.write(f"Probable Vigenère key lengths: **{kl}**")
            else:
                st.write("Not enough repeated trigrams for Kasiski analysis.")

    with ana_tab2:
        img_up = st.file_uploader("Upload image for chi-squared steganalysis",
                                  type=["png","bmp","jpg"])
        if img_up:
            img = Image.open(img_up)
            arr = np.array(img.convert("RGB"))
            chi2 = image_chi_squared(arr)
            st.metric("Chi-squared statistic", f"{chi2:.2f}")
            if chi2 > 100:
                st.warning("⚠️ High chi-squared — possible LSB steganography detected")
            else:
                st.success("✅ Low chi-squared — no steganography evidence found")


