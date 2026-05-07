"""
PYTHON CRYPTOGRAPHY TOOLKIT — Streamlit UI
Run with: streamlit run crypto_app.py
Requires: pip install streamlit pycryptodome
"""

import os
import base64
import hashlib
import streamlit as st

# ─── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CryptoVault",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

/* ── Global ── */
html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
}

.stApp {
    background: #0a0c10;
    color: #c8d6e5;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: #0d1117 !important;
    border-right: 1px solid #1f2d3d;
}
section[data-testid="stSidebar"] * {
    color: #7ec8e3 !important;
}
section[data-testid="stSidebar"] .stRadio label {
    font-size: 1.05rem;
    letter-spacing: 0.05em;
}

/* ── Main headings ── */
h1, h2, h3 {
    font-family: 'Rajdhani', sans-serif !important;
    letter-spacing: 0.08em;
}

/* ── Hero banner ── */
.hero-banner {
    background: linear-gradient(135deg, #0d1b2a 0%, #112233 60%, #0a1628 100%);
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 2rem 2.5rem;
    margin-bottom: 1.5rem;
    position: relative;
    overflow: hidden;
}
.hero-banner::before {
    content: '';
    position: absolute;
    top: -40px; right: -40px;
    width: 200px; height: 200px;
    background: radial-gradient(circle, rgba(0,200,255,0.06) 0%, transparent 70%);
    border-radius: 50%;
}
.hero-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2.4rem;
    color: #00c8ff;
    margin: 0;
    text-shadow: 0 0 30px rgba(0,200,255,0.4);
    letter-spacing: 0.12em;
}
.hero-sub {
    font-size: 1.1rem;
    color: #5a8fa8;
    margin-top: 0.4rem;
    letter-spacing: 0.05em;
}

/* ── Cipher card ── */
.cipher-card {
    background: #0d1b2a;
    border: 1px solid #1e3a5f;
    border-left: 4px solid #00c8ff;
    border-radius: 10px;
    padding: 1.4rem 1.6rem;
    margin-bottom: 1.2rem;
}
.cipher-card h3 {
    color: #00c8ff;
    margin: 0 0 0.4rem 0;
    font-size: 1.3rem;
}
.cipher-card p {
    color: #5a8fa8;
    margin: 0;
    font-size: 0.95rem;
    line-height: 1.5;
}

/* ── Result box ── */
.result-box {
    background: #061018;
    border: 1px solid #00c8ff44;
    border-radius: 8px;
    padding: 1.2rem 1.4rem;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.9rem;
    color: #00ff88;
    word-break: break-all;
    white-space: pre-wrap;
    line-height: 1.6;
    margin-top: 0.5rem;
}

/* ── Error / warning box ── */
.err-box {
    background: #1a0a0a;
    border: 1px solid #ff4444;
    border-radius: 8px;
    padding: 1rem 1.2rem;
    color: #ff6666;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.88rem;
}

/* ── Inputs ── */
.stTextArea textarea, .stTextInput input, .stNumberInput input {
    background: #0d1b2a !important;
    border: 1px solid #1e3a5f !important;
    color: #c8d6e5 !important;
    font-family: 'Share Tech Mono', monospace !important;
    border-radius: 6px !important;
}
.stTextArea textarea:focus, .stTextInput input:focus {
    border-color: #00c8ff !important;
    box-shadow: 0 0 0 2px rgba(0,200,255,0.15) !important;
}

/* ── Buttons ── */
.stButton > button {
    background: linear-gradient(135deg, #003d5c, #005580) !important;
    color: #00c8ff !important;
    border: 1px solid #00c8ff55 !important;
    border-radius: 6px !important;
    font-family: 'Rajdhani', sans-serif !important;
    font-weight: 700 !important;
    letter-spacing: 0.1em !important;
    font-size: 1rem !important;
    padding: 0.5rem 1.5rem !important;
    transition: all 0.2s ease !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #005580, #0077aa) !important;
    border-color: #00c8ff !important;
    box-shadow: 0 0 16px rgba(0,200,255,0.25) !important;
}

/* ── Radio ── */
.stRadio > div { gap: 0.4rem; }
.stRadio label { font-size: 1rem; }

/* ── Select ── */
.stSelectbox select, div[data-baseweb="select"] {
    background: #0d1b2a !important;
    color: #c8d6e5 !important;
    border-color: #1e3a5f !important;
}

/* ── Key badge ── */
.key-badge {
    display: inline-block;
    background: #00c8ff18;
    border: 1px solid #00c8ff44;
    color: #00c8ff;
    border-radius: 4px;
    padding: 0.15rem 0.6rem;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.78rem;
    margin-right: 0.3rem;
    letter-spacing: 0.05em;
}

/* ── Divider ── */
hr { border-color: #1e3a5f !important; }

/* ── Info metric ── */
.info-metric {
    background: #0d1b2a;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 1rem;
    text-align: center;
}
.info-metric .val {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1.6rem;
    color: #00c8ff;
}
.info-metric .lbl {
    font-size: 0.85rem;
    color: #5a8fa8;
    letter-spacing: 0.06em;
    text-transform: uppercase;
}

/* ── PEM box ── */
.pem-box {
    background: #061018;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 1rem;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.78rem;
    color: #7ec8e3;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 180px;
    overflow-y: auto;
    margin-top: 0.5rem;
}
</style>
""", unsafe_allow_html=True)


# ─── Cipher Classes (self-contained) ─────────────────────────────────────────

class CaesarCipher:
    def encrypt(self, text, shift):
        shift %= 26
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch) - base + shift) % 26 + base))
            else:
                result.append(ch)
        return ''.join(result)
    def decrypt(self, text, shift): return self.encrypt(text, -shift)


class VigenereCipher:
    def _key(self, k): return ''.join(filter(str.isalpha, k)).upper()
    def encrypt(self, text, key):
        key = self._key(key)
        if not key: raise ValueError("Key must contain letters.")
        result, ki = [], 0
        for ch in text:
            if ch.isalpha():
                shift = ord(key[ki % len(key)]) - ord('A')
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch) - base + shift) % 26 + base))
                ki += 1
            else:
                result.append(ch)
        return ''.join(result)
    def decrypt(self, text, key):
        key = self._key(key)
        if not key: raise ValueError("Key must contain letters.")
        result, ki = [], 0
        for ch in text:
            if ch.isalpha():
                shift = ord(key[ki % len(key)]) - ord('A')
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch) - base - shift) % 26 + base))
                ki += 1
            else:
                result.append(ch)
        return ''.join(result)


class XORCipher:
    def _xor(self, data, key):
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    def encrypt(self, text, key):
        return base64.b64encode(self._xor(text.encode(), key.encode())).decode()
    def decrypt(self, text, key):
        return self._xor(base64.b64decode(text.encode()), key.encode()).decode()


def _try_import_crypto():
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP, AES
        from Crypto.Util.Padding import pad, unpad
        return RSA, PKCS1_OAEP, AES, pad, unpad, True
    except ImportError:
        return None, None, None, None, None, False


RSA_mod, PKCS1_OAEP_mod, AES_mod, pad_fn, unpad_fn, CRYPTO_OK = _try_import_crypto()


class RSACipher:
    def generate_keys(self, bits=2048):
        if not CRYPTO_OK: raise ImportError("pycryptodome required")
        key = RSA_mod.generate(bits)
        return key.publickey().export_key(), key.export_key()
    def encrypt(self, text, pub_pem):
        if not CRYPTO_OK: raise ImportError("pycryptodome required")
        cipher = PKCS1_OAEP_mod.new(RSA_mod.import_key(pub_pem))
        return base64.b64encode(cipher.encrypt(text.encode())).decode()
    def decrypt(self, ct_b64, priv_pem):
        if not CRYPTO_OK: raise ImportError("pycryptodome required")
        cipher = PKCS1_OAEP_mod.new(RSA_mod.import_key(priv_pem))
        return cipher.decrypt(base64.b64decode(ct_b64)).decode()


class AESCipher:
    def _key(self, p): return hashlib.sha256(p.encode()).digest()
    def encrypt(self, text, passphrase):
        if not CRYPTO_OK: raise ImportError("pycryptodome required")
        key, iv = self._key(passphrase), os.urandom(16)
        ct = AES_mod.new(key, AES_mod.MODE_CBC, iv).encrypt(pad_fn(text.encode(), 16))
        return base64.b64encode(iv + ct).decode()
    def decrypt(self, ct_b64, passphrase):
        if not CRYPTO_OK: raise ImportError("pycryptodome required")
        key, raw = self._key(passphrase), base64.b64decode(ct_b64)
        return unpad_fn(AES_mod.new(key, AES_mod.MODE_CBC, raw[:16]).decrypt(raw[16:]), 16).decode()


# ─── Sidebar ──────────────────────────────────────────────────────────────────

CIPHERS = {
    "🔤  Caesar Cipher":   "caesar",
    "🔑  Vigenère Cipher": "vigenere",
    "⊕   XOR Cipher":     "xor",
    "🔒  RSA (2048-bit)":  "rsa",
    "🛡️  AES-256-CBC":    "aes",
}

with st.sidebar:
    st.markdown("### 🔐 CryptoVault")
    st.markdown("---")
    st.markdown("**Select Cipher**")
    selected_label = st.radio("", list(CIPHERS.keys()), label_visibility="collapsed")
    cipher_key = CIPHERS[selected_label]

    st.markdown("---")
    st.markdown(
        "<div style='font-size:0.8rem;color:#2a5a75;letter-spacing:0.05em'>"
        "CIPHER STRENGTH<br>"
        "</div>",
        unsafe_allow_html=True,
    )
    strength_map = {
        "caesar": ("▓░░░░", "WEAK"),
        "vigenere": ("▓▓░░░", "LOW"),
        "xor": ("▓▓▓░░", "MEDIUM"),
        "rsa": ("▓▓▓▓▓", "STRONG"),
        "aes": ("▓▓▓▓▓", "STRONG"),
    }
    bar, label = strength_map[cipher_key]
    st.markdown(
        f"<div style='font-family:Share Tech Mono,monospace;color:#00c8ff;font-size:1.1rem'>"
        f"{bar} <span style='color:#5a8fa8;font-size:0.85rem'>{label}</span></div>",
        unsafe_allow_html=True,
    )

    if not CRYPTO_OK:
        st.markdown("---")
        st.warning("⚠️ Install pycryptodome for RSA & AES:\n```\npip install pycryptodome\n```")


# ─── Hero ─────────────────────────────────────────────────────────────────────

st.markdown("""
<div class="hero-banner">
  <div class="hero-title">🔐 CRYPTOVAULT</div>
  <div class="hero-sub">Multi-cipher encryption & decryption toolkit · 5 algorithms</div>
</div>
""", unsafe_allow_html=True)


# ─── Cipher descriptions ──────────────────────────────────────────────────────

DESCRIPTIONS = {
    "caesar": ("Caesar Cipher", "Classical substitution cipher. Each letter is shifted by a fixed integer key. Simple but historically significant — used by Julius Caesar himself."),
    "vigenere": ("Vigenère Cipher", "Polyalphabetic substitution cipher using a repeating keyword. Much stronger than Caesar — each letter uses a different shift based on the key character."),
    "xor": ("XOR Cipher", "Bitwise XOR of each byte against a repeating key. Symmetric (encrypt = decrypt). Output is Base64-encoded for safe display. Forms the basis of many stream ciphers."),
    "rsa": ("RSA Cipher — 2048-bit", "Industry-standard asymmetric public-key cryptography. Encrypt with the public key, decrypt with the private key. Uses PKCS1-OAEP padding. Ideal for key exchange."),
    "aes": ("AES-256-CBC", "The gold standard for symmetric encryption. Your passphrase is hashed via SHA-256 to derive a 32-byte key. A random 16-byte IV is prepended to each ciphertext — so identical plaintext always produces different output."),
}

title, desc = DESCRIPTIONS[cipher_key]
st.markdown(f"""
<div class="cipher-card">
  <h3>{title}</h3>
  <p>{desc}</p>
</div>
""", unsafe_allow_html=True)


# ─── Operation toggle ─────────────────────────────────────────────────────────

col_op1, col_op2, _ = st.columns([1, 1, 3])
with col_op1:
    operation = st.radio("Operation", ["🔒 Encrypt", "🔓 Decrypt"], horizontal=False)
is_encrypt = operation == "🔒 Encrypt"


st.markdown("---")


# ──────────────────────────────────────────────────────────────────────────────
# CAESAR
# ──────────────────────────────────────────────────────────────────────────────

if cipher_key == "caesar":
    col1, col2 = st.columns(2)
    with col1:
        text_in = st.text_area("Input Text", height=140, placeholder="Enter text here…")
        shift = st.number_input("Shift Value", min_value=0, max_value=25, value=13)
    with col2:
        st.markdown("**Output**")
        if st.button("Run Caesar", use_container_width=True):
            try:
                c = CaesarCipher()
                result = c.encrypt(text_in, shift) if is_encrypt else c.decrypt(text_in, shift)
                st.markdown(f'<div class="result-box">{result}</div>', unsafe_allow_html=True)
            except Exception as e:
                st.markdown(f'<div class="err-box">✗ {e}</div>', unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# VIGENÈRE
# ──────────────────────────────────────────────────────────────────────────────

elif cipher_key == "vigenere":
    col1, col2 = st.columns(2)
    with col1:
        text_in = st.text_area("Input Text", height=140, placeholder="Enter text here…")
        key_in = st.text_input("Keyword", placeholder="e.g. PYTHON")
    with col2:
        st.markdown("**Output**")
        if st.button("Run Vigenère", use_container_width=True):
            try:
                c = VigenereCipher()
                result = c.encrypt(text_in, key_in) if is_encrypt else c.decrypt(text_in, key_in)
                st.markdown(f'<div class="result-box">{result}</div>', unsafe_allow_html=True)
            except Exception as e:
                st.markdown(f'<div class="err-box">✗ {e}</div>', unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# XOR
# ──────────────────────────────────────────────────────────────────────────────

elif cipher_key == "xor":
    col1, col2 = st.columns(2)
    with col1:
        text_in = st.text_area("Input Text", height=140, placeholder="Plaintext or Base64 ciphertext…")
        key_in = st.text_input("Secret Key", placeholder="Any string key")
    with col2:
        st.markdown("**Output**")
        if st.button("Run XOR", use_container_width=True):
            try:
                c = XORCipher()
                result = c.encrypt(text_in, key_in) if is_encrypt else c.decrypt(text_in, key_in)
                st.markdown(f'<div class="result-box">{result}</div>', unsafe_allow_html=True)
            except Exception as e:
                st.markdown(f'<div class="err-box">✗ {e}</div>', unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# RSA
# ──────────────────────────────────────────────────────────────────────────────

elif cipher_key == "rsa":
    if not CRYPTO_OK:
        st.error("pycryptodome is required. Run: `pip install pycryptodome`")
    else:
        rsa = RSACipher()

        # Key generation section
        st.markdown("#### Key Management")
        gen_col1, gen_col2 = st.columns([1, 3])
        with gen_col1:
            bits = st.selectbox("Key Size", [1024, 2048, 4096], index=1)
            if st.button("Generate Key Pair", use_container_width=True):
                with st.spinner("Generating keys…"):
                    pub, priv = rsa.generate_keys(bits)
                    st.session_state["rsa_pub"] = pub.decode()
                    st.session_state["rsa_priv"] = priv.decode()
        with gen_col2:
            if "rsa_pub" in st.session_state:
                k1, k2 = st.columns(2)
                with k1:
                    st.markdown("**Public Key**")
                    st.markdown(f'<div class="pem-box">{st.session_state["rsa_pub"]}</div>', unsafe_allow_html=True)
                    st.download_button("⬇ Download", st.session_state["rsa_pub"], "public.pem", use_container_width=True)
                with k2:
                    st.markdown("**Private Key**")
                    st.markdown(f'<div class="pem-box">{st.session_state["rsa_priv"]}</div>', unsafe_allow_html=True)
                    st.download_button("⬇ Download", st.session_state["rsa_priv"], "private.pem", use_container_width=True)

        st.markdown("---")
        st.markdown("#### Encrypt / Decrypt")
        col1, col2 = st.columns(2)
        with col1:
            text_in = st.text_area("Input Text", height=120, placeholder="Short message (RSA size limited)…")
            if is_encrypt:
                pub_paste = st.text_area("Public Key PEM", height=100,
                    value=st.session_state.get("rsa_pub", ""),
                    placeholder="Paste PEM or generate above…")
            else:
                priv_paste = st.text_area("Private Key PEM", height=100,
                    value=st.session_state.get("rsa_priv", ""),
                    placeholder="Paste PEM or generate above…")
        with col2:
            st.markdown("**Output**")
            if st.button("Run RSA", use_container_width=True):
                try:
                    if is_encrypt:
                        result = rsa.encrypt(text_in, pub_paste.encode())
                    else:
                        result = rsa.decrypt(text_in, priv_paste.encode())
                    st.markdown(f'<div class="result-box">{result}</div>', unsafe_allow_html=True)
                except Exception as e:
                    st.markdown(f'<div class="err-box">✗ {e}</div>', unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# AES
# ──────────────────────────────────────────────────────────────────────────────

elif cipher_key == "aes":
    if not CRYPTO_OK:
        st.error("pycryptodome is required. Run: `pip install pycryptodome`")
    else:
        aes = AESCipher()
        col1, col2 = st.columns(2)
        with col1:
            text_in = st.text_area("Input Text", height=140, placeholder="Plaintext or Base64 ciphertext…")
            passphrase = st.text_input("Passphrase", type="password", placeholder="Your secret passphrase")
            if passphrase:
                key_bytes = hashlib.sha256(passphrase.encode()).hexdigest()[:16].upper()
                st.markdown(
                    f'Key preview (SHA-256): <span class="key-badge">{key_bytes}…</span>',
                    unsafe_allow_html=True,
                )
        with col2:
            st.markdown("**Output**")
            if st.button("Run AES-256", use_container_width=True):
                try:
                    result = aes.encrypt(text_in, passphrase) if is_encrypt else aes.decrypt(text_in, passphrase)
                    st.markdown(f'<div class="result-box">{result}</div>', unsafe_allow_html=True)
                except Exception as e:
                    st.markdown(f'<div class="err-box">✗ {e}</div>', unsafe_allow_html=True)


# ─── Footer ───────────────────────────────────────────────────────────────────

st.markdown("---")
m1, m2, m3, m4, m5 = st.columns(5)
metrics = [
    ("Caesar",   "CLASSICAL"),
    ("Vigenère", "CLASSICAL"),
    ("XOR",      "SYMMETRIC"),
    ("RSA",      "ASYMMETRIC"),
    ("AES-256",  "SYMMETRIC"),
]
for col, (val, lbl) in zip([m1, m2, m3, m4, m5], metrics):
    col.markdown(
        f'<div class="info-metric"><div class="val">{val}</div><div class="lbl">{lbl}</div></div>',
        unsafe_allow_html=True,
    )
