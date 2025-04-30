import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from PIL import Image
import io

# --- Caesar Cipher ---
def caesar_cipher(text: str, shift: int, mode: str) -> str:
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            shifted_char = chr((ord(char) - shift_base + (shift if mode == "encrypt" else -shift)) % 26 + shift_base)
            result += shifted_char
        else:
            result += char
    return result

# --- AES Encryption ---
def aes_encrypt_to_numbers(plaintext: str, key: bytes) -> int:
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_bytes = iv + ciphertext
    return int.from_bytes(encrypted_bytes, byteorder='big')

def aes_decrypt_from_numbers(encrypted_number: int, key: bytes) -> str:
    encrypted_bytes = encrypted_number.to_bytes((encrypted_number.bit_length() + 7) // 8, byteorder='big')
    iv = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

# --- RSA Encryption ---
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def rsa_encrypt(plaintext: str, public_key_pem: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(ciphertext: bytes, private_key_pem: bytes) -> str:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    plaintext = private_key.decrypt(
        ciphertext,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# --- File Upload and Encryption ---
def encrypt_file(file, encryption_method, key):
    if encryption_method == "Caesar Cipher":
        # Read file content as text
        text = file.read().decode('utf-8', errors='ignore')
        encrypted_text = caesar_cipher(text, 3, "encrypt")  # Example with shift=3
        return encrypted_text
    elif encryption_method == "AES-256":
        # Read file content and encrypt as AES
        file_content = file.read()
        encrypted_content = aes_encrypt_to_numbers(file_content.decode(), key)
        return str(encrypted_content)
    elif encryption_method == "RSA":
        # Encrypt file content with RSA
        file_content = file.read().decode('utf-8', errors='ignore')
        encrypted_content = rsa_encrypt(file_content, key)
        return encrypted_content.hex()

# --- Streamlit App ---
st.set_page_config(page_title="🔐 Enkripsi Teks dan File", layout="wide")  # Wide layout for larger screens
st.title("🔐 Enkripsi dan Dekripsi: Caesar Cipher, AES, RSA")
st.caption("Pilih metode enkripsi dan dekripsi sesuai kebutuhan!")

# --- Mobile-Friendly Custom Styling ---
st.markdown("""
    <style>
        /* Larger font size and button size for mobile view */
        .css-1e2qb0v { font-size: 18px; }
        .css-18e3p7o { padding: 15px; font-size: 20px; }
        .css-1byaxg8 { font-size: 24px; }
    </style>
""", unsafe_allow_html=True)

method = st.radio("Pilih Metode Enkripsi/Dekripsi:", ["Caesar Cipher", "AES-256", "RSA"], key="encryption_method")

if method == "Caesar Cipher":
    mode = st.radio("Mode", ["Enkripsi", "Dekripsi"], horizontal=True)
    shift = st.number_input("Jumlah Shift", min_value=1, max_value=25, value=3)
    text_input = st.text_area("Masukkan Teks", height=100)

    if st.button("🔒 Jalankan Enkripsi/Deskripsi"):
        if mode == "Enkripsi":
            result = caesar_cipher(text_input, shift, "encrypt")
            st.success("✅ Teks berhasil dienkripsi dengan Caesar Cipher!")
        else:
            result = caesar_cipher(text_input, shift, "decrypt")
            st.success("✅ Teks berhasil didekripsi dengan Caesar Cipher!")

        st.code(result)
        st.download_button("📥 Unduh Hasil", result, "hasil_caesar.txt")

elif method == "AES-256":
    mode = st.radio("Mode", ["Enkripsi", "Dekripsi"], horizontal=True)
    key_input = st.text_input("Kunci AES (32 karakter)", type="password", max_chars=32)
    if mode == "Enkripsi":
        text_input = st.text_area("Masukkan Teks untuk Enkripsi", height=100)
    else:
        text_input = st.text_area("Masukkan Angka untuk Dekripsi", height=100)

    if st.button("🚀 Jalankan Enkripsi/Dekripsi"):
        if len(key_input) != 32:
            st.error("Kunci harus 32 karakter.")
        elif not text_input.strip():
            st.warning("Pesan kosong.")
        else:
            try:
                if mode == "Enkripsi":
                    encrypted_number = aes_encrypt_to_numbers(text_input, key_input.encode())
                    st.success("✅ Teks berhasil dienkripsi!")
                    result = str(encrypted_number)
                else:
                    encrypted_number = int(text_input)
                    decrypted_text = aes_decrypt_from_numbers(encrypted_number, key_input.encode())
                    st.success("✅ Teks berhasil didekripsi!")
                    result = decrypted_text

                st.code(result)
                st.download_button("📥 Unduh Hasil", result, "hasil_aes.txt")
            except Exception as e:
                st.error(f"❌ Terjadi kesalahan: {e}")

elif method == "RSA":
    mode = st.radio("Mode", ["Enkripsi", "Dekripsi"], horizontal=True)
    if mode == "Enkripsi":
        text_input = st.text_area("Masukkan Teks untuk Enkripsi", height=100)
        private_key, public_key = generate_rsa_keys()
        st.session_state.rsa_public_key = public_key
        st.session_state.rsa_private_key = private_key  # Simpan private key di session_state
    else:
        text_input = st.text_area("Masukkan Ciphertext untuk Dekripsi", height=100)

    if st.button("🔐 Jalankan Enkripsi/Dekripsi"):
        if mode == "Enkripsi":
            encrypted_data = rsa_encrypt(text_input, st.session_state.rsa_public_key)
            st.success("✅ Teks berhasil dienkripsi dengan RSA!")
            result = encrypted_data.hex()  # Convert to hex to display
        else:
            encrypted_data = bytes.fromhex(text_input.strip())
            decrypted_text = rsa_decrypt(encrypted_data, st.session_state.rsa_private_key)  # Gunakan private key dari session_state
            st.success("✅ Teks berhasil didekripsi dengan RSA!")
            result = decrypted_text

        st.code(result)
        st.download_button("📥 Unduh Hasil", result, "hasil_rsa.txt")

# --- Upload File ---
st.subheader("Unggah File untuk Enkripsi")
uploaded_file = st.file_uploader("Pilih file teks atau gambar", type=["txt", "png", "jpg", "jpeg"])

if uploaded_file is not None:
    encryption_method = st.radio("Pilih Metode Enkripsi untuk File:", ["Caesar Cipher", "AES-256", "RSA"])

    if st.button("Enkripsi File"):
        key_input = st.text_input("Masukkan Kunci untuk Enkripsi", type="password", max_chars=32)
        if encryption_method == "AES-256" and len(key_input) != 32:
            st.error("Kunci harus 32 karakter untuk AES-256!")
        elif uploaded_file:
            encrypted_file = encrypt_file(uploaded_file, encryption_method, key_input.encode())
            st.success("✅ File berhasil dienkripsi!")
            st.code(encrypted_file)
            st.download_button("📥 Unduh File Terenkripsi", encrypted_file, "encrypted_file.txt")
