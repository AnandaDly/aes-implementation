import streamlit as st
import os
from cryptography.fernet import Fernet
from typing import Tuple
import base64
import json

def is_prime(n: int) -> bool:
    """Fungsi sederhana untuk mengecek bilangan prima"""
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def gcd(a: int, b: int) -> int:
    """Menghitung GCD (Greatest Common Divisor)"""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e: int, phi: int) -> int:
    """Menghitung modular multiplicative inverse"""
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError(f"Modular inverse tidak ditemukan karena GCD({e}, {phi}) = {gcd}")
    return x % phi

def generate_keypair(p: int, q: int) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """Membuat pasangan kunci publik dan private"""
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Kedua angka harus prima')
    elif p == q:
        raise ValueError('p dan q tidak boleh sama')
    
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # Biasanya menggunakan 65537 sebagai standar
    if gcd(e, phi) != 1:
        raise ValueError("e tidak coprime dengan phi. Pilih p dan q yang berbeda.")
    
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def rsa_encrypt(public_key: Tuple[int, int], message: bytes) -> list:
    """Enkripsi menggunakan RSA"""
    e, n = public_key
    # Enkripsi setiap byte dari pesan
    encrypted = [pow(byte, e, n) for byte in message]
    return encrypted

def rsa_decrypt(private_key: Tuple[int, int], encrypted_data: list) -> bytes:
    """Dekripsi menggunakan RSA"""
    d, n = private_key
    # Dekripsi setiap byte
    decrypted = bytes([pow(byte, d, n) for byte in encrypted_data])
    return decrypted

def encrypt_file(file_data: bytes, public_key: Tuple[int, int]) -> dict:
    """Enkripsi file menggunakan kombinasi RSA dan Fernet (AES)"""
    # Generate kunci Fernet (AES)
    fernet_key = Fernet.generate_key()
    fernet = Fernet(fernet_key)
    
    # Enkripsi file menggunakan Fernet
    encrypted_file = fernet.encrypt(file_data)
    
    # Enkripsi kunci Fernet menggunakan RSA
    encrypted_key = rsa_encrypt(public_key, fernet_key)
    
    # Return keduanya
    return {
        'encrypted_file': base64.b64encode(encrypted_file).decode('utf-8'),
        'encrypted_key': encrypted_key
    }

def decrypt_file(encrypted_package: dict, private_key: Tuple[int, int]) -> bytes:
    """Dekripsi file menggunakan kombinasi RSA dan Fernet (AES)"""
    # Dekripsi kunci Fernet menggunakan RSA
    fernet_key = rsa_decrypt(private_key, encrypted_package['encrypted_key'])
    
    # Dekripsi file menggunakan Fernet
    fernet = Fernet(fernet_key)
    encrypted_file = base64.b64decode(encrypted_package['encrypted_file'].encode('utf-8'))
    decrypted_file = fernet.decrypt(encrypted_file)
    
    return decrypted_file

# Streamlit Interface
def main():
    st.title('Enkripsi File dengan RSA dan AES')
    st.write("""
    Aplikasi ini menggunakan kombinasi RSA dan AES untuk mengamankan file:
    - RSA digunakan untuk mengenkripsi kunci AES
    - AES digunakan untuk mengenkripsi file (lebih efisien untuk data besar)
    """)

    # Input bilangan prima
    col1, col2 = st.columns(2)
    with col1:
        p = st.number_input("Masukkan bilangan prima p:", min_value=11, max_value=97, value=11)
    with col2:
        q = st.number_input("Masukkan bilangan prima q:", min_value=11, max_value=97, value=13)

    st.info("""
    Contoh pasangan bilangan prima yang bisa digunakan:
    - p = 11, q = 13
    - p = 17, q = 19
    - p = 23, q = 29
    """)

    # Generate kunci
    if st.button("Generate Kunci"):
        try:
            if not (is_prime(p) and is_prime(q)):
                st.error("Pastikan kedua angka adalah bilangan prima!")
                return
            
            public_key, private_key = generate_keypair(p, q)
            st.session_state['public_key'] = public_key
            st.session_state['private_key'] = private_key
            st.success("Kunci berhasil dibuat!")
            st.write("Kunci Publik (e, n):", public_key)
            st.write("Kunci Private (d, n):", private_key)
        except Exception as e:
            st.error(f"Error saat generate kunci: {str(e)}")
            return

    # Tab untuk enkripsi dan dekripsi
    tab1, tab2 = st.tabs(["Enkripsi File", "Dekripsi File"])
    
    with tab1:
        if 'public_key' in st.session_state:
            uploaded_file = st.file_uploader("Pilih file untuk dienkripsi", key="encrypt")
            if uploaded_file is not None:
                if st.button("Enkripsi File"):
                    try:
                        # Baca file
                        file_content = uploaded_file.read()
                        
                        # Enkripsi
                        encrypted_data = encrypt_file(file_content, st.session_state['public_key'])
                        
                        # Simpan hasil enkripsi
                        encrypted_str = json.dumps(encrypted_data)
                        
                        # Button download
                        st.download_button(
                            label="Download File Terenkripsi",
                            data=encrypted_str,
                            file_name=f"encrypted_{uploaded_file.name}",
                            mime="application/json"
                        )
                        st.success("File berhasil dienkripsi!")
                    except Exception as e:
                        st.error(f"Error saat enkripsi: {str(e)}")
        else:
            st.warning("Harap generate kunci terlebih dahulu!")

    with tab2:
        if 'private_key' in st.session_state:
            uploaded_file = st.file_uploader("Pilih file untuk didekripsi", key="decrypt")
            if uploaded_file is not None:
                try:
                    # Baca file enkripsi
                    encrypted_data = json.loads(uploaded_file.read())
                    
                    if st.button("Dekripsi File"):
                        # Dekripsi
                        decrypted_data = decrypt_file(encrypted_data, st.session_state['private_key'])
                        
                        # Button download
                        st.download_button(
                            label="Download File Terdekripsi",
                            data=decrypted_data,
                            file_name="decrypted_file",
                            mime="application/octet-stream"
                        )
                        st.success("File berhasil didekripsi!")
                except Exception as e:
                    st.error(f"Error saat dekripsi: {str(e)}")
        else:
            st.warning("Harap generate kunci terlebih dahulu!")

    # Penjelasan
    with st.expander("Lihat Penjelasan Cara Kerja"):
        st.markdown("""
        ### Cara Kerja Enkripsi File:
        1. **Generate Kunci RSA**
           - Menggunakan dua bilangan prima untuk membuat pasangan kunci publik dan private
           - Kunci publik untuk enkripsi, kunci private untuk dekripsi
        
        2. **Proses Enkripsi**
           - Generate kunci AES (Fernet) secara random
           - Enkripsi file menggunakan kunci AES
           - Enkripsi kunci AES menggunakan RSA
           - Gabungkan hasil enkripsi file dan kunci dalam satu paket
        
        3. **Proses Dekripsi**
           - Dekripsi kunci AES menggunakan RSA private key
           - Gunakan kunci AES untuk mendekripsi file
        
        ### Keuntungan Metode Hybrid (RSA + AES):
        - RSA aman untuk enkripsi kunci
        - AES cepat untuk enkripsi file besar
        - Kombinasi keduanya memberikan keamanan dan efisiensi
        
        ### Catatan Penting:
        - Ini adalah implementasi sederhana untuk pembelajaran
        - Gunakan bilangan prima yang lebih besar untuk keamanan yang lebih baik
        - Simpan kunci private dengan aman
        """)

if __name__ == "__main__":
    main()