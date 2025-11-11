"""
Secure File Encryption Suite
Author: [Raj M Konkar]
Internship Project - Codec Technologies

Features:
- AES encryption/decryption for files
- RSA key generation and encryption for AES key
- SHA-256 integrity check
"""

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64
import os

# === RSA Key Generation ===
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("private.pem", "wb") as f:
        f.write(private_key)
    with open("public.pem", "wb") as f:
        f.write(public_key)
    print("[+] RSA Key Pair Generated: private.pem, public.pem")

# === AES Encryption ===
def encrypt_file(file_path, public_key_path):
    data = open(file_path, "rb").read()

    # Generate AES key
    aes_key = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    # Encrypt AES key with RSA public key
    recipient_key = RSA.import_key(open(public_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    # Save encrypted data
    with open(file_path + ".enc", "wb") as f:
        for x in (enc_aes_key, cipher_aes.nonce, tag, ciphertext):
            f.write(x)

    # Generate file hash
    file_hash = SHA256.new(data).hexdigest()
    with open(file_path + ".hash", "w") as f:
        f.write(file_hash)

    print(f"[+] File encrypted: {file_path}.enc")
    print(f"[+] File integrity hash stored: {file_path}.hash")

# === AES Decryption ===
def decrypt_file(file_path, private_key_path):
    private_key = RSA.import_key(open(private_key_path).read())
    with open(file_path, "rb") as f:
        enc_aes_key, nonce, tag, ciphertext = \
            [f.read(x) for x in (256, 16, 16, -1)]

    # Decrypt AES key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    # Decrypt file
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    original_file = file_path.replace(".enc", ".dec")
    with open(original_file, "wb") as f:
        f.write(data)

    print(f"[+] File decrypted: {original_file}")

# === File Integrity Verification ===
def verify_integrity(original_file, hash_file):
    with open(original_file, "rb") as f:
        data = f.read()
    computed_hash = SHA256.new(data).hexdigest()
    stored_hash = open(hash_file, "r").read().strip()

    if computed_hash == stored_hash:
        print("[+] File integrity verified: SHA-256 hash matches ✅")
    else:
        print("[-] Integrity check failed! File may be corrupted ⚠️")

# === CLI Menu ===
def main():
    print("\n==== Secure File Encryption Suite ====")
    print("1. Generate RSA Key Pair")
    print("2. Encrypt File")
    print("3. Decrypt File")
    print("4. Verify File Integrity")
    print("5. Exit")

    choice = input("Enter choice: ")

    if choice == "1":
        generate_rsa_keys()
    elif choice == "2":
        file_path = input("Enter file path to encrypt: ")
        public_key = input("Enter RSA public key path: ")
        encrypt_file(file_path, public_key)
    elif choice == "3":
        file_path = input("Enter encrypted file path: ")
        private_key = input("Enter RSA private key path: ")
        decrypt_file(file_path, private_key)
    elif choice == "4":
        file_path = input("Enter original file path: ")
        hash_path = input("Enter hash file path: ")
        verify_integrity(file_path, hash_path)
    else:
        print("Exiting...")

if __name__ == "__main__":
    main()
