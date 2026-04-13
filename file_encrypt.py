import os
import argparse
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# =========================
# KONSTANTA
# =========================
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 100000

# =========================
# DERIVASI KUNCI
# =========================
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode())

# =========================
# ENKRIPSI
# =========================
def encrypt_file(input_file, output_file, password):
    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print("File input tidak ditemukan!")
        return

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)

    aad = os.path.basename(input_file).encode()
    aad_length = len(aad)

    ciphertext = aesgcm.encrypt(nonce, data, aad)

    tag_length = 16

    with open(output_file, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(tag_length.to_bytes(1, 'big'))
        f.write(aad_length.to_bytes(1, 'big'))
        f.write(aad)
        f.write(ciphertext)

    print("Enkripsi berhasil!")

# =========================
# DEKRIPSI (AUTO AAD)
# =========================
def decrypt_file(input_file, output_file, password):
    try:
        with open(input_file, "rb") as f:
            file_data = f.read()
    except FileNotFoundError:
        print("File tidak ditemukan!")
        return

    try:
        salt = file_data[:SALT_SIZE]
        nonce = file_data[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
        tag_length = file_data[SALT_SIZE+NONCE_SIZE]
        aad_length = file_data[SALT_SIZE+NONCE_SIZE+1]

        aad_start = SALT_SIZE + NONCE_SIZE + 2
        aad_end = aad_start + aad_length

        aad = file_data[aad_start:aad_end]
        ciphertext = file_data[aad_end:]

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

        with open(output_file, "wb") as f:
            f.write(plaintext)

        print("Dekripsi berhasil!")
        print(f"AAD (nama file asli): {aad.decode()}")

    except InvalidTag:
        print("Password salah / file telah dimodifikasi!")
    except Exception as e:
        print("File rusak atau format tidak valid!")
        print("Detail:", str(e))

# =========================
# READ HEX (UPDATE)
# =========================
def read_file_hex(filename):
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print("File tidak ditemukan!")
        return

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    tag_length = data[SALT_SIZE+NONCE_SIZE]
    aad_length = data[SALT_SIZE+NONCE_SIZE+1]

    aad_start = SALT_SIZE + NONCE_SIZE + 2
    aad_end = aad_start + aad_length

    aad = data[aad_start:aad_end]
    ciphertext = data[aad_end:]

    print("\n===== PARSING HEADER =====")
    print(f"Salt (16B)        : {salt.hex()}")
    print(f"Nonce (12B)       : {nonce.hex()}")
    print(f"Tag Length        : {tag_length}")
    print(f"AAD Length        : {aad_length}")
    print(f"AAD (filename)    : {aad.decode()}")
    print(f"Ciphertext+Tag    : {ciphertext.hex()}")

# =========================
# MAIN CLI
# =========================
def main():
    parser = argparse.ArgumentParser(description="AES-256-GCM Tool (Auto AAD)")
    
    parser.add_argument("mode", choices=["encrypt", "decrypt", "read"])
    parser.add_argument("input_file")
    parser.add_argument("output_file", nargs="?", default=None)
    parser.add_argument("--password")

    args = parser.parse_args()

    if args.mode == "encrypt":
        if not args.password:
            print("Butuh --password")
            return
        encrypt_file(args.input_file, args.output_file, args.password)

    elif args.mode == "decrypt":
        if not args.password:
            print("Butuh --password")
            return
        decrypt_file(args.input_file, args.output_file, args.password)

    elif args.mode == "read":
        read_file_hex(args.input_file)

if __name__ == "__main__":
    main()