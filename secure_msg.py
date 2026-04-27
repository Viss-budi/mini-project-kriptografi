import argparse
import os
import time

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =========================
# KEY GENERATION
# =========================
def generate_keypair(name):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    with open(f"{name}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b'pass123')
        ))

    with open(f"{name}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"[OK] Key {name} berhasil dibuat")


# =========================
# LOAD KEY
# =========================
def load_public(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=b'pass123')


# =========================
# RSA
# =========================
def rsa_encrypt(pub, data):
    return pub.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(priv, data):
    return priv.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# =========================
# HYBRID
# =========================
def hybrid_encrypt(pub, plaintext):
    session_key = os.urandom(32)

    aes = AESGCM(session_key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, plaintext, None)

    c_key = rsa_encrypt(pub, session_key)

    return c_key + nonce + ciphertext


def hybrid_decrypt(priv, package):
    c_key = package[:256]
    nonce = package[256:268]
    c_data = package[268:]

    session_key = rsa_decrypt(priv, c_key)

    aes = AESGCM(session_key)
    return aes.decrypt(nonce, c_data, None)


# =========================
# CLI
# =========================
parser = argparse.ArgumentParser()

parser.add_argument("mode", choices=["keygen", "encrypt", "decrypt"])
parser.add_argument("--name")
parser.add_argument("--pub")
parser.add_argument("--priv")
parser.add_argument("--infile")
parser.add_argument("--outfile")

args = parser.parse_args()

if args.mode == "keygen":
    generate_keypair(args.name)


elif args.mode == "encrypt":
    pub = load_public(args.pub)

    with open(args.infile, "rb") as f:
        data = f.read()

    start = time.perf_counter()
    enc = hybrid_encrypt(pub, data)
    end = time.perf_counter()

    with open(args.outfile, "wb") as f:
        f.write(enc)

    print("[OK] Enkripsi berhasil")
    print(f"Waktu enkripsi: {end - start:.6f} detik")


elif args.mode == "decrypt":
    priv = load_private(args.priv)

    with open(args.infile, "rb") as f:
        data = f.read()

    try:
        start = time.perf_counter()
        dec = hybrid_decrypt(priv, data)
        end = time.perf_counter()

        with open(args.outfile, "wb") as f:
            f.write(dec)

        print("[OK] Dekripsi berhasil")
        print(f"Waktu dekripsi: {end - start:.6f} detik")

    except Exception:
        print("[ERROR] Gagal decrypt / Auth Tag tidak valid!")