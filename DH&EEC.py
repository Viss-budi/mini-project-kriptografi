from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


# 6.3 HKDF Derivation

def derive_keys(shared_secret: bytes, info: bytes = b"session-key") -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_secret)

# Generate Key Pair

def generate_keypair():
    private = X25519PrivateKey.generate()
    public = private.public_key()

    public_bytes = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return private, public_bytes


# Encrypt

def encrypt_message(sender_private, receiver_public_bytes, message: bytes):
    receiver_public = X25519PublicKey.from_public_bytes(receiver_public_bytes)

    # Shared secret
    shared_secret = sender_private.exchange(receiver_public)

    # Session key
    session_key = derive_keys(shared_secret)

    # AES-GCM
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message, None)

    return {
        "sender_pub": sender_private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        ),
        "nonce": nonce,
        "ciphertext": ciphertext
    }, shared_secret, session_key


# Decrypt

def decrypt_message(receiver_private, package):
    sender_pub = X25519PublicKey.from_public_bytes(package["sender_pub"])

    shared_secret = receiver_private.exchange(sender_pub)
    session_key = derive_keys(shared_secret)

    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(
        package["nonce"],
        package["ciphertext"],
        None
    )

    return plaintext, shared_secret, session_key


# MAIN SIMULASI
if __name__ == "__main__":

    # 1. Generate key pair
    alice_private, alice_public = generate_keypair()
    bob_private, bob_public = generate_keypair()

    print(f"[Alice] Public Key: {alice_public.hex()}")
    print(f"[Bob] Public Key: {bob_public.hex()}")

    # 2. Alice input pesan
    message = input("\n[Alice] Masukkan pesan: ").encode()

    # 3. Encrypt
    pkg, shared_alice, key_alice = encrypt_message(
        alice_private,
        bob_public,
        message
    )

    # 4. Decrypt
    plaintext, shared_bob, key_bob = decrypt_message(
        bob_private,
        pkg
    )

    print("\n=== HASIL ===")
    print(f"[Shared Secret] Alice: {shared_alice.hex()[:20]}... | Bob: {shared_bob.hex()[:20]}...")
    print(f"Sama? {shared_alice == shared_bob}")

    print(f"[Session Key] Alice: {key_alice.hex()[:20]}... | Bob: {key_bob.hex()[:20]}...")
    print(f"Sama? {key_alice == key_bob}")

    print(f"[Alice] Pesan asli: \"{message.decode()}\"")

    print(f"[Alice] Ciphertext: nonce={pkg['nonce'].hex()[:20]}... ct={pkg['ciphertext'].hex()[:20]}...")

    print(f"[Bob] Terdekripsi: \"{plaintext.decode()}\" ✓")

    # 5. Session baru (isolasi)
    print("\n=== SESSION BARU ===")

    bob_private_new, _ = generate_keypair()

    try:
        plaintext_new, _, _ = decrypt_message(bob_private_new, pkg)
        print("[ERROR] Pesan lama masih bisa dibaca:", plaintext_new.decode())
    except:
        print("[Session baru] Key berbeda → tidak bisa dekripsi pesan lama ✓")