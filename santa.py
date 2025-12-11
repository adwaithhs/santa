#!/usr/bin/env python3
"""
Deterministic Secret Santa using Ed25519 -> Curve25519 conversion and SealedBox.

Workflow:
- register(name, password): derive deterministic Ed25519 key from password, store only the
  public verify key (base64) alongside the name in registry.json.
- generate_assignments(): creates a single-cycle assignment and encrypts each recipient's name
  with the santa's public key (so only that santa — who can reconstruct their private key
  from their password — can decrypt).
- decrypt_assignment(password, ciphertext_b64): recreate the private key from password and
  decrypt the sealed ciphertext.

Notes:
- Deterministic key derivation uses Scrypt to turn an arbitrary password into a 32-byte seed.
- We convert Ed25519 keys to Curve25519 (required for Box/SealedBox operations) using
  libsodium-compatible conversion via nacl.bindings.
"""

from __future__ import annotations
import json
import os
import base64
import random
from typing import List, Dict, Tuple, Any

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from nacl import signing, public, bindings, encoding as nacl_encoding
from nacl.public import SealedBox

REGISTRY_FILE = "registry.json"
ASSIGNMENTS_FILE = "assignments.json"


# ---------------------------
# Key derivation / helpers
# ---------------------------

def derive_seed_from_password(password: str, *, salt: bytes = b"secret-santa-fixed-salt") -> bytes:
    """
    Derive a 32-byte seed from a password using Scrypt.
    Use a fixed salt to keep derivation deterministic across runs for the same password.
    (If you want different behavior per event, include event-specific salt.)
    """
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())


def signing_key_from_seed(seed32: bytes) -> signing.SigningKey:
    """
    Create an Ed25519 SigningKey from a 32-byte seed deterministically.
    """
    if len(seed32) != 32:
        raise ValueError("seed must be 32 bytes")
    return signing.SigningKey(seed32)


def ed25519_verifykey_to_curve25519_pub(ed25519_pk: bytes) -> bytes:
    """
    Convert Ed25519 public key bytes (32) to Curve25519 public key bytes (32).
    """
    return bindings.crypto_sign_ed25519_pk_to_curve25519(ed25519_pk)


def ed25519_secret_to_curve25519_sk(ed25519_sk_seed32: bytes, ed25519_pk: bytes) -> bytes:
    """
    Convert Ed25519 secret key (seed32 + pubkey -> 64 bytes) to Curve25519 secret key (32 bytes).
    libsodium's conversion expects the 64-byte secret key (seed || pubkey).
    """
    if len(ed25519_sk_seed32) != 32 or len(ed25519_pk) != 32:
        raise ValueError("ed25519 seed and pubkey must be 32 bytes each")
    ed25519_sk_64 = ed25519_sk_seed32 + ed25519_pk
    return bindings.crypto_sign_ed25519_sk_to_curve25519(ed25519_sk_64)


def ed25519_seed_to_curve25519_keypair(seed32: bytes) -> Tuple[bytes, bytes]:
    """
    Given a 32-byte seed, return (curve25519_sk_bytes, curve25519_pk_bytes).
    """
    sk = signing_key_from_seed(seed32)
    vk = sk.verify_key
    ed_pk = vk.encode()   # 32 bytes
    curve_pk = ed25519_verifykey_to_curve25519_pub(ed_pk)
    curve_sk = ed25519_secret_to_curve25519_sk(sk.encode(), ed_pk)
    return curve_sk, curve_pk


# ---------------------------
# Registry management
# ---------------------------

def load_registry() -> List[Dict[str, str]]:
    if not os.path.exists(REGISTRY_FILE):
        return []
    with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_registry(registry: List[Dict[str, str]]) -> None:
    with open(REGISTRY_FILE, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2, ensure_ascii=False)


def register(name: str, password: str) -> None:
    """
    Register a participant: derive deterministic Ed25519 key from password and
    store name + base64-encoded verify_key (ed25519 public key) in the registry.
    Only the public key is stored.
    """
    seed = derive_seed_from_password(password)
    sk = signing_key_from_seed(seed)
    vk = sk.verify_key
    vk_b64 = base64.b64encode(vk.encode()).decode("ascii")  # store as base64 string

    registry = load_registry()
    registry.append({"name": name, "public_key_b64": vk_b64})
    save_registry(registry)


# ---------------------------
# Assignments
# ---------------------------

def generate_single_cycle(names: List[str]) -> Dict[str, str]:
    """
    Produce a single-cycle permutation mapping each giver -> receiver.
    e.g. for [A,B,C] return {A: B, B: C, C: A}
    """
    if len(names) < 2:
        raise ValueError("Need at least two participants")
    shuffled = names[:]
    random.shuffle(shuffled)
    return {shuffled[i]: shuffled[(i + 1) % len(shuffled)] for i in range(len(shuffled))}


def encrypt_for_santa(ed25519_verifykey_b64: str, message: str) -> str:
    """
    Encrypt 'message' for the owner of the given ed25519 verify key (base64).
    Returns base64 ciphertext of a SealedBox-encrypted blob (anonymous sender).
    """
    ed_pk = base64.b64decode(ed25519_verifykey_b64)
    curve_pk_bytes = ed25519_verifykey_to_curve25519_pub(ed_pk)
    curve_pub = public.PublicKey(curve_pk_bytes)
    sealed = SealedBox(curve_pub).encrypt(message.encode("utf-8"))
    return base64.b64encode(sealed).decode("ascii")


def generate_assignments() -> None:
    """
    Load registry, build a single-cycle assignment, encrypt each receiver name with
    the santa's public key, and write assignments to ASSIGNMENTS_FILE.
    """
    registry = load_registry()
    names = [entry["name"] for entry in registry]
    mapping = generate_single_cycle(names)

    output: List[Dict[str, str]] = []
    for entry in registry:
        santa = entry["name"]
        receiver = mapping[santa]
        enc = encrypt_for_santa(entry["public_key_b64"], receiver)
        output.append({"santa": santa, "encrypted_receiver_b64": enc})

    with open(ASSIGNMENTS_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)


# ---------------------------
# Decryption (by participant)
# ---------------------------

def decrypt_with_password(password: str, ciphertext_b64: str) -> str:
    """
    Given the participant's password (used at registration) reconstruct the Curve25519
    private key and decrypt the sealed box ciphertext (base64).
    Returns the plaintext string.
    """
    seed = derive_seed_from_password(password)
    curve_sk_bytes, _curve_pk = ed25519_seed_to_curve25519_keypair(seed)
    priv = public.PrivateKey(curve_sk_bytes)
    sealed = base64.b64decode(ciphertext_b64)
    plain = SealedBox(priv).decrypt(sealed)
    return plain.decode("utf-8")


# ---------------------------
# Utilities / Example test
# ---------------------------

def clear_files() -> None:
    for fn in (REGISTRY_FILE, ASSIGNMENTS_FILE):
        try:
            os.remove(fn)
        except FileNotFoundError:
            pass


def test_end_to_end() -> None:
    """
    Example test similar to your earlier test: register participants,
    generate assignments, then reconstruct each private key from password
    and decrypt the assigned receiver.
    """
    clear_files()
    names = ["One", "Two", "Three", "Four"]

    # Register using name.lower() as password (same pattern you used)
    for nm in names:
        register(nm, nm.lower())

    # Generate assignments (encrypt each receiver with santa's public key)
    generate_assignments()

    # Load assignments and demonstrate decryption
    with open(ASSIGNMENTS_FILE, "r", encoding="utf-8") as f:
        assignments = json.load(f)

    print("=== Assignments (encrypted) ===")
    for entry in assignments:
        print(entry["santa"])
        print(entry["encrypted_receiver_b64"])

    print("\n=== Decrypting using deterministic private keys ===")
    for entry in assignments:
        santa = entry["santa"]
        ciphertext_b64 = entry["encrypted_receiver_b64"]
        # participant reconstructs private key with same password used at registration:
        pwd = santa.lower()
        plaintext = decrypt_with_password(pwd, ciphertext_b64)
        print(f"{santa} -> {plaintext}")


# If module executed directly, run the test example
if __name__ == "__main__":
    test_end_to_end()
