[![C](https://img.shields.io/badge/C-00599C?style=flat-square&logo=c&logoColor=white)]()
[![Kyber-1024](https://img.shields.io/badge/KEM-Kyber--1024-blue?style=flat-square)]()
[![X25519](https://img.shields.io/badge/ECDH-X25519-green?style=flat-square)]()
[![AES-256-GCM](https://img.shields.io/badge/AEAD-AES--256--GCM-lightgrey?style=flat-square)]()
[![Argon2id](https://img.shields.io/badge/KDF-Argon2id-orange?style=flat-square)]()
[![OpenSSL 3.0+](https://img.shields.io/badge/OpenSSL-3.0%2B-blueviolet?style=flat-square)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)]()

# 🛡️ Classified Kyber Encryption Utility (CKEU)

**CKEU** is a hardened, deniable file‑encryption tool that combines **post‑quantum Kyber‑1024** with **classical X25519** in a hybrid KEM, then protects the actual data with **AES‑256‑GCM**.  
The secret key is stored encrypted (Argon2id + AES‑256‑GCM + padding), and *plausible deniability* is achieved through cryptographic padding so that files look like random noise.

It follows government & IETF standards (FIPS 203, FIPS 202, RFC 7748, RFC 9106) and is built with constant‑time operations, `memfd` staging, memory locking, and aggressive zeroisation.

---

## ✨ Features

- 🔐 **Hybrid KEM** – Kyber‑1024 + X25519 → 256‑bit shared secret  
- ⚔️ **AEAD** – AES‑256‑GCM (12 B nonce, 16 B tag) with AAD binding  
- 🔑 **Key storage** – secret key encrypted with **Argon2id** + AES‑256‑GCM, then padded  
- 🧹 **Memory safety** – `mlock`/`MADV_DONTDUMP`, `memfd` staging, `OPENSSL_cleanse`  
- 🥷 **Deniability** – random padding before and after the ciphertext (deterministic length)  
- 📜 **Compliance** – NIST FIPS 203 (ML‑KEM), FIPS 202 (SHA‑3), SP 800‑38D/175B, RFC 7748/9106  
- 🧪 **Constant‑time** – masked comparisons, no early exits on failure  
- 📊 **Progress feedback** and colour‑coded status  

---

## 🔧 Build

**Dependencies:**  
- OpenSSL ≥ 3.0 (for SHA‑3, AES‑GCM, X25519)  
- libargon2 (for Argon2id)  
- A recent GCC or Clang (C11)  

The source includes a `kyber/` subdirectory with the reference implementation of Kyber‑1024.  
Compile everything with:

```bash
gcc -O2 -Wall -Wextra -Werror -std=c99 -DKYBER_K=4 -I. -Ikyber \
    ckeu.c \
    kyber/cbd.c kyber/fips202.c kyber/indcpa.c kyber/kem.c \
    kyber/ntt.c kyber/poly.c kyber/polyvec.c kyber/reduce.c \
    kyber/symmetric-shake.c kyber/verify.c kyber/randombytes.c \
    -DOPENSSLDIR="\"/dev/null\"" \
    -DENGINESDIR="\"/dev/null\"" \
    -DMODULESDIR="\"/dev/null\"" \
    -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -fno-builtin-memset -fno-strict-aliasing \
    -Wl,-z,relro,-z,now \
    -Wl,-Bstatic -lcrypto -largon2 -Wl,-Bdynamic \
    -latomic -lpthread -ldl -lm -lc \
    -s -o ckeu
```

After compilation, strip further if desired:
```bash
strip --strip-all --remove-section=.comment --remove-section=.note --remove-section=.gnu.version ckeu
```

---

## 🖥️ Usage

Run `./ckeu`. The program checks for existing public and secret keys; if none are found, it will generate them automatically.

```
==========================================
 CLASSIFIED KYBER ENCRYPTION UTILITY
 v6.2.7-DENIABLE [HARDENED]
==========================================

 MAIN OPERATIONS MENU
------------------------------------------
 [1] Encrypt File
 [2] Decrypt File
 [3] View Features & Compliance
 [4] Secure Exit
 > Enter choice:
```

### 🔑 Key Management

- **Public key** is stored in `cke_pub.key` (Kyber + X25519).  
- **Secret key** is encrypted with a **password** (Argon2id → AES‑256‑GCM) and saved as `cke_sec.key` (or a custom path).  
- The encrypted secret key is padded with random data to make its size and existence harder to identify.

### 🔒 Encryption

1. Loads the recipient’s public key.  
2. Performs hybrid KEM (Kyber‑1024 + X25519) → 32‑byte shared secret.  
3. Derives a 256‑bit AES key via SHA3‑512 domain‑separated hash.  
4. Encrypts the file with AES‑256‑GCM (AAD includes the KEM ciphertext + nonce).  
5. Appends deterministic random padding before and after the ciphertext.  

Result: a file that appears as random noise.

### 🔓 Decryption

1. Loads the user’s password → decrypts the secret key (after Argon2id).  
2. Extracts the KEM ciphertext & nonce from the file.  
3. Decapsulates the shared secret (Kyber + X25519).  
4. Derives the same AES key.  
5. Verifies GCM authentication tag; if correct, decrypts to a secure temporary file.  
6. Commits the clean plaintext to disk (and wipes temp).  

On AEAD failure, the output is automatically deleted.

---

## 📜 Compliance & Standards

| Standard | Implementation |
|:---------|:---------------|
| **NIST FIPS 203** | ML‑KEM (Kyber‑1024) |
| **NIST FIPS 202** | SHA‑3‑512 (and SHA3‑256) |
| **NIST SP 800‑38D** | AES‑256‑GCM with AAD |
| **NIST SP 800‑175B** | Guidelines for using symmetric crypto |
| **RFC 7748** | X25519 key agreement |
| **RFC 9106** | Argon2id memory‑hard KDF |
| **RFC 5288** | AES‑GCM AEAD for TLS (used as standalone AE) |

---

## 🧹 Security & OpSec

- **All sensitive memory** is zeroed with `volatile` barriers.  
- `mlockall(MCL_CURRENT|MCL_FUTURE)` prevents swapping (requires root).  
- Temporary decrypted data is written into a **memfd** or securely erased temporary file (5‑pass wipe).  
- **Constant‑time comparisons** for MAC/tag verification – no oracle.  
- **Plausible deniability** – file sizes are randomised with deterministic padding; an adversary cannot distinguish an encrypted file from random noise.  

---

## ⚠️ Important Notes

- The public key must be distributed **out‑of‑band** and trusted.  
- The secret key password should be strong and never stored alongside the key file.  
- The program is **research‑grade**; a full third‑party audit has not been performed.  
- **Kyber‑1024** (category 5) offers the highest margin against quantum attacks, but computational cost is higher than lighter variants.  
- On Linux, `mlock` may require `CAP_IPC_LOCK` or root; the tool warns if it fails.  

---

## 📄 License

MIT – see [LICENSE](LICENSE).  

---

*Post‑quantum. Deniable. Battle‑ready.* 🛡️💎
```
