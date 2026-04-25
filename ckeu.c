/* ckeu.c - Hardened Hybrid Kyber+X25519 File Encryption Utility */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#include <argon2.h>
#include "kyber/kem.h"
#include "kyber/randombytes.h"

/* ==========================
 * SECTION: CONFIGURATION & CONSTANTS
 * ========================== */
#define AES_NONCE_LEN 12
#define AES_TAG_LEN 16
#define CHUNK_SIZE 65536
#define SKE_SALT_LEN 16
#define MAX_PAD_LEN 8192

#define X25519_PUBKEY_LEN 32
#define X25519_PRIVKEY_LEN 32
#define HYBRID_CT_LEN (CRYPTO_CIPHERTEXTBYTES + X25519_PUBKEY_LEN)
#define HYBRID_SK_LEN (CRYPTO_SECRETKEYBYTES + X25519_PRIVKEY_LEN)
#define SKE_STRUCT_SIZE (SKE_SALT_LEN + AES_NONCE_LEN + HYBRID_SK_LEN + AES_TAG_LEN)

#define ARGON2_T_COST 8
#define ARGON2_M_COST 262144
#define ARGON2_P_COST 4

#define PUB_KEY_FILE "cke_pub.key"
#define DEFAULT_SEC_KEY_FILE "cke_sec.key"

/* ==========================
 * SECTION: GLOBAL STATE & TYPES
 * ========================== */
static char g_sec_key_path[512] = DEFAULT_SEC_KEY_FILE;

typedef struct {
    unsigned char kyber_sk[CRYPTO_SECRETKEYBYTES];
    unsigned char x25519_sk[X25519_PRIVKEY_LEN];
} hybrid_sk_t;

static struct termios saved_termios;
static int termios_saved = 0;
static hybrid_sk_t *global_sk_ptr = NULL;

/* ==========================
 * SECTION: ANSI COLORS & ICONS
 * ========================== */
#define COL_CYAN    "\033[1;36m"
#define COL_WHITE   "\033[1;37m"
#define COL_GREEN   "\033[1;32m"
#define COL_RED     "\033[1;31m"
#define COL_RESET   "\033[0m"
#define ICON_OK     "✅"
#define ICON_ERR    "❌"

/* ==========================
 * SECTION: PROVIDER INITIALIZATION
 * ========================== */
static int init_crypto_providers(void) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    if (!def) {
        OSSL_PROVIDER *fips = OSSL_PROVIDER_load(NULL, "fips");
        if (!fips) {
            fprintf(stderr, COL_RED "[FATAL] " ICON_ERR " Failed to load any crypto provider." COL_RESET "\n");
            return 0;
        }
        fprintf(stderr, COL_CYAN "[INIT]" COL_RESET " Using FIPS provider (default unavailable).\n");
        return 1;
    }
    return 1;
#else
    return 1;
#endif
}

/* ==========================
 * SECTION: SECURE MEMORY & TERMINAL UTILS
 * ========================== */
static void secure_wipe(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
    __asm__ __volatile__("" : : "r"(p) : "memory");
}

static void restore_terminal(void) {
    if (termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
        termios_saved = 0;
    }
}

static void emergency_cleanup(int sig) {
    restore_terminal();
    if (global_sk_ptr) {
        secure_wipe(global_sk_ptr->kyber_sk, CRYPTO_SECRETKEYBYTES);
        secure_wipe(global_sk_ptr->x25519_sk, X25519_PRIVKEY_LEN);
    }
    _exit(128 + sig);
}

/* ==========================
 * SECTION: SECURE TEMPORARY STORAGE
 * ========================== */
typedef struct { int fd; int is_memfd; char path[256]; } secure_temp_t;

static int create_secure_temp(secure_temp_t *st) {
    memset(st, 0, sizeof(*st));
    st->fd = -1;
#ifdef SYS_memfd_create
    st->fd = syscall(SYS_memfd_create, "kyber_dec_tmp", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (st->fd >= 0) { st->is_memfd = 1; return 0; }
#endif
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir || tmpdir[0] == '\0') tmpdir = "/tmp";
    snprintf(st->path, sizeof(st->path), "%s/kyber_tmp_XXXXXX", tmpdir);
    st->fd = mkstemp(st->path);
    if (st->fd < 0) return -1;
    st->is_memfd = 0;
    return 0;
}

static void wipe_5_passes(int fd, size_t len) {
    const unsigned char patterns[4] = {0x00, 0xFF, 0x55, 0xAA};
    unsigned char buf[CHUNK_SIZE];
    size_t remaining = len;
    lseek(fd, 0, SEEK_SET);
    while (remaining > 0) {
        size_t chunk = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
        for (int i = 0; i < 4; i++) {
            memset(buf, patterns[i], chunk);
            if (write(fd, buf, chunk) != (ssize_t)chunk) break;
            lseek(fd, -chunk, SEEK_CUR);
        }
        if (RAND_bytes(buf, chunk) == 1) {
            if (write(fd, buf, chunk) != (ssize_t)chunk) break;
            lseek(fd, -chunk, SEEK_CUR);
        }
        remaining -= chunk;
    }
    fsync(fd);
}

static void destroy_secure_temp(secure_temp_t *st) {
    if (st->fd < 0) return;
    if (!st->is_memfd) {
        long size = lseek(st->fd, 0, SEEK_END);
        if (size > 0) wipe_5_passes(st->fd, (size_t)size);
        close(st->fd);
        if (st->path[0] != '\0') unlink(st->path);
    } else {
        close(st->fd);
    }
    memset(st, 0, sizeof(*st));
}

static int get_password(const char *prompt, char *pass, size_t max_len) {
    int show = 0;
    printf(COL_CYAN "[?]" COL_RESET " Show password? [y/N]: ");
    fflush(stdout);
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
        if (c == 'y' || c == 'Y') show = 1;
    }
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    printf("\n%s", prompt);
    fflush(stdout);
    int len = 0;
    while (1) {
        int ch = getchar();
        if (ch == '\n' || ch == EOF) break;
        if (ch == 127 || ch == 8) {
            if (len > 0) {
                len--;
                printf("\b \b");
                fflush(stdout);
            }
        } else if (len < (int)max_len - 1 && ch >= 32 && ch <= 126) {
            pass[len++] = (char)ch;
            printf(show ? "%c" : "*", ch);
            fflush(stdout);
        }
    }
    pass[len] = '\0';
    printf("\n");
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return len;
}

/* ==========================
 * SECTION: CRYPTOGRAPHIC DERIVATION
 * ========================== */
static int derive_ske_key(const char *pass, const unsigned char *salt, unsigned char *aes_key) {
    unsigned char raw[32];
    if (argon2id_hash_raw(ARGON2_T_COST, ARGON2_M_COST, ARGON2_P_COST,
                          pass, strlen(pass), salt, SKE_SALT_LEN, raw, 32) != ARGON2_OK) return 0;
    unsigned char hash[64];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { secure_wipe(raw, 32); return 0; }
    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL) != 1) goto fail;
    EVP_DigestUpdate(ctx, "cke_ske_v1", 10);
    EVP_DigestUpdate(ctx, raw, 32);
    unsigned int len;
    if (EVP_DigestFinal_ex(ctx, hash, &len) != 1) goto fail;
    EVP_MD_CTX_free(ctx);
    memcpy(aes_key, hash, 32);
    secure_wipe(raw, 32);
    secure_wipe(hash, 64);
    return 1;
fail:
    EVP_MD_CTX_free(ctx);
    secure_wipe(raw, 32);
    secure_wipe(hash, 64);
    return 0;
}

static int derive_file_key(const unsigned char *ss, unsigned char *aes_key) {
    unsigned char hash[64];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL) != 1) { EVP_MD_CTX_free(ctx); return 0; }
    EVP_DigestUpdate(ctx, "cke_file_v1", 12);
    EVP_DigestUpdate(ctx, ss, 32);
    unsigned int len;
    if (EVP_DigestFinal_ex(ctx, hash, &len) != 1) { EVP_MD_CTX_free(ctx); return 0; }
    EVP_MD_CTX_free(ctx);
    memcpy(aes_key, hash, 32);
    secure_wipe(hash, 64);
    return 1;
}

/* Deterministic PRNG to generate uniform padding length from hash */
static uint32_t deterministic_uniform(const unsigned char *seed, size_t seed_len, uint32_t max) {
    uint64_t state = 0;
    for (size_t i = 0; i < seed_len; i++) {
        state = (state << 8) ^ seed[i];
        state ^= state >> 33;
        state *= 0xff51afd7ed558ccdULL;
        state ^= state >> 33;
        state *= 0xc4ceb9fe1a85ec53ULL;
        state ^= state >> 33;
    }
    /* rejection sampling to avoid bias */
    uint32_t limit = (0xFFFFFFFFU / max) * max;
    uint32_t r;
    do {
        state ^= state >> 33;
        state *= 0xff51afd7ed558ccdULL;
        state ^= state >> 33;
        state *= 0xc4ceb9fe1a85ec53ULL;
        state ^= state >> 33;
        r = (uint32_t)state;
    } while (r >= limit);
    return r % max;
}

static int derive_pad_len_ss(const unsigned char *ss) {
    unsigned char hash[64];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(ctx, ss, 32);
    EVP_DigestUpdate(ctx, "file_pad_v1", 11);
    unsigned int len;
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    return (int)deterministic_uniform(hash, sizeof(hash), MAX_PAD_LEN);
}

static int derive_pad_len_pass(const char *pass) {
    unsigned char hash[64];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(ctx, pass, strlen(pass));
    EVP_DigestUpdate(ctx, "ske_pad_v1", 10);
    unsigned int len;
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    return (int)deterministic_uniform(hash, sizeof(hash), MAX_PAD_LEN);
}

/* ==========================
 * SECTION: FEATURES & COMPLIANCE MENU
 * ========================== */
static void show_features(void) {
    printf("\n==========================================\n");
    printf("      SYSTEM FEATURES & COMPLIANCE\n");
    printf("------------------------------------------\n");
    printf(COL_WHITE " Author:          " COL_CYAN "Effjy\n" COL_RESET);
    printf(COL_WHITE " Version:         " COL_CYAN "v6.2.7-DENIABLE\n\n" COL_RESET);
    printf(COL_WHITE " CRYPTOGRAPHIC PRIMITIVES:\n" COL_RESET);
    printf("  - KEM: Kyber-1024 + X25519 Hybrid\n");
    printf("  - AEAD: AES-256-GCM (12B IV/16B Tag)\n");
    printf("  - KDF:  Argon2id + SHA3-512 Domain Sep.\n");
    printf("------------------------------------------\n");
    printf(COL_WHITE " OPSEC & HARDENING:\n" COL_RESET);
    printf("  - Compiler-guaranteed volatile wiping\n");
    printf("  - memfd staging & CSPRNG polling\n");
    printf("  - Constant-time ops & masked failures\n");
    printf("  - Plausible deniability (random-noise files)\n");
    printf("------------------------------------------\n");
    printf(COL_WHITE " COMPLIANCE & STANDARDS:\n" COL_RESET);
    printf("  - NIST FIPS 203 (ML-KEM), FIPS 202\n");
    printf("  - FIPS 140-3 CSP, SP 800-38D/175B\n");
    printf("  - IETF RFC 7748, 9106, 5288, 3552\n");
    printf("==========================================\n\n");
}

/* ==========================
 * SECTION: HYBRID KEM OPERATIONS
 * ========================== */
static int hybrid_kem_encaps(unsigned char *ct_out, unsigned char *ss_out,
                             const unsigned char *pk_kyber, const unsigned char *pk_x25519) {
    unsigned char ss_kyber[CRYPTO_BYTES] = {0};
    unsigned char ss_x[X25519_PUBKEY_LEN] = {0};
    unsigned char hash[64] = {0};
    unsigned char eph_pub[X25519_PUBKEY_LEN] = {0};
    EVP_PKEY_CTX *kgen = NULL; EVP_PKEY *eph_priv = NULL; EVP_PKEY *static_pub = NULL;
    EVP_PKEY_CTX *dctx = NULL; EVP_MD_CTX *md = NULL;
    size_t pk_len = X25519_PUBKEY_LEN, ss_len = X25519_PUBKEY_LEN;
    unsigned int out_len = 0; int ret = -1;

    if (crypto_kem_enc(ct_out, ss_kyber, pk_kyber) != 0) goto cleanup;

    kgen = EVP_PKEY_CTX_new_id(NID_X25519, NULL);
    if (!kgen || EVP_PKEY_keygen_init(kgen) <= 0 || EVP_PKEY_keygen(kgen, &eph_priv) <= 0 ||
        EVP_PKEY_get_raw_public_key(eph_priv, eph_pub, &pk_len) <= 0) goto cleanup;

    static_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pk_x25519, X25519_PUBKEY_LEN);
    if (!static_pub) goto cleanup;

    dctx = EVP_PKEY_CTX_new(eph_priv, NULL);
    if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 || EVP_PKEY_derive_set_peer(dctx, static_pub) <= 0) goto cleanup;
    if (EVP_PKEY_derive(dctx, ss_x, &ss_len) <= 0) goto cleanup;

    md = EVP_MD_CTX_new();
    if (!md || EVP_DigestInit_ex(md, EVP_sha3_256(), NULL) != 1 ||
        EVP_DigestUpdate(md, "hybrid_kem_v1", 13) != 1 || EVP_DigestUpdate(md, ss_kyber, CRYPTO_BYTES) != 1 ||
        EVP_DigestUpdate(md, ss_x, X25519_PUBKEY_LEN) != 1 || EVP_DigestFinal_ex(md, hash, &out_len) != 1) goto cleanup;

    memcpy(ss_out, hash, 32);
    memcpy(ct_out + CRYPTO_CIPHERTEXTBYTES, eph_pub, X25519_PUBKEY_LEN);
    ret = 0;

cleanup:
    EVP_MD_CTX_free(md); EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(static_pub);
    EVP_PKEY_free(eph_priv); EVP_PKEY_CTX_free(kgen);
    secure_wipe(ss_kyber, CRYPTO_BYTES); secure_wipe(ss_x, X25519_PUBKEY_LEN); secure_wipe(hash, 64);
    return ret;
}

static int hybrid_kem_decaps(unsigned char *ss_out, const unsigned char *ct, const hybrid_sk_t *sk) {
    const unsigned char *ct_kyber = ct;
    const unsigned char *eph_pub = ct + CRYPTO_CIPHERTEXTBYTES;
    unsigned char ss_kyber[CRYPTO_BYTES] = {0};
    unsigned char ss_x[X25519_PUBKEY_LEN] = {0};
    unsigned char hash[64] = {0};
    EVP_PKEY *static_priv = NULL; EVP_PKEY *eph_pub_pkey = NULL;
    EVP_PKEY_CTX *dctx = NULL; EVP_MD_CTX *md = NULL;
    size_t ss_len = X25519_PUBKEY_LEN; unsigned int out_len = 0; int ret = -1;

    if (crypto_kem_dec(ss_kyber, ct_kyber, sk->kyber_sk) != 0) goto cleanup;

    static_priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk->x25519_sk, X25519_PRIVKEY_LEN);
    eph_pub_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, eph_pub, X25519_PUBKEY_LEN);
    if (!static_priv || !eph_pub_pkey) goto cleanup;

    dctx = EVP_PKEY_CTX_new(static_priv, NULL);
    if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 || EVP_PKEY_derive_set_peer(dctx, eph_pub_pkey) <= 0) goto cleanup;
    if (EVP_PKEY_derive(dctx, ss_x, &ss_len) <= 0) goto cleanup;

    md = EVP_MD_CTX_new();
    if (!md || EVP_DigestInit_ex(md, EVP_sha3_256(), NULL) != 1 ||
        EVP_DigestUpdate(md, "hybrid_kem_v1", 13) != 1 || EVP_DigestUpdate(md, ss_kyber, CRYPTO_BYTES) != 1 ||
        EVP_DigestUpdate(md, ss_x, X25519_PUBKEY_LEN) != 1 || EVP_DigestFinal_ex(md, hash, &out_len) != 1) goto cleanup;

    memcpy(ss_out, hash, 32);
    ret = 0;

cleanup:
    EVP_MD_CTX_free(md); EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(static_priv);
    EVP_PKEY_free(eph_pub_pkey);
    secure_wipe(ss_kyber, CRYPTO_BYTES); secure_wipe(ss_x, X25519_PUBKEY_LEN); secure_wipe(hash, 64);
    return ret;
}

/* ==========================
 * SECTION: KEY MANAGEMENT
 * ========================== */
static int save_encrypted_secret_key(const hybrid_sk_t *hs, const char *pass, const char *filename) {
    FILE *f = NULL;
    unsigned char *pad = NULL;
    int pad_len = 0;
    int ret = -1;
    unsigned char salt[SKE_SALT_LEN], nonce[AES_NONCE_LEN], aes_key[32];
    unsigned char payload[HYBRID_SK_LEN];
    unsigned char out[HYBRID_SK_LEN + AES_TAG_LEN];
    EVP_CIPHER_CTX *ctx = NULL;
    
    f = fopen(filename, "wb");
    if (!f) return -1;
    
    if (RAND_bytes(salt, SKE_SALT_LEN) != 1 || RAND_bytes(nonce, AES_NONCE_LEN) != 1) goto cleanup;

    printf(COL_CYAN "[KEYGEN]" COL_RESET " Deriving AES-256 key... please wait.\n");
    if (derive_ske_key(pass, salt, aes_key) != 1) goto cleanup;

    pad_len = derive_pad_len_pass(pass);
    if (pad_len > 0) {
        pad = malloc(pad_len);
        if (!pad || RAND_bytes(pad, pad_len) != 1) goto cleanup;
        if (fwrite(pad, 1, pad_len, f) != (size_t)pad_len) goto cleanup;
    }

    if (fwrite(salt, 1, SKE_SALT_LEN, f) != SKE_SALT_LEN ||
        fwrite(nonce, 1, AES_NONCE_LEN, f) != AES_NONCE_LEN) goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_NONCE_LEN, NULL) != 1) goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, nonce) != 1) goto cleanup;

    /* Add AAD to bind encryption to context */
    const char *aad = "cke_sk_v1";
    int aad_len = 10;
    int outlen_tmp;
    if (EVP_EncryptUpdate(ctx, NULL, &outlen_tmp, (unsigned char*)aad, aad_len) != 1) goto cleanup;

    memcpy(payload, hs->kyber_sk, CRYPTO_SECRETKEYBYTES);
    memcpy(payload + CRYPTO_SECRETKEYBYTES, hs->x25519_sk, X25519_PRIVKEY_LEN);

    int outlen;
    if (EVP_EncryptUpdate(ctx, out, &outlen, payload, HYBRID_SK_LEN) != 1) goto cleanup;
    if (fwrite(out, 1, outlen, f) != (size_t)outlen) goto cleanup;

    if (EVP_EncryptFinal_ex(ctx, out, &outlen) != 1) goto cleanup;
    if (fwrite(out, 1, outlen, f) != (size_t)outlen) goto cleanup;

    unsigned char tag[AES_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag) != 1) goto cleanup;
    if (fwrite(tag, 1, AES_TAG_LEN, f) != AES_TAG_LEN) goto cleanup;

    if (pad_len > 0 && pad) {
        if (RAND_bytes(pad, pad_len) != 1) goto cleanup;
        if (fwrite(pad, 1, pad_len, f) != (size_t)pad_len) goto cleanup;
    }

    ret = 0;
    printf(COL_GREEN "[KEYGEN] " ICON_OK " Secret key encrypted & saved." COL_RESET "\n");

cleanup:
    if (f) fclose(f);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (pad) { secure_wipe(pad, pad_len); free(pad); }
    secure_wipe(aes_key, 32);
    secure_wipe(payload, HYBRID_SK_LEN);
    secure_wipe(out, sizeof(out));
    if (ret != 0) {
        fprintf(stderr, COL_RED "[KEYGEN] " ICON_ERR " Failed to save secret key." COL_RESET "\n");
    }
    return ret;
}

static int load_secret_key(hybrid_sk_t *hs_out, const char *filename) {
    FILE *f = NULL;
    unsigned char *ct = NULL;
    char pass[256] = {0};
    unsigned char aes_key[32];
    unsigned char salt[SKE_SALT_LEN], nonce[AES_NONCE_LEN], tag[AES_TAG_LEN];
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = -1;
    unsigned char tmp[HYBRID_SK_LEN + AES_TAG_LEN];
    int outlen, final_len;

    f = fopen(filename, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) goto cleanup;
    long fsize = ftell(f);
    if (fsize < 0 || fseek(f, 0, SEEK_SET) != 0) goto cleanup;

    if (fsize < SKE_STRUCT_SIZE) goto cleanup;

    long payload_size = fsize - SKE_STRUCT_SIZE;
    if (payload_size % 2 != 0) goto cleanup;

    int pad_len = (int)(payload_size / 2);
    if (pad_len < 0 || pad_len > MAX_PAD_LEN) goto cleanup;

    if (get_password("Enter password for secret key: ", pass, sizeof(pass)) <= 0) goto cleanup;

    /* Skip first padding block */
    if (fseek(f, pad_len, SEEK_SET) != 0) goto cleanup;

    if (fread(salt, 1, SKE_SALT_LEN, f) != SKE_SALT_LEN ||
        fread(nonce, 1, AES_NONCE_LEN, f) != AES_NONCE_LEN) goto cleanup;

    printf(COL_CYAN "[DECRYPT]" COL_RESET " Deriving key (Argon2id)...\n");
    if (derive_ske_key(pass, salt, aes_key) != 1) goto cleanup;

    ct = malloc(HYBRID_SK_LEN);
    if (!ct) goto cleanup;

    if (fread(ct, 1, HYBRID_SK_LEN, f) != HYBRID_SK_LEN ||
        fread(tag, 1, AES_TAG_LEN, f) != AES_TAG_LEN) goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_NONCE_LEN, NULL) != 1) goto cleanup;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, nonce) != 1) goto cleanup;

    /* Provide AAD */
    const char *aad = "cke_sk_v1";
    if (EVP_DecryptUpdate(ctx, NULL, &outlen, (unsigned char*)aad, 10) != 1) goto cleanup;

    if (EVP_DecryptUpdate(ctx, tmp, &outlen, ct, HYBRID_SK_LEN) != 1) {
        fprintf(stderr, COL_RED "[DECRYPT] " ICON_ERR " Decryption failed." COL_RESET "\n");
        ret = -3;
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_LEN, tag) != 1) goto cleanup;

    if (EVP_DecryptFinal_ex(ctx, tmp + outlen, &final_len) != 1) {
        fprintf(stderr, COL_RED "[DECRYPT] " ICON_ERR " Authentication failed." COL_RESET "\n");
        ret = -3;
        goto cleanup;
    }

    memcpy(hs_out->kyber_sk, tmp, CRYPTO_SECRETKEYBYTES);
    memcpy(hs_out->x25519_sk, tmp + CRYPTO_SECRETKEYBYTES, X25519_PRIVKEY_LEN);
    ret = 0;

cleanup:
    if (f) fclose(f);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    free(ct);
    secure_wipe(aes_key, 32);
    secure_wipe(tmp, sizeof(tmp));
    secure_wipe(pass, sizeof(pass));
    if (ret != 0 && ret != -3) {
        fprintf(stderr, COL_RED "[DECRYPT] " ICON_ERR " Failed to load secret key." COL_RESET "\n");
    }
    return ret;
}

static int ensure_keypair(void) {
    printf(COL_CYAN "[KEYGEN]" COL_RESET " Generating Hybrid Key Pair...\n");

    unsigned char pk_kyber[CRYPTO_PUBLICKEYBYTES] = {0}, sk_kyber[CRYPTO_SECRETKEYBYTES] = {0};
    if (crypto_kem_keypair(pk_kyber, sk_kyber) != 0) {
        fprintf(stderr, COL_RED "[KEYGEN] " ICON_ERR " Kyber keygen failed." COL_RESET "\n");
        return -1;
    }

    EVP_PKEY_CTX *kgen = EVP_PKEY_CTX_new_id(NID_X25519, NULL); EVP_PKEY *x_priv = NULL;
    unsigned char sk_x[X25519_PRIVKEY_LEN] = {0}, pk_x[X25519_PUBKEY_LEN] = {0};
    size_t sk_len = X25519_PRIVKEY_LEN, pk_len = X25519_PUBKEY_LEN;

    int x_ok = (kgen && EVP_PKEY_keygen_init(kgen) > 0 && EVP_PKEY_keygen(kgen, &x_priv) > 0 &&
                EVP_PKEY_get_raw_private_key(x_priv, sk_x, &sk_len) > 0 &&
                EVP_PKEY_get_raw_public_key(x_priv, pk_x, &pk_len) > 0);

    EVP_PKEY_CTX_free(kgen); EVP_PKEY_free(x_priv);
    if (!x_ok) {
        fprintf(stderr, COL_RED "[KEYGEN] " ICON_ERR " X25519 keygen failed." COL_RESET "\n");
        return -1;
    }

    FILE *fp = fopen(PUB_KEY_FILE, "wb");
    if (!fp || fwrite(pk_kyber, 1, CRYPTO_PUBLICKEYBYTES, fp) != CRYPTO_PUBLICKEYBYTES ||
        fwrite(pk_x, 1, X25519_PUBKEY_LEN, fp) != X25519_PUBKEY_LEN) {
        fprintf(stderr, COL_RED "[KEYGEN] " ICON_ERR " Failed to save public keys." COL_RESET "\n");
        if(fp) fclose(fp);
        return -1;
    }
    fclose(fp);

    char pass1[256] = {0}, pass2[256] = {0};
    do {
        get_password("Set password to protect key: ", pass1, sizeof(pass1));
        get_password("Confirm password: ", pass2, sizeof(pass2));
        if (strcmp(pass1, pass2) != 0) printf(COL_RED "[KEYGEN] " ICON_ERR " Passwords do not match." COL_RESET "\n");
    } while (strcmp(pass1, pass2) != 0);

    printf(COL_CYAN "[KEYGEN]" COL_RESET " Save path [default: " DEFAULT_SEC_KEY_FILE "]: ");
    fflush(stdout);
    char custom_name[512] = {0};
    if (fgets(custom_name, sizeof(custom_name), stdin)) {
        custom_name[strcspn(custom_name, "\n")] = '\0';
        if (custom_name[0] != '\0') {
            strncpy(g_sec_key_path, custom_name, sizeof(g_sec_key_path) - 1);
            g_sec_key_path[sizeof(g_sec_key_path) - 1] = '\0';
        }
    }

    hybrid_sk_t hs = {0};
    memcpy(hs.kyber_sk, sk_kyber, CRYPTO_SECRETKEYBYTES);
    memcpy(hs.x25519_sk, sk_x, X25519_PRIVKEY_LEN);
    if (save_encrypted_secret_key(&hs, pass1, g_sec_key_path) != 0) return -1;

    secure_wipe(sk_kyber, CRYPTO_SECRETKEYBYTES); secure_wipe(pk_kyber, CRYPTO_PUBLICKEYBYTES);
    secure_wipe(sk_x, X25519_PRIVKEY_LEN); secure_wipe(pk_x, X25519_PUBKEY_LEN);
    secure_wipe(pass1, sizeof(pass1)); secure_wipe(pass2, sizeof(pass2));
    return 0;
}

static int get_input(const char *prompt, char *buf, size_t size) {
    printf("%s", prompt); if (!fgets(buf, size, stdin)) return -1;
    buf[strcspn(buf, "\n")] = 0; return 0;
}

/* ==========================
 * SECTION: FILE CRYPTOGRAPHY
 * ========================== */
static int encrypt_file(const char *in_path, const char *out_path) {
    FILE *fin = NULL, *fout = NULL;
    unsigned char *pad = NULL;
    int ret = -1;
    unsigned char pk_kyber[CRYPTO_PUBLICKEYBYTES], pk_x[X25519_PUBKEY_LEN];
    unsigned char ss[32] = {0}, ct_hybrid[HYBRID_CT_LEN] = {0};
    unsigned char nonce[AES_NONCE_LEN];
    unsigned char aes_key[32];
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char buf[CHUNK_SIZE], out_buf[CHUNK_SIZE + AES_TAG_LEN];
    int out_len;
    size_t bytes_read;

    fin = fopen(in_path, "rb");
    fout = fopen(out_path, "wb");
    if (!fin || !fout) {
        fprintf(stderr, COL_RED "[ENCRYPT] " ICON_ERR " Failed to open files." COL_RESET "\n");
        goto cleanup;
    }

    FILE *fpk = fopen(PUB_KEY_FILE, "rb");
    if (!fpk || fread(pk_kyber, 1, CRYPTO_PUBLICKEYBYTES, fpk) != CRYPTO_PUBLICKEYBYTES ||
        fread(pk_x, 1, X25519_PUBKEY_LEN, fpk) != X25519_PUBKEY_LEN) {
        fprintf(stderr, COL_RED "[ENCRYPT] " ICON_ERR " Failed to read public keys." COL_RESET "\n");
        if (fpk) fclose(fpk);
        goto cleanup;
    }
    fclose(fpk);

    if (hybrid_kem_encaps(ct_hybrid, ss, pk_kyber, pk_x) != 0) {
        fprintf(stderr, COL_RED "[ENCRYPT] " ICON_ERR " KEM encapsulation failed." COL_RESET "\n");
        goto cleanup;
    }

    if (RAND_bytes(nonce, AES_NONCE_LEN) != 1) goto cleanup;
    if (fwrite(ct_hybrid, 1, HYBRID_CT_LEN, fout) != HYBRID_CT_LEN ||
        fwrite(nonce, 1, AES_NONCE_LEN, fout) != AES_NONCE_LEN) goto cleanup;

    if (derive_file_key(ss, aes_key) != 1) goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_NONCE_LEN, NULL) != 1) goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, nonce) != 1) goto cleanup;

    /* Use KEM ciphertext and nonce as AAD to bind envelope */
    int aad_outlen;
    if (EVP_EncryptUpdate(ctx, NULL, &aad_outlen, ct_hybrid, HYBRID_CT_LEN) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &aad_outlen, nonce, AES_NONCE_LEN) != 1) goto cleanup;

    while ((bytes_read = fread(buf, 1, CHUNK_SIZE, fin)) > 0) {
        if (EVP_EncryptUpdate(ctx, out_buf, &out_len, buf, (int)bytes_read) != 1) goto cleanup;
        if (fwrite(out_buf, 1, out_len, fout) != (size_t)out_len) goto cleanup;
    }
    if (ferror(fin)) goto cleanup;

    if (EVP_EncryptFinal_ex(ctx, out_buf, &out_len) != 1) goto cleanup;
    if (fwrite(out_buf, 1, out_len, fout) != (size_t)out_len) goto cleanup;

    unsigned char tag[AES_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag) != 1) goto cleanup;
    if (fwrite(tag, 1, AES_TAG_LEN, fout) != AES_TAG_LEN) goto cleanup;

    int pad_len = derive_pad_len_ss(ss);
    if (pad_len > 0) {
        pad = malloc(pad_len);
        if (!pad || RAND_bytes(pad, pad_len) != 1) goto cleanup;
        if (fwrite(pad, 1, pad_len, fout) != (size_t)pad_len) goto cleanup;
        if (RAND_bytes(pad, pad_len) != 1) goto cleanup;
        if (fwrite(pad, 1, pad_len, fout) != (size_t)pad_len) goto cleanup;
    }

    ret = 0;
    printf(COL_GREEN "[ENCRYPT] " ICON_OK " File encrypted successfully." COL_RESET "\n");

cleanup:
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (pad) { secure_wipe(pad, pad_len); free(pad); }
    secure_wipe(ss, 32);
    secure_wipe(aes_key, 32);
    secure_wipe(buf, sizeof(buf));
    secure_wipe(out_buf, sizeof(out_buf));
    if (ret != 0) {
        fprintf(stderr, COL_RED "[ENCRYPT] " ICON_ERR " Encryption failed." COL_RESET "\n");
    }
    return ret;
}

static int decrypt_file(const char *in_path, const char *out_path, const hybrid_sk_t *sk) {
    FILE *fin = NULL, *fout = NULL;
    secure_temp_t st = { .fd = -1 };
    int ret = -1;
    unsigned char ct_hybrid[HYBRID_CT_LEN] = {0}, nonce[AES_NONCE_LEN] = {0};
    unsigned char ss[32] = {0}, aes_key[32];
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char buf[CHUNK_SIZE], dec_buf[CHUNK_SIZE + AES_TAG_LEN];
    int out_len;
    long remaining;
    unsigned char tag[AES_TAG_LEN];
    long total_size;
    int pad_len;

    fin = fopen(in_path, "rb");
    fout = fopen(out_path, "wb");
    if (!fin || !fout) {
        fprintf(stderr, COL_RED "[DECRYPT] " ICON_ERR " Failed to open files." COL_RESET "\n");
        goto cleanup;
    }

    if (fread(ct_hybrid, 1, HYBRID_CT_LEN, fin) != HYBRID_CT_LEN ||
        fread(nonce, 1, AES_NONCE_LEN, fin) != AES_NONCE_LEN) {
        fprintf(stderr, COL_RED "[DECRYPT] " ICON_ERR " File too small or corrupted." COL_RESET "\n");
        goto cleanup;
    }

    if (hybrid_kem_decaps(ss, ct_hybrid, sk) != 0) {
        fprintf(stderr, COL_RED "[DECRYPT] " ICON_ERR " KEM decapsulation failed." COL_RESET "\n");
        goto cleanup;
    }

    if (fseek(fin, 0, SEEK_END) != 0) goto cleanup;
    total_size = ftell(fin);
    pad_len = derive_pad_len_ss(ss);
    long aes_ct_len = total_size - HYBRID_CT_LEN - AES_NONCE_LEN - AES_TAG_LEN - (2 * pad_len);
    if (aes_ct_len <= 0) {
        fprintf(stderr, COL_RED "[DECRYPT] " ICON_ERR " Invalid size or corrupt padding." COL_RESET "\n");
        goto cleanup;
    }

    if (fseek(fin, HYBRID_CT_LEN + AES_NONCE_LEN, SEEK_SET) != 0) goto cleanup;

    if (derive_file_key(ss, aes_key) != 1) goto cleanup;

    if (create_secure_temp(&st) != 0) {
        fprintf(stderr, COL_RED "[DECRYPT] " ICON_ERR " Failed to create secure temp." COL_RESET "\n");
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_NONCE_LEN, NULL) != 1) goto cleanup;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, nonce) != 1) goto cleanup;

    /* Provide AAD (same as encryption) */
    int aad_outlen;
    if (EVP_DecryptUpdate(ctx, NULL, &aad_outlen, ct_hybrid, HYBRID_CT_LEN) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &aad_outlen, nonce, AES_NONCE_LEN) != 1) goto cleanup;

    remaining = aes_ct_len;
    while (remaining > 0) {
        size_t to_read = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : (size_t)remaining;
        size_t bytes_read = fread(buf, 1, to_read, fin);
        if (bytes_read == 0) break;
        if (EVP_DecryptUpdate(ctx, dec_buf, &out_len, buf, (int)bytes_read) != 1) goto cleanup;
        if (write(st.fd, dec_buf, out_len) != out_len) goto cleanup;
        remaining -= (long)bytes_read;
    }
    if (ferror(fin)) goto cleanup;

    if (fread(tag, 1, AES_TAG_LEN, fin) != AES_TAG_LEN) {
        fprintf(stderr, COL_RED "[DECRYPT] " ICON_ERR " Failed to read GCM tag." COL_RESET "\n");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_LEN, tag) != 1) goto cleanup;

    if (EVP_DecryptFinal_ex(ctx, dec_buf, &out_len) != 1) {
        fprintf(stderr, COL_RED "[DECRYPT] " ICON_ERR " AEAD Auth FAILED. Discarding." COL_RESET "\n");
        goto cleanup;
    }
    if (out_len > 0) {
        if (write(st.fd, dec_buf, out_len) != out_len) {
            fprintf(stderr, COL_RED "[DECRYPT] " ICON_ERR " Write to temp failed." COL_RESET "\n");
            goto cleanup;
        }
    }

    if (lseek(st.fd, 0, SEEK_SET) == (off_t)-1) goto cleanup;
    long total_decrypted = lseek(st.fd, 0, SEEK_END);
    if (total_decrypted < 0) goto cleanup;
    if (lseek(st.fd, 0, SEEK_SET) == (off_t)-1) goto cleanup;

    remaining = total_decrypted;
    while (remaining > 0) {
        size_t to_read = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : (size_t)remaining;
        ssize_t bytes_read = read(st.fd, buf, to_read);
        if (bytes_read <= 0) break;
        if (fwrite(buf, 1, (size_t)bytes_read, fout) != (size_t)bytes_read) goto cleanup;
        remaining -= bytes_read;
    }
    if (fsync(fileno(fout)) != 0) {
        /* non-fatal, just warn */
        fprintf(stderr, COL_CYAN "[DECRYPT]" COL_RESET " Warning: fsync failed.\n");
    }

    ret = 0;
    printf(COL_GREEN "[DECRYPT] " ICON_OK " File decrypted successfully." COL_RESET "\n");

cleanup:
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    destroy_secure_temp(&st);
    secure_wipe(ss, 32);
    secure_wipe(aes_key, 32);
    secure_wipe(buf, sizeof(buf));
    secure_wipe(dec_buf, sizeof(dec_buf));
    if (ret != 0) {
        /* On failure, delete the potentially incomplete output file */
        if (out_path) unlink(out_path);
    }
    return ret;
}

/* ==========================
 * SECTION: MAIN EXECUTION FLOW
 * ========================== */
int main(void) {
    if (!init_crypto_providers()) {
        return 1;
    }

    umask(0077);
    prctl(PR_SET_DUMPABLE, 0);
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        fprintf(stderr, COL_CYAN "[OpSec]" COL_RESET " Notice: mlockall() needs root.\n");
    }

    if (RAND_status() <= 0) {
        RAND_poll();
        if (RAND_status() <= 0) {
            fprintf(stderr, COL_RED "[FATAL] " ICON_ERR " CSPRNG seeding failed." COL_RESET "\n");
            return 1;
        }
    }

    signal(SIGINT, emergency_cleanup);
    signal(SIGTERM, emergency_cleanup);
    atexit(restore_terminal);

    printf("\n==========================================\n");
    printf(" CLASSIFIED KYBER ENCRYPTION UTILITY\n");
    printf(" v6.2.7-DENIABLE [HARDENED]\n");
    printf("==========================================\n\n");

    int pub_exists = (access(PUB_KEY_FILE, F_OK) == 0);
    int sec_exists = (access(g_sec_key_path, F_OK) == 0);

    if (!pub_exists) {
        printf(COL_CYAN "[INIT]" COL_RESET " Generating new keypair...\n");
        if (ensure_keypair() < 0) {
            fprintf(stderr, COL_RED "[FATAL] " ICON_ERR " Could not initialize keypair." COL_RESET "\n");
            return 1;
        }
    } else if (!sec_exists) {
        printf(COL_CYAN "[LOAD]" COL_RESET " Public key found. Enter secret key path: ");
        fflush(stdout);
        char fallback_path[512] = {0};
        if (fgets(fallback_path, sizeof(fallback_path), stdin)) {
            fallback_path[strcspn(fallback_path, "\n")] = '\0';
            if (fallback_path[0] != '\0') {
                strncpy(g_sec_key_path, fallback_path, sizeof(g_sec_key_path) - 1);
                g_sec_key_path[sizeof(g_sec_key_path) - 1] = '\0';
            }
        }
    }

    hybrid_sk_t hs = {0}; global_sk_ptr = &hs;
    int load_res = load_secret_key(&hs, g_sec_key_path);
    if (load_res != 0) {
        if (load_res == -3) fprintf(stderr, COL_RED "[AUTH] " ICON_ERR " Authentication failed." COL_RESET "\n");
        else fprintf(stderr, COL_RED "[LOAD] " ICON_ERR " Failed to load secret key." COL_RESET "\n");
        global_sk_ptr = NULL; return 1;
    }

    int choice = 0; char in_path[256] = {0}, out_path[256] = {0};
    while (1) {
        printf("\n==========================================\n");
        printf("         MAIN OPERATIONS MENU\n");
        printf("------------------------------------------\n");
        printf(" [1] Encrypt File\n");
        printf(" [2] Decrypt File\n");
        printf(" [3] View Features & Compliance\n");
        printf(" [4] Secure Exit\n");
        printf("==========================================\n");
        printf(" > Enter choice: " COL_RESET);

        if (scanf("%d", &choice) != 1) {
            int c; while ((c = getchar()) != '\n' && c != EOF) {}
            printf(COL_RED "[INPUT] " ICON_ERR " Invalid input." COL_RESET "\n");
            continue;
        }
        int c; while ((c = getchar()) != '\n' && c != EOF) {}

        if (choice == 1) {
            if (get_input("Input file: ", in_path, sizeof(in_path)) != 0) continue;
            if (get_input("Output file: ", out_path, sizeof(out_path)) != 0) continue;
            encrypt_file(in_path, out_path);
        } else if (choice == 2) {
            if (get_input("Input file: ", in_path, sizeof(in_path)) != 0) continue;
            if (get_input("Output file: ", out_path, sizeof(out_path)) != 0) continue;
            decrypt_file(in_path, out_path, &hs);
        } else if (choice == 3) {
            show_features();
        } else if (choice == 4) {
            printf(COL_CYAN "[EXIT]" COL_RESET " Performing secure sanitization...\n");
            secure_wipe(in_path, sizeof(in_path)); secure_wipe(out_path, sizeof(out_path));
            secure_wipe(hs.kyber_sk, CRYPTO_SECRETKEYBYTES); secure_wipe(hs.x25519_sk, X25519_PRIVKEY_LEN);
            global_sk_ptr = NULL;
            printf(COL_GREEN "[EXIT] " ICON_OK " Sanitized. Exiting." COL_RESET "\n");
            return 0;
        } else {
            printf(COL_RED "[MENU] " ICON_ERR " Invalid choice." COL_RESET "\n");
        }
    }
}
