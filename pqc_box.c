// pqc_box.c — KEM-DEM "sealed box" in C (liboqs + OpenSSL AES-256-GCM)
// Build (pkg-config): cc -O2 pqc_box.c $(pkg-config --cflags --libs liboqs openssl) -o pqc_box
// Usage:
//   ./pqc_box keygen [alg=ML-KEM-768] [keydir=keys]
//   ./pqc_box seal <infile> [outdir=out] [pk=keys/pk.bin] [alg=ML-KEM-768]
//   ./pqc_box open [outdir=out] [sk=keys/sk.bin] <outfile> [alg=ML-KEM-768]

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <errno.h>       // for errno, EEXIST
#include <sys/types.h>   // for mkdir on macOS/BSD
#include <sys/stat.h>    // for mkdir

#include <oqs/oqs.h>     // liboqs KEM API (OQS_KEM_new, _keypair, _encaps, _decaps)
#include <openssl/evp.h> // OpenSSL EVP (AES-GCM, HKDF)
#include <openssl/kdf.h>
#include <openssl/rand.h>

static int mkdir_p(const char *path) {
#ifdef _WIN32
    (void)path; return 1; // user creates dirs on Windows
#else
    return (mkdir(path, 0700) == 0) || (errno == EEXIST);
#endif
}

static uint8_t *read_all(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    uint8_t *buf = (uint8_t*)malloc((size_t)n);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *out_len = (size_t)n;
    return buf;
}

static int write_all(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    if (fwrite(buf, 1, len, f) != len) { fclose(f); return 0; }
    fclose(f); return 1;
}

// HKDF-SHA256 using OpenSSL EVP_KDF (derives an AES-256 key from KEM shared secret)
static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out_key, size_t out_len) {
    int ok = 0;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return 0;
    if (EVP_PKEY_derive_init(pctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len) <= 0) goto done;
    if (info && info_len) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) <= 0) goto done;
    }
    if (EVP_PKEY_derive(pctx, out_key, &out_len) <= 0) goto done;
    ok = 1;
done:
    EVP_PKEY_CTX_free(pctx);
    return ok;
}

// AES-256-GCM encrypt: outputs ciphertext and 16-byte tag
static int aes256gcm_encrypt(const uint8_t *key, const uint8_t *nonce, size_t nonce_len,
                             const uint8_t *in, size_t in_len,
                             uint8_t **out_ct, size_t *out_ct_len,
                             uint8_t tag[16]) {
    int ok = 0, len = 0, ct_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    *out_ct = (uint8_t*)malloc(in_len);
    if (!*out_ct) goto done;
    if (EVP_EncryptUpdate(ctx, *out_ct, &len, in, (int)in_len) != 1) goto done;
    ct_len = len;

    if (EVP_EncryptFinal_ex(ctx, *out_ct + ct_len, &len) != 1) goto done;
    ct_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto done;

    *out_ct_len = (size_t)ct_len;
    ok = 1;
done:
    if (!ok && *out_ct) { free(*out_ct); *out_ct = NULL; }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// AES-256-GCM decrypt: needs tag; returns plaintext
static int aes256gcm_decrypt(const uint8_t *key, const uint8_t *nonce, size_t nonce_len,
                             const uint8_t *ct, size_t ct_len,
                             const uint8_t tag[16],
                             uint8_t **out_pt, size_t *out_pt_len) {
    int ok = 0, len = 0, pt_len = 0, final_ok = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    *out_pt = (uint8_t*)malloc(ct_len);
    if (!*out_pt) goto done;
    if (EVP_DecryptUpdate(ctx, *out_pt, &len, ct, (int)ct_len) != 1) goto done;
    pt_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) goto done;
    final_ok = EVP_DecryptFinal_ex(ctx, *out_pt + pt_len, &len);
    if (final_ok != 1) goto done;
    pt_len += len;

    *out_pt_len = (size_t)pt_len;
    ok = 1;
done:
    if (!ok && *out_pt) { free(*out_pt); *out_pt = NULL; }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static const char *ALG_DEFAULT = "ML-KEM-768"; // older builds may prefer "Kyber768"

static int cmd_keygen(const char *alg, const char *keydir) {
    (void)mkdir_p(keydir);
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) { fprintf(stderr, "KEM not available: %s\n", alg); return 1; }
    uint8_t *pk = (uint8_t*)malloc(kem->length_public_key);
    uint8_t *sk = (uint8_t*)malloc(kem->length_secret_key);
    if (!pk || !sk) { fprintf(stderr, "alloc failed\n"); return 1; }
    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) { fprintf(stderr, "keypair failed\n"); return 1; }
    char p1[512], p2[512];
    snprintf(p1, sizeof p1, "%s/pk.bin", keydir);
    snprintf(p2, sizeof p2, "%s/sk.bin", keydir);
    if (!write_all(p1, pk, kem->length_public_key) || !write_all(p2, sk, kem->length_secret_key)) {
        fprintf(stderr, "write key files failed\n"); return 1;
    }
    printf("{\"alg\":\"%s\",\"pk_len\":%zu,\"sk_len\":%zu}\n", alg,
           (size_t)kem->length_public_key, (size_t)kem->length_secret_key);
    free(pk); free(sk); OQS_KEM_free(kem);
    return 0;
}

static int cmd_seal(const char *alg, const char *infile, const char *outdir, const char *pkpath) {
    (void)mkdir_p(outdir);
    size_t pk_len = 0, in_len = 0;
    uint8_t *pk = read_all(pkpath, &pk_len);
    if (!pk) { fprintf(stderr, "read pk failed\n"); return 1; }
    uint8_t *in = read_all(infile, &in_len);
    if (!in) { fprintf(stderr, "read infile failed\n"); free(pk); return 1; }

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) { fprintf(stderr, "KEM not available: %s\n", alg); free(pk); free(in); return 1; }
    if ((size_t)kem->length_public_key != pk_len) {
        fprintf(stderr, "pk length mismatch (got %zu, want %zu)\n", pk_len, (size_t)kem->length_public_key);
        OQS_KEM_free(kem); free(pk); free(in); return 1;
    }

    uint8_t *kem_ct = (uint8_t*)malloc(kem->length_ciphertext);
    uint8_t *shared = (uint8_t*)malloc(kem->length_shared_secret);
    if (!kem_ct || !shared) { fprintf(stderr, "alloc failed\n"); return 1; }
    if (OQS_KEM_encaps(kem, kem_ct, shared, pk) != OQS_SUCCESS) {
        fprintf(stderr, "encaps failed\n"); return 1;
    }

    // Derive AES-256 key via HKDF-SHA256 (domain-separated)
    uint8_t key[32];
    const uint8_t salt[] = "pqc_box_salt_v1";
    const uint8_t info[] = "ML-KEM sealed box AES-256-GCM key";
    if (!hkdf_sha256(shared, kem->length_shared_secret, salt, sizeof(salt)-1, info, sizeof(info)-1, key, sizeof key)) {
        fprintf(stderr, "HKDF failed\n"); return 1;
    }

    // Encrypt with AES-256-GCM
    uint8_t nonce[12];
    if (RAND_bytes(nonce, sizeof nonce) != 1) { fprintf(stderr, "RAND_bytes failed\n"); return 1; }
    uint8_t *ct = NULL, tag[16]; size_t ct_len = 0;
    if (!aes256gcm_encrypt(key, nonce, sizeof nonce, in, in_len, &ct, &ct_len, tag)) {
        fprintf(stderr, "AES-GCM encrypt failed\n"); return 1;
    }

    char p_ct[512], p_nonce[512], p_tag[512], p_kem[512];
    snprintf(p_ct, sizeof p_ct, "%s/cipher.bin", outdir);
    snprintf(p_nonce, sizeof p_nonce, "%s/nonce.bin", outdir);
    snprintf(p_tag, sizeof p_tag, "%s/tag.bin", outdir);
    snprintf(p_kem, sizeof p_kem, "%s/kem.bin", outdir);

    int ok = write_all(p_ct, ct, ct_len) &&
             write_all(p_nonce, nonce, sizeof nonce) &&
             write_all(p_tag, tag, sizeof tag) &&
             write_all(p_kem, kem_ct, kem->length_ciphertext);
    if (!ok) { fprintf(stderr, "write outputs failed\n"); return 1; }

    printf("{\"ok\":true,\"alg\":\"%s\",\"cipher_len\":%zu,\"kem_ct_len\":%zu}\n",
           alg, ct_len, (size_t)kem->length_ciphertext);

    free(ct); free(kem_ct); free(shared); free(pk); free(in); OQS_KEM_free(kem);
    return 0;
}

static int cmd_open(const char *alg, const char *outdir, const char *skpath, const char *outfile) {
    size_t sk_len=0, kem_len=0, nonce_len=0, tag_len=0, ct_len=0;
    char p_ct[512], p_nonce[512], p_tag[512], p_kem[512];

    snprintf(p_ct, sizeof p_ct, "%s/cipher.bin", outdir);
    snprintf(p_nonce, sizeof p_nonce, "%s/nonce.bin", outdir);
    snprintf(p_tag, sizeof p_tag, "%s/tag.bin", outdir);
    snprintf(p_kem, sizeof p_kem, "%s/kem.bin", outdir);

    uint8_t *sk = read_all(skpath, &sk_len);
    uint8_t *kem_ct = read_all(p_kem, &kem_len);
    uint8_t *nonce = read_all(p_nonce, &nonce_len);
    uint8_t *tag = read_all(p_tag, &tag_len);
    uint8_t *ct = read_all(p_ct, &ct_len);

    if (!sk || !kem_ct || !nonce || !tag || !ct) { fprintf(stderr, "read inputs failed\n"); return 1; }
    if (nonce_len != 12 || tag_len != 16) { fprintf(stderr, "nonce/tag size mismatch\n"); return 1; }

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) { fprintf(stderr, "KEM not available: %s\n", alg); return 1; }
    if ((size_t)kem->length_secret_key != sk_len || (size_t)kem->length_ciphertext != kem_len) {
        fprintf(stderr, "sk/kem sizes mismatch\n"); return 1;
    }

    uint8_t *shared = (uint8_t*)malloc(kem->length_shared_secret);
    if (!shared) { fprintf(stderr, "alloc failed\n"); return 1; }
    if (OQS_KEM_decaps(kem, shared, kem_ct, sk) != OQS_SUCCESS) {
        fprintf(stderr, "decaps failed\n"); return 1;
    }

    uint8_t key[32];
    const uint8_t salt[] = "pqc_box_salt_v1";
    const uint8_t info[] = "ML-KEM sealed box AES-256-GCM key";
    if (!hkdf_sha256(shared, kem->length_shared_secret, salt, sizeof(salt)-1, info, sizeof(info)-1, key, sizeof key)) {
        fprintf(stderr, "HKDF failed\n"); return 1;
    }

    uint8_t *pt = NULL; size_t pt_len = 0;
    if (!aes256gcm_decrypt(key, nonce, nonce_len, ct, ct_len, tag, &pt, &pt_len)) {
        fprintf(stderr, "AES-GCM decrypt failed (bad key/tag?)\n"); return 1;
    }

    if (!write_all(outfile, pt, pt_len)) { fprintf(stderr, "write outfile failed\n"); return 1; }
    printf("{\"ok\":true,\"plain_len\":%zu}\n", pt_len);

    free(pt); free(shared); free(sk); free(kem_ct); free(nonce); free(tag); free(ct); OQS_KEM_free(kem);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage:\n  %s keygen [alg] [keydir]\n  %s seal <infile> [outdir] [pk] [alg]\n  %s open [outdir] [sk] <outfile> [alg]\n",
                argv[0], argv[0], argv[0]);
        return 1;
    }
    const char *cmd = argv[1];
    const char *alg = ALG_DEFAULT;

    if (!strcmp(cmd, "keygen")) {
        const char *alg_arg = (argc >= 3 && argv[2][0] != 0) ? argv[2] : ALG_DEFAULT;
        const char *dir_arg = (argc >= 4 && argv[3][0] != 0) ? argv[3] : "keys";
        return cmd_keygen(alg_arg, dir_arg);
    } else if (!strcmp(cmd, "seal")) {
        if (argc < 3) { fprintf(stderr, "seal needs <infile>\n"); return 1; }
        const char *infile = argv[2];
        const char *outdir = (argc >= 4) ? argv[3] : "out";
        const char *pk = (argc >= 5) ? argv[4] : "keys/pk.bin";
        alg = (argc >= 6) ? argv[5] : ALG_DEFAULT;
        return cmd_seal(alg, infile, outdir, pk);
    } else if (!strcmp(cmd, "open")) {
        const char *outdir = (argc >= 3) ? argv[2] : "out";
        const char *sk = (argc >= 4) ? argv[3] : "keys/sk.bin";
        if (argc < 5) { fprintf(stderr, "open needs <outfile>\n"); return 1; }
        const char *outfile = argv[4];
        alg = (argc >= 6) ? argv[5] : ALG_DEFAULT;
        return cmd_open(alg, outdir, sk, outfile);
    } else {
        fprintf(stderr, "unknown command: %s\n", cmd);
        return 1;
    }
}
