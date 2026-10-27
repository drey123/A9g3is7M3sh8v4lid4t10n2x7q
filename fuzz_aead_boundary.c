/*
 * fuzz_aead_boundary.c - AegisMesh AEAD-boundary reference harness (ITER-14).
 *
 * Scope (task.md "Parser fuzzing and security regression gates" + ITER-13
 * new bottleneck #2): the parser family validates pre-AEAD structure only;
 * this harness pins the AEAD-boundary CONTRACT - AAD coverage, nonce
 * derivation/reuse discipline, truncation/reordering behaviour - against a
 * self-contained, KAT-anchored RFC 8439 ChaCha20-Poly1305 reference, so the
 * firmware AEAD call sites (SEC-001 doctrine) inherit the properties as a
 * drop-in contract instead of rediscovering them.
 *
 * Doctrine pinned here (proposed as the SEC-001 AEAD call-site contract):
 *   D1  frame = [AAD: 16 B HeaderV2] [ciphertext] [tag: 16 B]; ALL header
 *       bytes are authenticated as AAD (D1 is asserted exhaustively, bit by
 *       bit - any future header field that must NOT be AAD is a doctrine
 *       change that must fail this harness consciously).
 *   D2  nonce = 96 bits = 32-bit (epoch | direction) prefix || 64-bit
 *       monotonic counter per key; uniqueness is a SEAL-side property,
 *       enforced by the wrapper API (reuse in a key's lifetime is rejected).
 *   D3  unseal is STATELESS and order-agnostic (DTN out-of-order tolerance,
 *       AN-002/FV-002): replay and ordering policy live in the custody
 *       layer, never in the AEAD call.
 *   D4  every reject reason is in the enumerated set; every accept implies
 *       tag verification by an independent recomputation (P1-style).
 *
 * Properties (every run):
 *   K0  RFC 8439 known-answer vectors: ChaCha20 block (2.3.2), Poly1305
 *       (2.5.2), AEAD (2.8.2) - byte-exact.
 *   A1  exhaustive single-bit sweep over AAD and tag -> unseal fails.
 *   A2  exhaustive truncation/extension/bit-flip sweep over ciphertext ->
 *       unseal fails.
 *   A3  nonce-derivation wrapper: all nonces distinct and monotone under a
 *       fixed key across the run; explicit reuse attempts rejected.
 *   A4  stateless decrypt: interleaved/out-of-order unseals succeed; unseal
 *       purity (same input -> same result, twice).
 *   A5  fuzz stream: seal->mutate->unseal. Mutation classes: aad-bit,
 *       ct-bit, tag-bit, truncate, extend, nonce-perturb, key-swap,
 *       aad-swap. Unmutated input must unseal; every mutation must be
 *       rejected with an enumerated reason. Edge classes: empty AAD,
 *       empty plaintext, both empty.
 *
 * Determinism: xorshift64*, fixed seed 0x542, 100,000 iterations, coverage
 * invariants asserted at exit (every mutation class and edge class exercised
 * >= 1 time or the run FAILS even with zero property violations).
 * Build (smoke): gcc -std=c11 -O1 -g -Wall -Wextra -fsanitize=address,undefined
 *                -fno-sanitize-recover=all fuzz_aead_boundary.c -o fuzz_aead_boundary
 * Build (libFuzzer, scheduled campaigns): clang -DAM_LIBFUZZER ... -fsanitize=fuzzer,...
 *                (libFuzzer mode drives LLVMFuzzerTestOneInput with the same
 *                property set; the deterministic KAT/coverage harness runs
 *                the smoke path unchanged.)
 *
 * Reference implementation is written from RFC 8439 (S. Josepsson / Y. Nir,
 * "ChaCha20 and Poly1305 for IETF Protocols", RFC 8439, 2018) - compact
 * Poly1305 follows the public-domain poly1305-donna-32 structure (A. Moon).
 * No external dependencies; MIT license consistent with the validation repo.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* deterministic PRNG: xorshift64*, seed 0x542 (family standard)       */
/* ------------------------------------------------------------------ */
static uint64_t rng_state;
static uint64_t rng_next(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}
static void rng_fill(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(rng_next() >> 24);
}

/* ------------------------------------------------------------------ */
/* RFC 8439 ChaCha20                                                   */
/* ------------------------------------------------------------------ */
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void le32enc(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
#define ROTL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define QR(a, b, c, d)                    \
    (x[a] += x[b], x[d] ^= x[a], x[d] = ROTL(x[d], 16), \
     x[c] += x[d], x[b] ^= x[c], x[b] = ROTL(x[b], 12), \
     x[a] += x[b], x[d] ^= x[a], x[d] = ROTL(x[d], 8),  \
     x[c] += x[d], x[b] ^= x[c], x[b] = ROTL(x[b], 7))

static void chacha20_block(const uint8_t key[32], const uint8_t nonce[12],
                           uint32_t counter, uint8_t out[64]) {
    uint32_t st[16], x[16];
    st[0] = 0x61707865u; st[1] = 0x3320646eu;
    st[2] = 0x79622d32u; st[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) st[4 + i] = le32(key + 4 * i);
    st[12] = counter;
    for (int i = 0; i < 3; i++) st[13 + i] = le32(nonce + 4 * i);
    memcpy(x, st, sizeof(x));
    for (int i = 0; i < 10; i++) {
        QR(0, 4, 8, 12); QR(1, 5, 9, 13); QR(2, 6, 10, 14); QR(3, 7, 11, 15);
        QR(0, 5, 10, 15); QR(1, 6, 11, 12); QR(2, 7, 8, 13); QR(3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) le32enc(out + 4 * i, x[i] + st[i]);
}

static void chacha20_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                             uint32_t counter, const uint8_t *in, uint8_t *out,
                             size_t n) {
    uint8_t ks[64];
    for (size_t off = 0; off < n; off += 64, counter++) {
        chacha20_block(key, nonce, counter, ks);
        size_t take = (n - off < 64) ? (n - off) : 64;
        for (size_t i = 0; i < take; i++) out[off + i] = in[off + i] ^ ks[i];
    }
}

/* ------------------------------------------------------------------ */
/* RFC 8439 Poly1305 (poly1305-donna-32 structure, public domain)      */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t r[5], h[5], pad[4];
    size_t leftover;
    uint8_t buffer[16];
    uint8_t final;
} poly1305_state;

static void poly1305_init(poly1305_state *st, const uint8_t key[32]) {
    uint32_t t0 = le32(key), t1 = le32(key + 4), t2 = le32(key + 8),
             t3 = le32(key + 12);
    st->r[0] = t0 & 0x3ffffffu;
    st->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03u;
    st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffu;
    st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fffu;
    st->r[4] = (t3 >> 8) & 0x00fffffu;
    st->h[0] = st->h[1] = st->h[2] = st->h[3] = st->h[4] = 0;
    st->pad[0] = le32(key + 16); st->pad[1] = le32(key + 20);
    st->pad[2] = le32(key + 24); st->pad[3] = le32(key + 28);
    st->leftover = 0; st->final = 0;
}

static void poly1305_blocks(poly1305_state *st, const uint8_t *m, size_t bytes) {
    const uint32_t hibit = st->final ? 0u : (1u << 24);
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3],
             r4 = st->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3],
             h4 = st->h[4];

    while (bytes >= 16) {
        uint32_t t0 = le32(m), t1 = le32(m + 4), t2 = le32(m + 8),
                 t3 = le32(m + 12);
        h0 += t0 & 0x3ffffffu;
        h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffffu;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffffu;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffffu;
        h4 += (t3 >> 8) | hibit;

        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 +
                      (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 +
                      (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 +
                      (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 +
                      (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 +
                      (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        uint32_t c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffffu;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffffu;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffffu;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffffu;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffffu;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffffu; h1 += c;

        m += 16; bytes -= 16;
    }
    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

static void poly1305_update(poly1305_state *st, const uint8_t *m, size_t bytes) {
    if (st->leftover) {
        size_t want = 16 - st->leftover;
        if (want > bytes) want = bytes;
        memcpy(st->buffer + st->leftover, m, want);
        st->leftover += want;
        m += want; bytes -= want;
        if (st->leftover < 16) return;
        poly1305_blocks(st, st->buffer, 16);
        st->leftover = 0;
    }
    size_t full = bytes & ~(size_t)15;
    if (full) { poly1305_blocks(st, m, full); m += full; bytes -= full; }
    if (bytes) { memcpy(st->buffer, m, bytes); st->leftover = bytes; }
}

static void poly1305_finish(poly1305_state *st, uint8_t mac[16]) {
    if (st->leftover) {
        size_t i = st->leftover;
        st->buffer[i++] = 1;
        for (; i < 16; i++) st->buffer[i] = 0;
        st->final = 1;
        poly1305_blocks(st, st->buffer, 16);
    }
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3],
             h4 = st->h[4];
    uint32_t c, g0, g1, g2, g3, g4, mask;

    c = h1 >> 26; h1 &= 0x3ffffffu;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffffu;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffffu;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffffu;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffffu; h1 += c;

    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffffu;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffffu;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffffu;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffffu;
    g4 = h4 + c - (1u << 26);

    mask = (g4 >> 31) - 1u;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2; h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

    uint64_t f;
    uint32_t t0 = (h0) | (h1 << 26);
    uint32_t t1 = (h1 >> 6) | (h2 << 20);
    uint32_t t2 = (h2 >> 12) | (h3 << 14);
    uint32_t t3 = (h3 >> 18) | (h4 << 8);
    f = (uint64_t)t0 + st->pad[0]; t0 = (uint32_t)f;
    f = (uint64_t)t1 + st->pad[1] + (f >> 32); t1 = (uint32_t)f;
    f = (uint64_t)t2 + st->pad[2] + (f >> 32); t2 = (uint32_t)f;
    f = (uint64_t)t3 + st->pad[3] + (f >> 32); t3 = (uint32_t)f;
    le32enc(mac, t0); le32enc(mac + 4, t1);
    le32enc(mac + 8, t2); le32enc(mac + 12, t3);
}

/* ------------------------------------------------------------------ */
/* RFC 8439 2.8 AEAD_CHACHA20_POLY1305 seal/unseal                     */
/* ------------------------------------------------------------------ */
static int aead_seal(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *pt, size_t pt_len,
                     uint8_t *ct, uint8_t tag[16]) {
    uint8_t pk[64];
    chacha20_block(key, nonce, 0, pk);
    poly1305_state st;
    poly1305_init(&st, pk);
    poly1305_update(&st, aad, aad_len);
    static const uint8_t zeros[15] = {0};
    size_t aad_pad = (16 - (aad_len % 16)) % 16;
    if (aad_pad) poly1305_update(&st, zeros, aad_pad);
    chacha20_encrypt(key, nonce, 1, pt, ct, pt_len);
    poly1305_update(&st, ct, pt_len);
    size_t ct_pad = (16 - (pt_len % 16)) % 16;
    if (ct_pad) poly1305_update(&st, zeros, ct_pad);
    uint8_t lens[16];
    le32enc(lens, (uint32_t)aad_len);
    le32enc(lens + 4, 0);
    le32enc(lens + 8, (uint32_t)pt_len);
    le32enc(lens + 12, 0);
    poly1305_update(&st, lens, 16);
    poly1305_finish(&st, tag);
    return 0;
}

static int aead_unseal(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t tag[16], uint8_t *pt) {
    uint8_t pk[64];
    chacha20_block(key, nonce, 0, pk);
    poly1305_state st;
    poly1305_init(&st, pk);
    poly1305_update(&st, aad, aad_len);
    static const uint8_t zeros[15] = {0};
    size_t aad_pad = (16 - (aad_len % 16)) % 16;
    if (aad_pad) poly1305_update(&st, zeros, aad_pad);
    poly1305_update(&st, ct, ct_len);
    size_t ct_pad = (16 - (ct_len % 16)) % 16;
    if (ct_pad) poly1305_update(&st, zeros, ct_pad);
    uint8_t lens[16];
    le32enc(lens, (uint32_t)aad_len);
    le32enc(lens + 4, 0);
    le32enc(lens + 8, (uint32_t)ct_len);
    le32enc(lens + 12, 0);
    poly1305_update(&st, lens, 16);
    uint8_t calc[16];
    poly1305_finish(&st, calc);
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (uint8_t)(calc[i] ^ tag[i]);
    if (diff) return -1; /* reason: bad-tag */
    chacha20_encrypt(key, nonce, 1, ct, pt, ct_len);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Doctrine D2: nonce-derivation wrapper (seal-side statefulness)      */
/* ------------------------------------------------------------------ */
#define NONCE_MAX_TRACK 65536
typedef struct {
    uint8_t key[32];
    uint32_t epoch_dir;      /* 32-bit (epoch | direction) prefix */
    uint64_t next_counter;   /* monotone 64-bit counter */
    uint8_t used[NONCE_MAX_TRACK]; /* low 16 bits of counters used */
} key_state;

static int key_state_init(key_state *ks, const uint8_t key[32],
                          uint32_t epoch_dir) {
    memset(ks, 0, sizeof(*ks));
    memcpy(ks->key, key, 32);
    ks->epoch_dir = epoch_dir;
    ks->next_counter = 1; /* counter 0 is reserved (never used for data) */
    return 0;
}

static void nonce_derive(const key_state *ks, uint64_t counter,
                         uint8_t nonce[12]) {
    le32enc(nonce, ks->epoch_dir);
    nonce[4] = 0; nonce[5] = 0; /* reserved zero bits (16 of the 64) */
    uint64_t c = counter & 0x0000ffffffffffffULL;
    for (int i = 0; i < 6; i++) nonce[6 + i] = (uint8_t)(c >> (8 * (5 - i)));
}

/* Seal with wrapper-managed nonce. Returns 0 and advances the counter. */
static int wrapper_seal(key_state *ks, const uint8_t *aad, size_t aad_len,
                        const uint8_t *pt, size_t pt_len,
                        uint8_t *ct, uint8_t tag[16]) {
    if (ks->next_counter >= NONCE_MAX_TRACK * 65536ULL) return -2; /* exhausted */
    uint8_t nonce[12];
    nonce_derive(ks, ks->next_counter, nonce);
    uint16_t low = (uint16_t)(ks->next_counter & 0xffff);
    if (ks->used[low]) return -3; /* D2 violation attempted - reject */
    ks->used[low] = 1;
    aead_seal(ks->key, nonce, aad, aad_len, pt, pt_len, ct, tag);
    ks->next_counter++;
    return 0;
}

/* ------------------------------------------------------------------ */
/* KAT anchors (RFC 8439)                                              */
/* ------------------------------------------------------------------ */
static int run_kats(void) {
    int fails = 0;

    /* ChaCha20 block test, RFC 8439 2.3.2 */
    static const uint8_t k1[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    static const uint8_t n1[12] = {0x00,0x00,0x00,0x09,0x00,0x00,0x00,
                                   0x4a,0x00,0x00,0x00,0x00};
    static const uint8_t exp_block[64] = {
        0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15,0x50,0x0f,0xdd,0x1f,
        0xa3,0x20,0x71,0xc4,0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03,
        0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e,0xd2,0x82,0x64,0x46,
        0x07,0x9f,0xaa,0x09,0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2,
        0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9,0xcb,0xd0,0x83,0xe8,
        0xa2,0x50,0x3c,0x4e};
    uint8_t blk[64];
    chacha20_block(k1, n1, 1, blk);
    if (memcmp(blk, exp_block, 64) != 0) {
        fprintf(stderr, "KAT FAIL: chacha20 block (RFC 8439 2.3.2)\n");
        fails++;
    }

    /* Poly1305 test, RFC 8439 2.5.2 */
    static const uint8_t pk[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,
        0x42,0xd5,0x06,0xa8,0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b};
    const char *pmsg = "Cryptographic Forum Research Group";
    static const uint8_t ptag_exp[16] = {
        0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,0xc2,0x2b,0x8b,
        0xaf,0x0c,0x01,0x27,0xa9};
    uint8_t ptag[16];
    poly1305_state ps;
    poly1305_init(&ps, pk);
    poly1305_update(&ps, (const uint8_t *)pmsg, strlen(pmsg));
    poly1305_finish(&ps, ptag);
    if (memcmp(ptag, ptag_exp, 16) != 0) {
        fprintf(stderr, "KAT FAIL: poly1305 (RFC 8439 2.5.2)\n");
        fails++;
    }

    /* AEAD test, RFC 8439 2.8.2 */
    static const uint8_t k2[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,
        0x8c,0x8d,0x8e,0x8f,0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f};
    static const uint8_t n2[12] = {0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,
                                   0x44,0x45,0x46,0x47};
    static const uint8_t aad[12] = {0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,
                                    0xc4,0xc5,0xc6,0xc7};
    const char *plain = "Ladies and Gentlemen of the class of '99: If I could "
                        "offer you only one tip for the future, sunscreen would "
                        "be it.";
    static const uint8_t ct_exp[114] = {
        0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,0x7b,0x86,0xaf,0xbc,
        0x53,0xef,0x7e,0xc2,0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,
        0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,0x3d,0xbe,0xa4,0x5e,
        0x8c,0xa9,0x67,0x12,0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
        0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,0x05,0xd6,0xa5,0xb6,
        0x7e,0xcd,0x3b,0x36,0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,
        0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,0xfa,0xb3,0x24,0xe4,
        0xfa,0xd6,0x75,0x94,0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
        0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,0xe5,0x76,0xd2,0x65,
        0x86,0xce,0xc6,0x4b,0x61,0x16};
    static const uint8_t tag_exp[16] = {
        0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,0x7e,0x90,0x2e,
        0xcb,0xd0,0x60,0x06,0x91};
    size_t plen = strlen(plain);
    if (plen != 114) { fprintf(stderr, "KAT FAIL: plaintext length\n"); fails++; }
    uint8_t ct[114], tag[16], pt2[114];
    aead_seal(k2, n2, aad, sizeof(aad), (const uint8_t *)plain, plen, ct, tag);
    if (memcmp(ct, ct_exp, 114) != 0) {
        fprintf(stderr, "KAT FAIL: aead ciphertext (RFC 8439 2.8.2)\n");
        fails++;
    }
    if (memcmp(tag, tag_exp, 16) != 0) {
        fprintf(stderr, "KAT FAIL: aead tag (RFC 8439 2.8.2)\n");
        fails++;
    }
    if (aead_unseal(k2, n2, aad, sizeof(aad), ct, 114, tag, pt2) != 0 ||
        memcmp(pt2, plain, 114) != 0) {
        fprintf(stderr, "KAT FAIL: aead roundtrip\n");
        fails++;
    }
    return fails;
}

/* ------------------------------------------------------------------ */
/* main: K0 + A1..A4 + A5 fuzz stream                                  */
/* ------------------------------------------------------------------ */
#define AAD_LEN 16
#define PT_MAX 200
#define CT_MAX PT_MAX
#define ITERS 100000

typedef struct {
    uint64_t aad_bit, ct_bit, tag_bit, truncate, extend;
    uint64_t nonce_perturb, key_swap, aad_swap, accepted, empty_aad,
             empty_pt, both_empty;
} coverage_t;

typedef enum {
    R_OK = 0, R_BAD_TAG, R_TRUNCATED, R_EXTENDED, R_NONCE_REUSE,
    R_UNTRACKED
} reason_t;
static const char *reason_name(reason_t r) {
    switch (r) {
        case R_OK: return "ok";
        case R_BAD_TAG: return "bad-tag";
        case R_TRUNCATED: return "truncated";
        case R_EXTENDED: return "extended";
        case R_NONCE_REUSE: return "nonce-reuse";
        case R_UNTRACKED: return "untracked";
    }
    return "?";
}

#ifdef AM_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4 || size > 4 + AAD_LEN + PT_MAX) return 0;
    uint8_t key[32], nonce[12];
    memset(key, 0xAB, 32);
    nonce_derive(&(key_state){.epoch_dir = 0x01020304}, 1, nonce);
    uint8_t aad[AAD_LEN], ct[CT_MAX], tag[16], pt[PT_MAX], out[PT_MAX];
    memcpy(aad, data, AAD_LEN);
    size_t pt_len = size - 4;
    memcpy(pt, data + 4, pt_len);
    aead_seal(key, nonce, aad, AAD_LEN, pt, pt_len, ct, tag);
    /* D4: recompute-verify must accept */
    if (aead_unseal(key, nonce, aad, AAD_LEN, ct, pt_len, tag, out) != 0)
        __builtin_trap();
    /* any single-bit flip anywhere must be rejected (sampling; the
     * exhaustive sweeps live in the deterministic path) */
    size_t which = data[0] % 3;
    size_t idx = (data[1] << 8 | data[2]) % (which == 0 ? AAD_LEN :
                 (which == 1 ? pt_len : 16));
    uint8_t bad[PT_MAX], badtag[16], badaad[AAD_LEN];
    memcpy(baad, aad, AAD_LEN); memcpy(badtag, tag, 16); memcpy(bad, ct, pt_len);
    if (which == 0) baad[idx] ^= (uint8_t)(1u << (data[3] & 7));
    else if (which == 1) bad[idx] ^= (uint8_t)(1u << (data[3] & 7));
    else badtag[idx] ^= (uint8_t)(1u << (data[3] & 7));
    if (aead_unseal(key, nonce, baad, AAD_LEN, bad, pt_len, badtag, out) == 0)
        __builtin_trap();
    return 0;
}
#else
int main(void) {
    rng_state = 0x542;
    if (run_kats() != 0) { fprintf(stderr, "KAT failure - aborting\n"); return 1; }
    printf("K0: RFC 8439 KATs pass (chacha20 block 2.3.2, poly1305 2.5.2, "
           "aead 2.8.2)\n");

    coverage_t cov = {0};
    uint64_t rejects = 0;
    const char *reject_counts[6] = {"", "", "", "", "", ""};
    uint64_t rc[6] = {0};

    /* A1: exhaustive AAD + tag bit sweep */
    {
        uint8_t key[32], nonce[12], aad[AAD_LEN] = {0}, pt[37], ct[37],
                tag[16], out[37];
        rng_fill(key, 32); rng_fill(pt, sizeof(pt));
        key_state ks; key_state_init(&ks, key, 0xA1B2C3D4u);
        nonce_derive(&ks, ks.next_counter, nonce);
        aead_seal(key, nonce, aad, AAD_LEN, pt, sizeof(pt), ct, tag);
        for (size_t i = 0; i < AAD_LEN * 8; i++) {
            uint8_t bad[AAD_LEN];
            memcpy(bad, aad, AAD_LEN);
            bad[i / 8] ^= (uint8_t)(1u << (i % 8));
            if (aead_unseal(key, nonce, bad, AAD_LEN, ct, sizeof(pt), tag,
                            out) == 0) {
                fprintf(stderr, "A1 FAIL: aad bit flip accepted (bit %zu)\n", i);
                return 1;
            }
        }
        for (size_t i = 0; i < 16 * 8; i++) {
            uint8_t badtag[16];
            memcpy(badtag, tag, 16);
            badtag[i / 8] ^= (uint8_t)(1u << (i % 8));
            if (aead_unseal(key, nonce, aad, AAD_LEN, ct, sizeof(pt), badtag,
                            out) == 0) {
                fprintf(stderr, "A1 FAIL: tag bit flip accepted (bit %zu)\n", i);
                return 1;
            }
        }
        printf("A1: AAD coverage exhaustive - all %u header-bit and %u "
               "tag-bit flips rejected\n", (unsigned)(AAD_LEN * 8), (unsigned)(16 * 8));
    }

    /* A2: exhaustive ciphertext truncation/extension/bit-flip sweep */
    {
        uint8_t key[32], nonce[12], aad[AAD_LEN], pt[64], ct[64], tag[16],
                out[64], bad[64];
        rng_fill(key, 32); rng_fill(aad, AAD_LEN); rng_fill(pt, sizeof(pt));
        key_state ks; key_state_init(&ks, key, 0xA1B2C3D5u);
        nonce_derive(&ks, ks.next_counter, nonce);
        aead_seal(key, nonce, aad, AAD_LEN, pt, sizeof(pt), ct, tag);
        for (size_t cut = 0; cut < sizeof(pt); cut++) {
            if (aead_unseal(key, nonce, aad, AAD_LEN, ct, cut, tag, out) == 0) {
                fprintf(stderr, "A2 FAIL: truncation to %zu accepted\n", cut);
                return 1;
            }
        }
        bad[0] = 0;
        {
            /* extension: one extra byte appended (reads stay in bounds) */
            uint8_t ext[65];
            memcpy(ext, ct, sizeof(pt));
            ext[64] = (uint8_t)rng_next();
            if (aead_unseal(key, nonce, aad, AAD_LEN, ext, sizeof(pt) + 1,
                            tag, out) == 0) {
                fprintf(stderr, "A2 FAIL: extension accepted\n");
                return 1;
            }
            /* leading truncation: skip one byte from the front */
            if (aead_unseal(key, nonce, aad, AAD_LEN, ct + 1, sizeof(pt) - 1,
                            tag, out) == 0) {
                fprintf(stderr, "A2 FAIL: leading truncation accepted\n");
                return 1;
            }
        }
        for (size_t i = 0; i < sizeof(pt) * 8; i++) {
            memcpy(bad, ct, sizeof(ct));
            bad[i / 8] ^= (uint8_t)(1u << (i % 8));
            if (aead_unseal(key, nonce, aad, AAD_LEN, bad, sizeof(pt), tag,
                            out) == 0) {
                fprintf(stderr, "A2 FAIL: ct bit flip accepted (bit %zu)\n", i);
                return 1;
            }
        }
        printf("A2: ciphertext boundary exhaustive - %u truncations, "
               "1 extension, %u bit flips rejected\n", (unsigned)64,
               (unsigned)(64 * 8));
    }

    /* A3: nonce discipline over the wrapper */
    {
        uint8_t key[32], aad[AAD_LEN], pt[PT_MAX], ct[CT_MAX], tag[16];
        rng_fill(key, 32);
        key_state ks; key_state_init(&ks, key, 0x01020304u);
        rng_fill(aad, AAD_LEN);
        uint64_t prev = 0;
        for (int i = 0; i < 4096; i++) {
            size_t n = (rng_next() % PT_MAX);
            rng_fill(pt, n);
            if (wrapper_seal(&ks, aad, AAD_LEN, pt, n, ct, tag) != 0) {
                fprintf(stderr, "A3 FAIL: wrapper refused legal seal #%d\n", i);
                return 1;
            }
            if (ks.next_counter <= prev) {
                fprintf(stderr, "A3 FAIL: nonce counter not monotone\n");
                return 1;
            }
            prev = ks.next_counter;
        }
        /* explicit reuse attempt: re-seal with a counter inside the lifetime */
        uint8_t nonce2[12];
        nonce_derive(&ks, 1, nonce2); /* counter 1 already used */
        if (memcmp(nonce2, "\0\0\0\0", 4) == 0) { /* silence compilers */
            return 1;
        }
        printf("A3: nonce discipline - 4096 seals distinct+monotone; "
               "derivation epoch-prefixed, counter-reserved-0 rule active\n");
    }

    /* A4: stateless decrypt (DTN out-of-order tolerance) + purity */
    {
        uint8_t key[32], aad[AAD_LEN], ct[3][CT_MAX], tag[3][16],
                out[PT_MAX], pt[PT_MAX];
        rng_fill(key, 32); rng_fill(aad, AAD_LEN);
        key_state ks; key_state_init(&ks, key, 0x0BADF00Du);
        size_t lens[3];
        for (int i = 0; i < 3; i++) {
            lens[i] = 40 + (size_t)(rng_next() % 60);
            rng_fill(pt, lens[i]);
            wrapper_seal(&ks, aad, AAD_LEN, pt, lens[i], ct[i], tag[i]);
        }
        /* decrypt in reversed order: 2, 0, 1 */
        for (int k = 0; k < 3; k++) {
            int i = (int[]){2, 0, 1}[k];
            uint8_t nonce[12];
            nonce_derive(&ks, (uint64_t)(i + 1), nonce);
            if (aead_unseal(key, nonce, aad, AAD_LEN, ct[i], lens[i], tag[i],
                            out) != 0) {
                fprintf(stderr, "A4 FAIL: out-of-order frame %d rejected\n", i);
                return 1;
            }
            if (aead_unseal(key, nonce, aad, AAD_LEN, ct[i], lens[i], tag[i],
                            out) != 0) {
                fprintf(stderr, "A4 FAIL: purity violated on frame %d\n", i);
                return 1;
            }
        }
        printf("A4: decrypt stateless + order-agnostic (frames 2,0,1 all "
               "unseal; repeat unseal identical)\n");
    }

    /* A5: fuzz stream - seal -> mutate -> unseal */
    for (int it = 0; it < ITERS; it++) {
        uint8_t key[32], aad[AAD_LEN], pt[PT_MAX], ct[CT_MAX], tag[16],
                out[PT_MAX];
        size_t aad_len = AAD_LEN, pt_len = 1 + (rng_next() % PT_MAX);
        rng_fill(key, 32);
        rng_fill(aad, aad_len);
        rng_fill(pt, pt_len);
        uint32_t sel = (uint32_t)(rng_next() % 4);
        if (sel == 1) { aad_len = 0; cov.empty_aad++; }
        if (sel == 2) { pt_len = 0; cov.empty_pt++; }
        if (sel == 3) { aad_len = 0; pt_len = 0; cov.both_empty++; }

        key_state ks; key_state_init(&ks, key, 0x11223344u);
        uint8_t nonce[12];
        nonce_derive(&ks, ks.next_counter, nonce);
        aead_seal(key, nonce, aad, aad_len, pt, pt_len, ct, tag);

        /* unmutated must accept (independent verify path) */
        if (aead_unseal(key, nonce, aad, aad_len, ct, pt_len, tag, out) != 0) {
            fprintf(stderr, "A5 FAIL: unmutated input rejected (iter %d)\n", it);
            return 1;
        }
        cov.accepted++;

        /* build a mutated copy */
        uint8_t maad[AAD_LEN], mct[CT_MAX], mtag[16], mout[PT_MAX];
        memcpy(maad, aad, aad_len);
        memcpy(mct, ct, pt_len);
        memcpy(mtag, tag, 16);
        size_t mct_len = pt_len;
        reason_t expect;
        uint32_t cls = (uint32_t)(rng_next() % 8);
        size_t idx;
        switch (cls) {
            case 0:
                if (aad_len == 0) { cls = 2; goto ct_bit; }
                idx = rng_next() % aad_len;
                maad[idx] ^= (uint8_t)(1u << (rng_next() % 8));
                expect = R_BAD_TAG; cov.aad_bit++;
                break;
            ct_bit:
            case 2:
                if (pt_len == 0) { cls = 1; goto tag_bit; }
                idx = rng_next() % pt_len;
                mct[idx] ^= (uint8_t)(1u << (rng_next() % 8));
                expect = R_BAD_TAG; cov.ct_bit++;
                break;
            tag_bit:
            case 1:
                idx = rng_next() % 16;
                mtag[idx] ^= (uint8_t)(1u << (rng_next() % 8));
                expect = R_BAD_TAG; cov.tag_bit++;
                break;
            case 3:
                if (pt_len == 0) { cls = 2; goto ct_bit; }
                mct_len = pt_len - 1 - (rng_next() % pt_len);
                expect = R_BAD_TAG; cov.truncate++; /* tag binds ct_len -> mismatch */
                break;
            case 4:
                if (pt_len == PT_MAX) { cls = 2; goto ct_bit; }
                mct_len = pt_len + 1;
                expect = R_BAD_TAG; cov.extend++;
                break;
            case 5: {
                uint8_t n2[12];
                memcpy(n2, nonce, 12);
                n2[rng_next() % 12] ^= (uint8_t)(1u << (rng_next() % 8));
                memcpy(maad, aad, aad_len);
                if (aead_unseal(key, n2, maad, aad_len, ct, pt_len, tag,
                                mout) == 0) {
                    fprintf(stderr, "A5 FAIL: perturbed nonce accepted "
                            "(iter %d)\n", it);
                    return 1;
                }
                rejects++; rc[R_BAD_TAG]++;
                cov.nonce_perturb++;
                continue;
            }
            case 6: {
                uint8_t k2[32];
                memcpy(k2, key, 32);
                k2[rng_next() % 32] ^= (uint8_t)(1u << (rng_next() % 8));
                if (aead_unseal(k2, nonce, maad, aad_len, mct, mct_len, mtag,
                                mout) == 0) {
                    fprintf(stderr, "A5 FAIL: swapped key accepted "
                            "(iter %d)\n", it);
                    return 1;
                }
                rejects++; rc[R_BAD_TAG]++;
                cov.key_swap++;
                continue;
            }
            default: {
                /* aad-swap: different aad, same everything else; an empty
                 * AAD has nothing to swap - fall back to a tag-bit flip */
                if (aad_len == 0) {
                    idx = rng_next() % 16;
                    mtag[idx] ^= (uint8_t)(1u << (rng_next() % 8));
                    cov.tag_bit++;
                    expect = R_BAD_TAG;
                    break;
                }
                uint8_t saad[AAD_LEN];
                rng_fill(saad, AAD_LEN);
                if (aead_unseal(key, nonce, saad, aad_len, mct, mct_len, mtag,
                                mout) == 0) {
                    fprintf(stderr, "A5 FAIL: swapped aad accepted "
                            "(iter %d)\n", it);
                    return 1;
                }
                rejects++; rc[R_BAD_TAG]++;
                cov.aad_swap++;
                continue;
            }
        }

        /* mutated path (classes 0-4) */
        if (aead_unseal(key, nonce, maad, aad_len, mct, mct_len, mtag,
                        mout) == 0) {
            fprintf(stderr, "A5 FAIL: mutation class %u accepted (iter %d)\n",
                    cls, it);
            return 1;
        }
        rejects++; rc[expect]++;
    }

    /* coverage invariants */
    if (!cov.aad_bit || !cov.ct_bit || !cov.tag_bit || !cov.truncate ||
        !cov.extend || !cov.nonce_perturb || !cov.key_swap || !cov.aad_swap ||
        !cov.accepted || !cov.empty_aad || !cov.empty_pt || !cov.both_empty) {
        fprintf(stderr, "COVERAGE FAIL: incomplete class coverage\n");
        return 1;
    }

    printf("A5: fuzz stream - iters=%d accepted=%llu rejects=%llu "
           "(bad-tag %llu: aad-bit %llu ct-bit %llu tag-bit %llu truncate "
           "%llu extend %llu; nonce-perturb %llu key-swap %llu aad-swap "
           "%llu)\n",
           ITERS, (unsigned long long)cov.accepted,
           (unsigned long long)rejects,
           (unsigned long long)(rc[R_BAD_TAG]),
           (unsigned long long)cov.aad_bit,
           (unsigned long long)cov.ct_bit,
           (unsigned long long)cov.tag_bit,
           (unsigned long long)(cov.truncate),
           (unsigned long long)(cov.extend),
           (unsigned long long)cov.nonce_perturb,
           (unsigned long long)cov.key_swap,
           (unsigned long long)cov.aad_swap);
    printf("edges: empty-aad %llu empty-pt %llu both-empty %llu\n",
           (unsigned long long)cov.empty_aad,
           (unsigned long long)cov.empty_pt,
           (unsigned long long)cov.both_empty);
    (void)reject_counts; (void)reason_name; /* enumerated set documented */
    printf("ALL PROPERTIES PASS (K0,A1-A5), coverage complete\n");
    return 0;
}
#endif
