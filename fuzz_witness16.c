// ============================================================================
// fuzz_witness16.c - AegisMesh 16-byte witness-receipt parser fuzz harness
//                    (ITER-13, harness family item 2 of 4).
//
// Owner mandate (task.md "Parser fuzzing and security regression gates"):
// "CI runs a smoke fuzz of at least 100,000 iterations per push for each
// harness, with bounded runtime and reproducible seeds where supported."
//
// Parser under test: the 16-byte witness receipt (MAC-006, research1.md
// ITER-2 §1.2(d): "Every Class-B/C relay ... emits a 16 B witness receipt
// (8 B msg-id hash + 4 B hop MAC + 4 B CRC) on the witness channel").
// MAC-007 (research1.md ITER-3) adds dual-channel rotation of the CARRIER
// channel; the receipt FORMAT is unchanged, so this harness covers both.
//
// Layout (16 B, fixed):
//   [0:8]   msg-id hash (opaque 8 B)
//   [8:12]  hop MAC    (opaque 4 B; authenticity is verified AFTER MAC
//                       admission + authentication, never by this parser -
//                       documented ordering: "MAC admission -> authentication
//                       -> custody acceptance", research2.md ITER-8 (c))
//   [12:16] CRC-32 (IEEE, little-endian) over bytes [0:12]
//
// Trust-plane relevance: the trust detector (TR-003/TR-004/TR-005) counts
// receipt presence/absence; a parser that accepted a structurally invalid
// receipt could forge or erase relay evidence. Structural validity is a
// precondition for the evidence plane, hence this harness.
//
// Properties asserted on EVERY iteration (violation = exit 1):
//   P1 accepted  => len == 16 and CRC-32 over [0:12] equals bytes [12:16]
//   P2 rejected  => reason code in the enumerated set {bad-length, bad-crc}
//   P3 parse() never reads outside [buf, buf+len)   (checked under ASan/UBSan)
//   P4 parse() is a pure function of (buf, len)     (re-parse identical)
//
// Deterministic: xorshift64* PRNG, fixed seed 0x542.  100,000 iterations.
// Build (CI): gcc -std=c11 -O1 -g -fsanitize=address,undefined
//             -fno-sanitize-recover=all fuzz_witness16.c -o fuzz_witness16
// libFuzzer-compatible: build with -DAM_LIBFUZZER -fsanitize=fuzzer to get
// LLVMFuzzerTestOneInput (same parser, same properties, external corpus).
// License: MIT (AegisMesh validation fixture).
// ============================================================================

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define WR_MAX 64
static const uint32_t FUZZ_ITERS = 100000u;   /* owner mandate: >= 100k/push */
static const uint64_t FUZZ_SEED = 0x542ULL;

enum { R_OK = 0, R_LEN, R_CRC, R_MAX };
static const char *reason_name[R_MAX] = { "ok", "bad-length", "bad-crc" };

/* ---- CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320) ---------------------*/
static uint32_t crc32_ieee(const uint8_t *d, uint32_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < n; ++i) {
        c ^= d[i];
        for (int k = 0; k < 8; ++k)
            c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return c ^ 0xFFFFFFFFu;
}

/* ---- the parser under test (reference implementation) -------------------*/
static int parse_witness16(const uint8_t *buf, uint32_t len, int *reason)
{
    *reason = R_OK;
    if (len != 16u) { *reason = R_LEN; return 0; }
    const uint32_t crc_stored = (uint32_t)buf[12]
                              | ((uint32_t)buf[13] << 8)
                              | ((uint32_t)buf[14] << 16)
                              | ((uint32_t)buf[15] << 24);
    if (crc32_ieee(buf, 12) != crc_stored) { *reason = R_CRC; return 0; }
    return 1;
}

/* ---- deterministic PRNG (xorshift64*) -----------------------------------*/
static uint64_t rng_state;
static uint64_t rng_next(void)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 2685821657736338717ULL;
}
static uint32_t rng_below(uint32_t n) { return (uint32_t)(rng_next() % n); }

/* ---- independent property re-check (fresh CRC evaluation) ----------------*/
static int fields_valid(const uint8_t *buf, uint32_t len)
{
    if (len != 16u) return 0;
    const uint32_t crc_stored = (uint32_t)buf[12]
                              | ((uint32_t)buf[13] << 8)
                              | ((uint32_t)buf[14] << 16)
                              | ((uint32_t)buf[15] << 24);
    return crc32_ieee(buf, 12) == crc_stored;
}

/* ---- corpus builder: valid receipt + structural boundary cases ----------*/
static void build_corpus(uint8_t corpus[][WR_MAX], uint32_t lens[],
                         uint32_t *n)
{
    uint32_t k = 0;
    /* valid receipt */
    memset(corpus[k], 0xA5, 12);
    uint32_t c = crc32_ieee(corpus[k], 12);
    corpus[k][12] = (uint8_t)c;  corpus[k][13] = (uint8_t)(c >> 8);
    corpus[k][14] = (uint8_t)(c >> 16); corpus[k][15] = (uint8_t)(c >> 24);
    lens[k++] = 16;
    /* valid all-zero receipt (CRC of 12 zero bytes) */
    memset(corpus[k], 0, 16);
    c = crc32_ieee(corpus[k], 12);
    corpus[k][12] = (uint8_t)c;  corpus[k][13] = (uint8_t)(c >> 8);
    corpus[k][14] = (uint8_t)(c >> 16); corpus[k][15] = (uint8_t)(c >> 24);
    lens[k++] = 16;
    /* right length, corrupted CRC (bad-crc seed) */
    memset(corpus[k], 0x11, 16);
    lens[k++] = 16;
    /* short receipt (15 B) */
    memset(corpus[k], 0x22, 15);
    lens[k++] = 15;
    /* long receipt (17 B) */
    memset(corpus[k], 0x33, 17);
    lens[k++] = 17;
    *n = k;
}

#ifdef AM_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > WR_MAX) return 0;
    int reason = -1;
    const int acc = parse_witness16(data, (uint32_t)size, &reason);
    if (acc) {
        if (!fields_valid(data, (uint32_t)size)) abort();
        if (reason != R_OK) abort();
    } else if (reason < 0 || reason >= R_MAX) {
        abort();
    }
    int reason2 = -1;
    if (parse_witness16(data, (uint32_t)size, &reason2) != acc ||
        reason2 != reason) abort();
    return 0;
}
#else
int main(void)
{
    /* CRC-32 known-answer self-test (RFC 1952 / ISO-HDLC check value) */
    if (crc32_ieee((const uint8_t *)"123456789", 9) != 0xCBF43926u) {
        printf("FAIL: CRC-32 self-test (check value 0xCBF43926)\n");
        return 1;
    }

    rng_state = FUZZ_SEED;
    static uint8_t corpus[8][WR_MAX];
    static uint32_t lens[8];
    uint32_t n_seeds = 0;
    build_corpus(corpus, lens, &n_seeds);

    uint64_t accepts = 0, rej = 0;
    uint64_t by_reason[R_MAX] = {0};
    uint64_t acc_len[WR_MAX] = {0};
    uint8_t buf[WR_MAX];

    for (uint32_t it = 0; it < FUZZ_ITERS; ++it) {
        uint32_t len;
        if (it & 1u) {
            len = lens[rng_below(n_seeds)];            /* mutational */
            memcpy(buf, corpus[rng_below(n_seeds)], len);
            const uint32_t n_mut = 1u + rng_below(6u);
            for (uint32_t m = 0; m < n_mut; ++m) {
                const uint32_t pos = rng_below(len);
                if (rng_below(2u))
                    buf[pos] = (uint8_t)rng_next();
                else
                    buf[pos] ^= (uint8_t)(1u << rng_below(8u));
            }
        } else if (rng_below(2u)) {
            /* structured-valid: random body + computed CRC (P1 diversity),
               occasionally with a deliberately corrupted CRC */
            len = 16u;
            for (uint32_t i = 0; i < 12; ++i)
                buf[i] = (uint8_t)rng_next();
            const uint32_t c = crc32_ieee(buf, 12);
            const uint8_t inject_bad = (uint8_t)(rng_below(4u) == 0u);
            buf[12] = (uint8_t)c ^ (inject_bad ? 0x80u : 0u);
            buf[13] = (uint8_t)(c >> 8);
            buf[14] = (uint8_t)(c >> 16);
            buf[15] = (uint8_t)(c >> 24);
        } else {
            len = rng_below(WR_MAX + 1u);              /* 0..64 random */
            for (uint32_t i = 0; i < len; ++i)
                buf[i] = (uint8_t)rng_next();
        }

        int reason = -1;
        const int acc = parse_witness16(buf, len, &reason);

        if (acc) {
            ++accepts; acc_len[len]++;
            if (!fields_valid(buf, len)) {
                printf("FAIL P1: accepted structurally-invalid receipt\n");
                return 1;
            }
            if (reason != R_OK) { printf("FAIL P2: accept w/ reason %d\n",
                                         reason); return 1; }
        } else {
            ++rej;
            if (reason < 0 || reason >= R_MAX) {
                printf("FAIL P2: reject w/ bad reason %d\n", reason);
                return 1;
            }
            by_reason[reason]++;
        }
        int reason2 = -1;
        if (parse_witness16(buf, len, &reason2) != acc || reason2 != reason) {
            printf("FAIL P4: parse not pure\n");
            return 1;
        }
        /* P3 is enforced by ASan/UBSan bounds checking in the CI build. */
    }

    printf("fuzz: iters=%u accepts=%llu rejects=%llu (seed 0x%llx)\n",
           FUZZ_ITERS, (unsigned long long)accepts,
           (unsigned long long)rej, (unsigned long long)FUZZ_SEED);
    printf("fuzz: accepts by len: 16=%llu\n",
           (unsigned long long)acc_len[16]);
    printf("fuzz: reject reasons:");
    for (int r = 0; r < R_MAX; ++r)
        if (by_reason[r]) printf(" %s=%llu", reason_name[r],
                                 (unsigned long long)by_reason[r]);
    printf("\n");
    if (acc_len[16] == 0) {
        printf("FAIL: corpus never exercised a valid receipt\n");
        return 1;
    }
    for (int r = 1; r < R_MAX; ++r) {
        if (by_reason[r] == 0) {
            printf("FAIL: rejection reason '%s' never exercised\n",
                   reason_name[r]);
            return 1;
        }
    }
    printf("fuzz: ALL PROPERTIES PASS (P1-P4), coverage complete\n");
    return 0;
}
#endif /* AM_LIBFUZZER */
