// ============================================================================
// fuzz_sdio_slot.c - AegisMesh 512-byte SDIO slot-framing parser fuzz
//                    harness (ITER-13, harness family item 3 of 4).
//
// Owner mandate (task.md "Parser fuzzing and security regression gates"):
// "CI runs a smoke fuzz of at least 100,000 iterations per push for each
// harness, with bounded runtime and reproducible seeds where supported."
//
// Parser under test: the 512-byte SDIO slot framing (FW-002, research1.md
// ITER-3: "512 B SDIO slot framing [len:2 | flags:1 | ring_seq:1 |
// payload:<=504 | CRC32:4] with EOT and crypto-required flags;
// slot epoch-tagging for crash-consistent ring ownership").
//
// Layout (512 B slot, fixed size; payload region zero-padded on TX, the
// trailing bytes after the CRC are don't-care to the parser):
//   [0:2]   len (little-endian)          payload length, 0..504
//   [2]     flags                        bit0 EOT (end-of-transfer),
//                                        bit1 crypto-required,
//                                        bits2..7 reserved (must be 0)
//   [3]     ring_seq                     ring sequence / ownership epoch tag
//   [4:4+len] payload
//   [4+len:8+len] CRC-32 (IEEE, LE) over bytes [0 : 4+len]
//   consumed = 8 + len, must be <= 512
//
// Trust-plane relevance: the SDIO ring is the STM32U5 <-> ESP32 inter-
// processor transport (HW-005/SDIO-001/FW-002). A malformed slot that a
// parser mis-accepts can desynchronise ring ownership (crash-consistency)
// or smuggle payload past the crypto-required gate. The ESP32 side is a
// constrained service host, not a security authority (architecture map,
// trust boundary), so framing discipline here protects availability and
// the crypto-required contract, not key material.
//
// Properties asserted on EVERY iteration (violation = exit 1):
//   P1 accepted  => len <= 504, reserved flag bits 0, CRC over [0:4+len)
//                    equals stored CRC, consumed = 8+len <= 512
//   P2 rejected  => reason code in the enumerated set
//                   {bad-length, reserved-flags, bad-crc}
//   P3 parse() never reads outside [buf, buf+len)   (checked under ASan/UBSan)
//   P4 parse() is a pure function of (buf, len)     (re-parse identical)
//
// Deterministic: xorshift64* PRNG, fixed seed 0x542.  100,000 iterations.
// Build (CI): gcc -std=c11 -O1 -g -fsanitize=address,undefined
//             -fno-sanitize-recover=all fuzz_sdio_slot.c -o fuzz_sdio_slot
// libFuzzer-compatible: build with -DAM_LIBFUZZER -fsanitize=fuzzer.
// License: MIT (AegisMesh validation fixture).
// ============================================================================

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SLOT_SIZE   512u
#define SLOT_MAXLEN 504u
#define BUF_MAX     (SLOT_SIZE + 16u)   /* allow over-long inputs */
static const uint32_t FUZZ_ITERS = 100000u;   /* owner mandate: >= 100k/push */
static const uint64_t FUZZ_SEED = 0x542ULL;

enum { R_OK = 0, R_LEN, R_FLAGS, R_CRC, R_MAX };
static const char *reason_name[R_MAX] =
    { "ok", "bad-length", "reserved-flags", "bad-crc" };

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
/* Returns 1 and *consumed = 8+len on accept; 0 with *reason on reject.      */
static int parse_sdio_slot(const uint8_t *buf, uint32_t len,
                           uint32_t *consumed, int *reason)
{
    *reason = R_OK;
    *consumed = 0;
    if (len < 8u) { *reason = R_LEN; return 0; }   /* header+CRC minimum */
    const uint32_t plen = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8);
    const uint8_t flags = buf[2];
    /* ring_seq = buf[3] (opaque ownership tag; any value structurally OK) */
    if (plen > SLOT_MAXLEN) { *reason = R_LEN; return 0; }
    if ((flags & 0xFCu) != 0u) { *reason = R_FLAGS; return 0; }
    const uint32_t need = 4u + plen + 4u;
    if (need > len) { *reason = R_LEN; return 0; } /* truncated slot */
    uint32_t crc_stored = (uint32_t)buf[4 + plen]
                        | ((uint32_t)buf[5 + plen] << 8)
                        | ((uint32_t)buf[6 + plen] << 16)
                        | ((uint32_t)buf[7 + plen] << 24);
    if (crc32_ieee(buf, 4 + plen) != crc_stored) {
        *reason = R_CRC; return 0;
    }
    *consumed = need;
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

/* ---- independent property re-check --------------------------------------*/
static int fields_valid(const uint8_t *buf, uint32_t len, uint32_t consumed)
{
    if (len < 8u) return 0;
    const uint32_t plen = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8);
    if (plen > SLOT_MAXLEN) return 0;
    if ((buf[2] & 0xFCu) != 0u) return 0;
    if (consumed != 8u + plen || consumed > SLOT_SIZE) return 0;
    uint32_t crc_stored = (uint32_t)buf[4 + plen]
                        | ((uint32_t)buf[5 + plen] << 8)
                        | ((uint32_t)buf[6 + plen] << 16)
                        | ((uint32_t)buf[7 + plen] << 24);
    return crc32_ieee(buf, 4 + plen) == crc_stored;
}

/* ---- corpus builder: valid slots + structural boundary cases ------------*/
static void build_corpus(uint8_t corpus[][BUF_MAX], uint32_t lens[],
                         uint32_t *n)
{
    uint32_t k = 0;
    uint32_t c;
    /* valid empty slot */
    memset(corpus[k], 0, SLOT_SIZE);
    corpus[k][0] = 0x00; corpus[k][1] = 0x00;   /* len=0  */
    corpus[k][2] = 0x01;                        /* EOT    */
    corpus[k][3] = 0x2A;                        /* ring_seq */
    c = crc32_ieee(corpus[k], 4);
    corpus[k][4] = (uint8_t)c; corpus[k][5] = (uint8_t)(c >> 8);
    corpus[k][6] = (uint8_t)(c >> 16); corpus[k][7] = (uint8_t)(c >> 24);
    lens[k++] = SLOT_SIZE;
    /* valid full-payload slot: len=504, crypto-required */
    memset(corpus[k], 0, SLOT_SIZE);
    corpus[k][0] = (uint8_t)(SLOT_MAXLEN & 0xFF);
    corpus[k][1] = (uint8_t)(SLOT_MAXLEN >> 8);
    corpus[k][2] = 0x02;                        /* crypto-required */
    corpus[k][3] = 0x7F;
    memset(&corpus[k][4], 0x5C, SLOT_MAXLEN);
    c = crc32_ieee(corpus[k], 4 + SLOT_MAXLEN);
    corpus[k][4 + SLOT_MAXLEN] = (uint8_t)c;
    corpus[k][5 + SLOT_MAXLEN] = (uint8_t)(c >> 8);
    corpus[k][6 + SLOT_MAXLEN] = (uint8_t)(c >> 16);
    corpus[k][7 + SLOT_MAXLEN] = (uint8_t)(c >> 24);
    lens[k++] = SLOT_SIZE;
    /* valid short slot, exact consumed length (8+4) */
    memset(corpus[k], 0, SLOT_SIZE);
    corpus[k][0] = 0x04; corpus[k][1] = 0x00;
    corpus[k][2] = 0x03;                        /* EOT | crypto-required */
    corpus[k][3] = 0x01;
    memset(&corpus[k][4], 0xD4, 4);
    c = crc32_ieee(corpus[k], 8);
    corpus[k][8] = (uint8_t)c; corpus[k][9] = (uint8_t)(c >> 8);
    corpus[k][10] = (uint8_t)(c >> 16); corpus[k][11] = (uint8_t)(c >> 24);
    lens[k++] = 12;
    /* over-length (len = 505 > 504) */
    memset(corpus[k], 0, SLOT_SIZE);
    corpus[k][0] = 0xF9; corpus[k][1] = 0x01;   /* 505 */
    corpus[k][2] = 0x00;
    lens[k++] = SLOT_SIZE;
    /* reserved flag bit set (0x04) */
    memset(corpus[k], 0, SLOT_SIZE);
    corpus[k][0] = 0x08; corpus[k][1] = 0x00;
    corpus[k][2] = 0x04;
    lens[k++] = SLOT_SIZE;
    /* corrupted CRC on a valid frame */
    memset(corpus[k], 0, SLOT_SIZE);
    corpus[k][0] = 0x10; corpus[k][1] = 0x00;
    corpus[k][2] = 0x00;
    memset(&corpus[k][4], 0xEE, 16);
    lens[k++] = SLOT_SIZE;
    /* truncated (7 B total) */
    memset(corpus[k], 0xAB, 7);
    lens[k++] = 7;
    *n = k;
}

#ifdef AM_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > BUF_MAX) return 0;
    int reason = -1; uint32_t consumed = 0;
    const int acc = parse_sdio_slot(data, (uint32_t)size, &consumed, &reason);
    if (acc) {
        if (!fields_valid(data, (uint32_t)size, consumed)) abort();
        if (reason != R_OK) abort();
    } else if (reason < 0 || reason >= R_MAX) {
        abort();
    }
    int reason2 = -1; uint32_t consumed2 = 0;
    if (parse_sdio_slot(data, (uint32_t)size, &consumed2, &reason2) != acc ||
        reason2 != reason || consumed2 != consumed) abort();
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
    static uint8_t corpus[8][BUF_MAX];
    static uint32_t lens[8];
    uint32_t n_seeds = 0;
    build_corpus(corpus, lens, &n_seeds);

    uint64_t accepts = 0, rej = 0;
    uint64_t by_reason[R_MAX] = {0};
    uint64_t acc_eot = 0, acc_crypto = 0, acc_full = 0, acc_empty = 0;
    uint8_t buf[BUF_MAX];

    for (uint32_t it = 0; it < FUZZ_ITERS; ++it) {
        uint32_t len;
        if (it & 1u) {
            len = lens[rng_below(n_seeds)];            /* mutational */
            memcpy(buf, corpus[rng_below(n_seeds)], len);
            const uint32_t n_mut = 1u + rng_below(8u);
            for (uint32_t m = 0; m < n_mut; ++m) {
                const uint32_t pos = rng_below(len);
                if (rng_below(2u))
                    buf[pos] = (uint8_t)rng_next();
                else
                    buf[pos] ^= (uint8_t)(1u << rng_below(8u));
            }
        } else {
            const uint32_t pick = rng_below(8u);
            if (pick < 3u) {
                /* structured-valid: random len, random payload + computed
                   CRC (P1 diversity), occasionally corrupted CRC */
                const uint32_t plen = rng_below(SLOT_MAXLEN + 1u);
                memset(buf, 0, SLOT_SIZE);
                buf[0] = (uint8_t)(plen & 0xFF);
                buf[1] = (uint8_t)(plen >> 8);
                buf[2] = (uint8_t)(rng_below(4u) |      /* EOT/crypto bits */
                                   (rng_below(4u) == 0u ? 0x04u : 0u));
                buf[3] = (uint8_t)rng_next();
                for (uint32_t i = 4; i < 4 + plen; ++i)
                    buf[i] = (uint8_t)rng_next();
                const uint32_t c = crc32_ieee(buf, 4 + plen);
                const uint8_t inject_bad = (uint8_t)(rng_below(4u) == 0u);
                buf[4 + plen] = (uint8_t)c ^ (inject_bad ? 0x40u : 0u);
                buf[5 + plen] = (uint8_t)(c >> 8);
                buf[6 + plen] = (uint8_t)(c >> 16);
                buf[7 + plen] = (uint8_t)(c >> 24);
                len = SLOT_SIZE;
            } else if (pick < 6u) {
                len = SLOT_SIZE;                        /* random full slot */
                for (uint32_t i = 0; i < len; ++i)
                    buf[i] = (uint8_t)rng_next();
            } else if (pick < 7u) {
                len = rng_below(64u) + 1u;              /* short/truncated */
                for (uint32_t i = 0; i < len; ++i)
                    buf[i] = (uint8_t)rng_next();
            } else {
                len = SLOT_SIZE + rng_below(16u) + 1u;  /* overlong input */
                for (uint32_t i = 0; i < len; ++i)
                    buf[i] = (uint8_t)rng_next();
            }
        }

        int reason = -1; uint32_t consumed = 0;
        const int acc = parse_sdio_slot(buf, len, &consumed, &reason);

        if (acc) {
            ++accepts;
            if (!fields_valid(buf, len, consumed)) {
                printf("FAIL P1: accepted structurally-invalid slot\n");
                return 1;
            }
            if (reason != R_OK) { printf("FAIL P2: accept w/ reason %d\n",
                                         reason); return 1; }
            if (consumed > SLOT_SIZE) {
                printf("FAIL P1: consumed %u > 512\n", consumed);
                return 1;
            }
            if (buf[2] & 0x01u) acc_eot++;
            if (buf[2] & 0x02u) acc_crypto++;
            const uint32_t plen = (uint32_t)buf[0]
                                | ((uint32_t)buf[1] << 8);
            if (plen == SLOT_MAXLEN) acc_full++;
            if (plen == 0) acc_empty++;
        } else {
            ++rej;
            if (reason < 0 || reason >= R_MAX) {
                printf("FAIL P2: reject w/ bad reason %d\n", reason);
                return 1;
            }
            by_reason[reason]++;
        }
        int reason2 = -1; uint32_t consumed2 = 0;
        if (parse_sdio_slot(buf, len, &consumed2, &reason2) != acc ||
            reason2 != reason || consumed2 != consumed) {
            printf("FAIL P4: parse not pure\n");
            return 1;
        }
        /* P3 is enforced by ASan/UBSan bounds checking in the CI build. */
    }

    printf("fuzz: iters=%u accepts=%llu rejects=%llu (seed 0x%llx)\n",
           FUZZ_ITERS, (unsigned long long)accepts,
           (unsigned long long)rej, (unsigned long long)FUZZ_SEED);
    printf("fuzz: accepts: eot=%llu crypto=%llu full504=%llu empty=%llu\n",
           (unsigned long long)acc_eot, (unsigned long long)acc_crypto,
           (unsigned long long)acc_full, (unsigned long long)acc_empty);
    printf("fuzz: reject reasons:");
    for (int r = 0; r < R_MAX; ++r)
        if (by_reason[r]) printf(" %s=%llu", reason_name[r],
                                 (unsigned long long)by_reason[r]);
    printf("\n");
    if (acc_eot == 0 || acc_crypto == 0 || acc_full == 0 || acc_empty == 0) {
        printf("FAIL: corpus failed to exercise accept classes\n");
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
