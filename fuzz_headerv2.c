// ============================================================================
// fuzz_headerv2.c - AegisMesh HeaderV2 parser fuzz harness (ITER-9).
//
// Owner mandate (task.md "Parser fuzzing and security regression gates"):
// "CI runs a smoke fuzz of at least 100,000 iterations per push for each
// harness, with bounded runtime and reproducible seeds where supported."
//
// Parser under test: the 16-byte HeaderV2 proposal (HDR-001, research log
// research1.md ITER-2) and the 12-byte legacy baseline, structural
// (pre-AEAD) validation only.  This is the FIRST of the mandated harness
// family (witness receipts, SDIO slot framing, BLE/Nostr envelopes follow
// the same pattern).
//
// Layout (16-byte V2):
//   [0]     Ver(4b) | PHY(2b) | Prio(2b)   Ver==2; PHY 0..2 (3 reserved)
//   [1]     Flags: bit0 ENC, bit1 FRAG; bits2..7 reserved (must be 0)
//   [2:6]   Dst (opaque 4B)
//   [6:10]  Src (opaque 4B)
//   [10]    Hop(4b) | TTLclass(4b)         TTLclass 0..9 (10..15 reserved)
//   [11]    Deadline class                 0..9 (>=10 reserved)
//   [12:14] Seq (opaque)
//   [14:16] Key epoch (opaque)
// Layout (12-byte legacy baseline):
//   [0] same Ver|PHY|Prio; [1] same Flags; [2:6] Dst; [6:10] Src;
//   [10] Hop(4b)|TTLclass(4b); [11] Seq8 (opaque)
//
// Properties asserted on EVERY iteration (violation = exit 1):
//   P1 accepted  => len in {12,16} and all structural fields valid
//   P2 rejected  => reason code in the enumerated set
//   P3 parse() never reads outside [buf, buf+len)   (checked under ASan/UBSan)
//   P4 parse() is a pure function of (buf, len)     (re-parse identical)
//
// Deterministic: xorshift64* PRNG, fixed seed 0x542.  100,000 iterations.
// Build (CI): gcc -std=c11 -O1 -g -fsanitize=address,undefined
//             -fno-sanitize-recover=all fuzz_headerv2.c -o fuzz_headerv2
// License: MIT (AegisMesh validation fixture).
// ============================================================================

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define HDR_MAX 40
static const uint32_t FUZZ_ITERS = 100000u;   /* owner mandate: >= 100k/push */
static const uint64_t FUZZ_SEED = 0x542ULL;

enum {
    R_OK = 0, R_LEN, R_VER, R_PHY, R_FLAGS, R_TTL, R_DEADLINE, R_MAX
};
static const char *reason_name[R_MAX] = {
    "ok", "bad-length", "bad-version", "bad-phy", "reserved-flags",
    "bad-ttlclass", "bad-deadline"
};

/* ---- the parser under test (reference implementation) -------------------*/
static int parse_header(const uint8_t *buf, uint32_t len, int *reason)
{
    *reason = R_OK;
    if (len == 16u) {
        const uint8_t ver  = (uint8_t)(buf[0] >> 4);
        const uint8_t phy  = (uint8_t)((buf[0] >> 2) & 0x3u);
        /* prio = buf[0] & 0x3 (all values valid) */
        const uint8_t flags = buf[1];
        const uint8_t ttlc = (uint8_t)(buf[10] & 0x0Fu);
        const uint8_t dl   = buf[11];
        if (ver != 2u)              { *reason = R_VER;      return 0; }
        if (phy == 3u)              { *reason = R_PHY;      return 0; }
        if ((flags & 0xFCu) != 0u)  { *reason = R_FLAGS;    return 0; }
        if (ttlc > 9u)              { *reason = R_TTL;      return 0; }
        if (dl > 9u)                { *reason = R_DEADLINE; return 0; }
        return 1;
    }
    if (len == 12u) {
        const uint8_t ver  = (uint8_t)(buf[0] >> 4);
        const uint8_t phy  = (uint8_t)((buf[0] >> 2) & 0x3u);
        const uint8_t flags = buf[1];
        const uint8_t ttlc = (uint8_t)(buf[10] & 0x0Fu);
        if (ver != 2u)              { *reason = R_VER;      return 0; }
        if (phy == 3u)              { *reason = R_PHY;      return 0; }
        if ((flags & 0xFCu) != 0u)  { *reason = R_FLAGS;    return 0; }
        if (ttlc > 9u)              { *reason = R_TTL;      return 0; }
        return 1;
    }
    *reason = R_LEN;
    return 0;
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
static int fields_valid(const uint8_t *buf, uint32_t len)
{
    if (len != 12u && len != 16u) return 0;
    if ((buf[0] >> 4) != 2u) return 0;
    if (((buf[0] >> 2) & 0x3u) == 3u) return 0;
    if ((buf[1] & 0xFCu) != 0u) return 0;
    if ((buf[10] & 0x0Fu) > 9u) return 0;
    if (len == 16u && buf[11] > 9u) return 0;
    return 1;
}

int main(void)
{
    rng_state = FUZZ_SEED;
    /* seed corpus: valid headers + structural boundary cases */
    static const uint8_t seeds[][HDR_MAX] = {
        /* valid V2 */    {0x20, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 0x35, 0x02,
                           0xAB, 0xCD, 0x00, 0x01},
        /* valid V2 SOS */{0x23, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0,
                           0x0F, 0x00, 0x00, 0x00, 0xFF, 0xFF},
        /* valid V1 */    {0x20, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 0x35, 0x42},
        /* bad ver */     {0x10, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00,
                           0, 0, 0, 0},
        /* bad phy=3 */   {0x2C, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00,
                           0, 0, 0, 0},
        /* reserved fl */ {0x20, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00,
                           0, 0, 0, 0},
        /* bad ttl=15 */  {0x20, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x0F, 0x00,
                           0, 0, 0, 0},
        /* bad dl=10 */   {0x20, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x0A,
                           0, 0, 0, 0}
    };
    const uint32_t n_seeds = (uint32_t)(sizeof(seeds) / sizeof(seeds[0]));

    uint64_t accepts = 0, rej = 0;
    uint64_t by_reason[R_MAX] = {0};
    uint64_t acc_by_len[HDR_MAX] = {0};
    uint8_t buf[HDR_MAX];

    for (uint32_t it = 0; it < FUZZ_ITERS; ++it) {
        /* half mutational (from corpus), half fully random length/content */
        uint32_t len;
        if (it & 1u) {
            len = 12u + (rng_below(2u) * 4u);          /* 12 or 16 */
            memcpy(buf, seeds[rng_below(n_seeds)], len);
            const uint32_t n_mut = 1u + rng_below(8u);
            for (uint32_t m = 0; m < n_mut; ++m) {
                const uint32_t pos = rng_below(len);
                if (rng_below(2u))
                    buf[pos] = (uint8_t)rng_next();
                else
                    buf[pos] ^= (uint8_t)(1u << rng_below(8u));
            }
        } else {
            len = rng_below(HDR_MAX + 1u);             /* 0..40, exercises len */
            for (uint32_t i = 0; i < len; ++i)
                buf[i] = (uint8_t)rng_next();
        }

        int reason = -1;
        const int acc = parse_header(buf, len, &reason);

        /* P1/P2 */
        if (acc) {
            ++accepts;
            if (len >= HDR_MAX || acc_by_len[len] > 0xFFFFFFFFull) return 1;
            acc_by_len[len]++;
            if (!fields_valid(buf, len)) {
                printf("FAIL P1: accepted structurally-invalid input "
                       "(len=%u)\n", len);
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
        /* P4: purity */
        int reason2 = -1;
        if (parse_header(buf, len, &reason2) != acc || reason2 != reason) {
            printf("FAIL P4: parse not pure (len=%u)\n", len);
            return 1;
        }
        /* P3 is enforced by ASan/UBSan bounds checking in the CI build. */
    }

    printf("fuzz: iters=%u accepts=%llu rejects=%llu (seed 0x%llx)\n",
           FUZZ_ITERS, (unsigned long long)accepts,
           (unsigned long long)rej, (unsigned long long)FUZZ_SEED);
    printf("fuzz: accepts by len: 12=%llu 16=%llu\n",
           (unsigned long long)acc_by_len[12],
           (unsigned long long)acc_by_len[16]);
    printf("fuzz: reject reasons:");
    for (int r = 0; r < R_MAX; ++r)
        if (by_reason[r]) printf(" %s=%llu", reason_name[r],
                                 (unsigned long long)by_reason[r]);
    printf("\n");
    /* invariants: the deterministic run must exercise both lengths and
       every rejection reason at least once across 100k iterations */
    if (acc_by_len[12] == 0 || acc_by_len[16] == 0) {
        printf("FAIL: corpus failed to exercise both header lengths\n");
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
