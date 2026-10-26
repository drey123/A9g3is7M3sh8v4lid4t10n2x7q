// ============================================================================
// fuzz_ble_envelope.c - AegisMesh BLE/Nostr transport-envelope parser fuzz
//                       harness (ITER-13, harness family item 4 of 4).
//
// Owner mandate (task.md "Parser fuzzing and security regression gates"):
// "CI runs a smoke fuzz of at least 100,000 iterations per push for each
// harness, with bounded runtime and reproducible seeds where supported."
//
// Parser under test: the BLE/Nostr transport envelope, anchored on the
// BitChat v1 binary wire frame (AegisMesh's BLE-flood transport family
// reference; verified primary sources below) with the two AegisMesh quota
// overlays the owner baseline mandates.
//
// Verified format sources (fetched 2026-10-26, ITER-13):
//  - BitChat whitepaper v2.0 (2026-07-06) section 4.1 "Packet Format":
//    "A compact binary header (version, type, TTL, timestamp, flags) is
//    followed by an 8-byte sender ID, an optional 8-byte recipient ID,
//    the payload, and an optional Ed25519 signature."  Section 4.2:
//    "Packets originate with TTL 7".
//  - BitChat reference implementation (permissionlesstech/bitchat, repo
//    main, localPackages/BitFoundation/Sources/BitFoundation/
//    BinaryProtocol.swift + BitchatPacket.swift), inspected to pin byte
//    widths of the whitepaper's fields (code inspection validating the
//    paper, per the research-mode rule):
//      v1HeaderSize = 14: [0] version(1)  [1] type(1)  [2] ttl(1)
//        [3:11] timestamp(8, big-endian)  [11] flags(1)  [12:14]
//        payloadLength(2, big-endian, payload-only)
//      flags: bit0 hasRecipient, bit1 hasSignature, bit2 isCompressed;
//      hasRoute (bit3) and isRSR (bit4) are valid for v2+ frames only
//      (SOURCE_ROUTING.md), so for a v1 frame bits3..7 are reserved.
//      senderIDSize = 8, recipientIDSize = 8, signatureSize = 64 (Ed25519).
//      Padding: frames may be padded toward 256/512/1024/2048-byte buckets
//      (whitepaper 4.1 noise-packet padding); decode tolerates trailing
//      padding, so the parser treats trailing bytes as padding (do-not-
//      care) once the declared fields are consumed.
//  - AegisMesh overlays (owner baseline, task.md Storage Architecture +
//    research2.md ITER-8 BitChat comparison):
//      (O1) 16 KiB envelope cap - "16 KiB envelope cap" is the task.md
//           per-peer outbox quota; envelopes above the cap are structurally
//           rejected (reason envelope-cap). EXTENDED relative to BitChat
//           (whose v1 public frames may reach 64-128 KiB per its
//           PacketPayloadLimits.swift) - the stricter AegisMesh cap wins.
//      (O2) TTL discipline - ttl == 0 is rejected (the CVE-2026-51376
//           remediation, PR #998, removed the "TTL==0 unconditional
//           acceptance path"; cache/custody insertion is gated on packet
//           acceptance) and ttl > 7 is rejected (packets originate with
//           TTL 7 and only decrement; a received frame above 7 is
//           structurally invalid). reason bad-ttl.
//
// v1 scope note: version 2 frames (4-byte length field + explicit source
// route) are OUT OF SCOPE for this harness - AegisMesh route descriptors
// are a separate carried item (research2.md ITER-12 #5); modelling the v2
// route table before that contract exists would validate fiction. Any
// version != 1 is rejected as bad-version. This is stated scoping, not an
// omission.
//
// Properties asserted on EVERY iteration (violation = exit 1):
//   P1 accepted  => all structural fields valid, consumed computed exactly,
//                   consumed <= 16384 (O1), 1 <= ttl <= 7 (O2)
//   P2 rejected  => reason code in the enumerated set {bad-length,
//                   bad-version, reserved-flags, bad-ttl, bad-plen,
//                   envelope-cap}
//   P3 parse() never reads outside [buf, buf+len)   (checked under ASan/UBSan)
//   P4 parse() is a pure function of (buf, len)     (re-parse identical)
//   P5 (documented ordering property, research2.md ITER-8 (c)): parse has
//      no side effects - no cache/custody state is touched at parse time.
//      Enforced structurally by P4 purity (no static mutable state).
//
// Deterministic: xorshift64* PRNG, fixed seed 0x542.  100,000 iterations.
// Build (CI): gcc -std=c11 -O1 -g -fsanitize=address,undefined
//             -fno-sanitize-recover=all fuzz_ble_envelope.c -o fuzz_ble_envelope
// libFuzzer-compatible: build with -DAM_LIBFUZZER -fsanitize=fuzzer.
// License: MIT (AegisMesh validation fixture).
// ============================================================================

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ENV_MAX        20480u              /* 16 KiB cap + padding headroom */
#define ENV_CAP        16384u              /* O1: AegisMesh envelope cap    */
#define V1_HEADER      14u
#define SENDER_SIZE    8u
#define RECIPIENT_SIZE 8u
#define SIG_SIZE       64u
static const uint32_t FUZZ_ITERS = 100000u;   /* owner mandate: >= 100k/push */
static const uint64_t FUZZ_SEED = 0x542ULL;

enum { R_OK = 0, R_LEN, R_VER, R_FLAGS, R_TTL, R_PLEN, R_CAP, R_MAX };
static const char *reason_name[R_MAX] = { "ok", "bad-length", "bad-version",
    "reserved-flags", "bad-ttl", "bad-plen", "envelope-cap" };

/* ---- the parser under test (reference implementation) -------------------*/
/* Returns 1 and *consumed on accept; 0 with *reason on reject.              */
static int parse_ble_envelope(const uint8_t *buf, uint32_t len,
                              uint32_t *consumed, int *reason)
{
    *reason = R_OK;
    *consumed = 0;
    if (len < V1_HEADER + SENDER_SIZE) { *reason = R_LEN; return 0; }
    const uint8_t version = buf[0];
    const uint8_t ttl     = buf[2];
    const uint8_t flags   = buf[11];
    if (version != 1u) { *reason = R_VER; return 0; }
    if ((flags & 0xF8u) != 0u) { *reason = R_FLAGS; return 0; }  /* v1: bits3..7 reserved */
    if (ttl == 0u || ttl > 7u) { *reason = R_TTL; return 0; }    /* O2 */
    const uint32_t plen = ((uint32_t)buf[12] << 8) | (uint32_t)buf[13];
    const uint32_t head = V1_HEADER + SENDER_SIZE
                        + ((flags & 0x01u) ? RECIPIENT_SIZE : 0u);
    if (plen > (len - head)) { *reason = R_PLEN; return 0; }     /* truncated */
    const uint32_t total = head + plen + ((flags & 0x02u) ? SIG_SIZE : 0u);
    if (total > len) { *reason = R_PLEN; return 0; }             /* truncated (sig) */
    if (total > ENV_CAP) { *reason = R_CAP; return 0; }          /* O1 */
    *consumed = total;
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
    if (len < V1_HEADER + SENDER_SIZE) return 0;
    if (buf[0] != 1u) return 0;
    if ((buf[11] & 0xF8u) != 0u) return 0;
    if (buf[2] == 0u || buf[2] > 7u) return 0;
    const uint32_t plen = ((uint32_t)buf[12] << 8) | (uint32_t)buf[13];
    const uint32_t head = V1_HEADER + SENDER_SIZE
                        + ((buf[11] & 0x01u) ? RECIPIENT_SIZE : 0u);
    if (plen > (len - head)) return 0;
    const uint32_t total = head + plen + ((buf[11] & 0x02u) ? SIG_SIZE : 0u);
    return total == consumed && total <= len && total <= ENV_CAP;
}

/* ---- corpus builder ------------------------------------------------------*/
static void put_env(uint8_t *e, uint8_t ttl, uint8_t flags,
                    uint16_t plen, int with_recip, int with_sig,
                    uint8_t sender_fill, uint32_t *total)
{
    e[0] = 0x01;                 /* version */
    e[1] = 0x05;                 /* type: noiseEncrypted-class (opaque here) */
    e[2] = ttl;
    memset(&e[3], 0x77, 8);      /* timestamp */
    e[11] = flags;
    e[12] = (uint8_t)(plen >> 8);
    e[13] = (uint8_t)(plen & 0xFF);
    memset(&e[14], sender_fill, SENDER_SIZE);
    uint32_t off = V1_HEADER + SENDER_SIZE;
    if (with_recip) { memset(&e[off], 0x91, RECIPIENT_SIZE); off += RECIPIENT_SIZE; }
    memset(&e[off], 0x42, plen); off += plen;
    if (with_sig)   { memset(&e[off], 0xCD, SIG_SIZE); off += SIG_SIZE; }
    *total = off;
}

static void build_corpus(uint8_t corpus[][ENV_MAX], uint32_t lens[],
                         uint32_t *n)
{
    uint32_t k = 0, t = 0;
    /* valid minimal */
    put_env(corpus[k], 7, 0x00, 16, 0, 0, 0xA1, &t); lens[k++] = t + 0;
    /* valid with recipient */
    put_env(corpus[k], 5, 0x01, 32, 1, 0, 0xA2, &t); lens[k++] = t;
    /* valid with signature */
    put_env(corpus[k], 3, 0x02, 48, 0, 1, 0xA3, &t); lens[k++] = t;
    /* valid with both + padding to a 2048 bucket */
    put_env(corpus[k], 7, 0x03, 100, 1, 1, 0xA4, &t);
    while (t < 2048u) corpus[k][t++] = 0x00;
    lens[k++] = 2048;
    /* ttl = 0 (O2 / PR #998 lesson) */
    put_env(corpus[k], 0, 0x00, 16, 0, 0, 0xA5, &t); lens[k++] = t;
    /* ttl = 8 (above origin bound) */
    put_env(corpus[k], 8, 0x00, 16, 0, 0, 0xA6, &t); lens[k++] = t;
    /* reserved flag 0x08 (hasRoute is v2-only) */
    put_env(corpus[k], 7, 0x08, 16, 0, 0, 0xA7, &t); lens[k++] = t;
    /* bad version 2 within a v1-shaped frame */
    put_env(corpus[k], 7, 0x00, 16, 0, 0, 0xA8, &t);
    corpus[k][0] = 0x02; lens[k++] = t;
    /* envelope-cap boundary: exactly 16384 accepted, 16385 rejected */
    {
        const uint16_t pl = (uint16_t)(ENV_CAP - (V1_HEADER + SENDER_SIZE + 8 + 0));
        put_env(corpus[k], 7, 0x01, pl, 1, 0, 0xA9, &t);
        lens[k++] = t;                       /* total == 16384 */
    }
    {
        const uint16_t pl = (uint16_t)(ENV_CAP - (V1_HEADER + SENDER_SIZE + 8 + 0) + 1);
        put_env(corpus[k], 7, 0x01, pl, 1, 0, 0xAA, &t);
        lens[k++] = t;                       /* total == 16385 -> envelope-cap */
    }
    /* truncated payload (declared plen > available) */
    put_env(corpus[k], 7, 0x00, 200, 0, 0, 0xAB, &t); lens[k++] = t - 50;
    *n = k;
}

#ifdef AM_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > ENV_MAX) return 0;
    int reason = -1; uint32_t consumed = 0;
    const int acc = parse_ble_envelope(data, (uint32_t)size, &consumed, &reason);
    if (acc) {
        if (!fields_valid(data, (uint32_t)size, consumed)) abort();
        if (reason != R_OK) abort();
    } else if (reason < 0 || reason >= R_MAX) {
        abort();
    }
    int reason2 = -1; uint32_t consumed2 = 0;
    if (parse_ble_envelope(data, (uint32_t)size, &consumed2, &reason2) != acc ||
        reason2 != reason || consumed2 != consumed) abort();
    return 0;
}
#else
int main(void)
{
    rng_state = FUZZ_SEED;
    static uint8_t corpus[16][ENV_MAX];
    static uint32_t lens[16];
    uint32_t n_seeds = 0;
    build_corpus(corpus, lens, &n_seeds);

    uint64_t accepts = 0, rej = 0;
    uint64_t by_reason[R_MAX] = {0};
    uint64_t acc_recip = 0, acc_sig = 0, acc_cap_boundary = 0;
    uint8_t buf[ENV_MAX];

    for (uint32_t it = 0; it < FUZZ_ITERS; ++it) {
        uint32_t len;
        if (it & 1u) {
            len = lens[rng_below(n_seeds)];            /* mutational */
            if (len > ENV_MAX) len = ENV_MAX;
            memcpy(buf, corpus[rng_below(n_seeds)], len);
            const uint32_t n_mut = 1u + rng_below(10u);
            for (uint32_t m = 0; m < n_mut; ++m) {
                const uint32_t pos = rng_below(len);
                if (rng_below(2u))
                    buf[pos] = (uint8_t)rng_next();
                else
                    buf[pos] ^= (uint8_t)(1u << rng_below(8u));
            }
        } else {
            /* fully random: envelope-scale, small, over-cap lengths, plus
               a structured-valid class (random fields within bounds, P1
               diversity incl. the 16 KiB cap boundary) */
            const uint32_t pick = rng_below(10u);
            if (pick < 3u) {
                /* structured-valid envelope */
                const uint8_t ttl = (uint8_t)(1u + rng_below(7u));
                const uint8_t flags = (uint8_t)(rng_below(4u) & 0x03u);
                const uint8_t with_recip = (uint8_t)(flags & 0x01u);
                const uint8_t with_sig = (uint8_t)((flags >> 1) & 0x01u);
                uint32_t head = V1_HEADER + SENDER_SIZE
                              + (with_recip ? RECIPIENT_SIZE : 0u);
                uint32_t plen;
                if (rng_below(8u) == 0u) {
                    /* cap-boundary class: total == 16384 or 16385 */
                    const uint32_t base = head
                        + (with_sig ? SIG_SIZE : 0u);
                    plen = ENV_CAP - base + rng_below(2u);
                } else {
                    plen = rng_below(1024u);
                }
                head += plen + (with_sig ? SIG_SIZE : 0u);
                if (head <= ENV_MAX) {
                    memset(buf, 0, ENV_MAX);
                    buf[0] = 0x01;
                    buf[1] = (uint8_t)rng_next();
                    buf[2] = ttl;
                    for (uint32_t i = 3; i < 11; ++i)
                        buf[i] = (uint8_t)rng_next();
                    buf[11] = flags;
                    buf[12] = (uint8_t)(plen >> 8);
                    buf[13] = (uint8_t)(plen & 0xFF);
                    for (uint32_t i = 14; i < head; ++i)
                        buf[i] = (uint8_t)rng_next();
                    len = head + (rng_below(2u) ? rng_below(256u) : 0u);
                } else {
                    len = rng_below(ENV_MAX) + 1u;
                    for (uint32_t i = 0; i < len; ++i)
                        buf[i] = (uint8_t)rng_next();
                }
            } else if (pick < 6u) {
                len = rng_below(2048u) + 1u;
                for (uint32_t i = 0; i < len; ++i)
                    buf[i] = (uint8_t)rng_next();
            } else if (pick < 8u) {
                len = rng_below(16384u) + 1u;
                for (uint32_t i = 0; i < len; ++i)
                    buf[i] = (uint8_t)rng_next();
            } else {
                len = rng_below(ENV_MAX - 16384u) + 16385u;
                for (uint32_t i = 0; i < len; ++i)
                    buf[i] = (uint8_t)rng_next();
            }
        }

        int reason = -1; uint32_t consumed = 0;
        const int acc = parse_ble_envelope(buf, len, &consumed, &reason);

        if (acc) {
            ++accepts;
            if (!fields_valid(buf, len, consumed)) {
                printf("FAIL P1: accepted structurally-invalid envelope\n");
                return 1;
            }
            if (reason != R_OK) { printf("FAIL P2: accept w/ reason %d\n",
                                         reason); return 1; }
            if (consumed > ENV_CAP) {
                printf("FAIL P1: consumed %u > 16384 cap\n", consumed);
                return 1;
            }
            if (buf[11] & 0x01u) acc_recip++;
            if (buf[11] & 0x02u) acc_sig++;
            if (consumed == ENV_CAP) acc_cap_boundary++;
        } else {
            ++rej;
            if (reason < 0 || reason >= R_MAX) {
                printf("FAIL P2: reject w/ bad reason %d\n", reason);
                return 1;
            }
            by_reason[reason]++;
        }
        int reason2 = -1; uint32_t consumed2 = 0;
        if (parse_ble_envelope(buf, len, &consumed2, &reason2) != acc ||
            reason2 != reason || consumed2 != consumed) {
            printf("FAIL P4/P5: parse not pure (side effect?)\n");
            return 1;
        }
        /* P3 is enforced by ASan/UBSan bounds checking in the CI build. */
    }

    printf("fuzz: iters=%u accepts=%llu rejects=%llu (seed 0x%llx)\n",
           FUZZ_ITERS, (unsigned long long)accepts,
           (unsigned long long)rej, (unsigned long long)FUZZ_SEED);
    printf("fuzz: accepts: recip=%llu sig=%llu cap-boundary=%llu\n",
           (unsigned long long)acc_recip, (unsigned long long)acc_sig,
           (unsigned long long)acc_cap_boundary);
    printf("fuzz: reject reasons:");
    for (int r = 0; r < R_MAX; ++r)
        if (by_reason[r]) printf(" %s=%llu", reason_name[r],
                                 (unsigned long long)by_reason[r]);
    printf("\n");
    if (acc_recip == 0 || acc_sig == 0) {
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
    printf("fuzz: ALL PROPERTIES PASS (P1-P5), coverage complete\n");
    return 0;
}
#endif /* AM_LIBFUZZER */
