#!/usr/bin/env python3
"""Check real group-19 SAE against IEEE Annex J.10 and Python P-256.

Fixed vector: IEEE Std 802.11-2020 Annex J.10, also reproduced in hostap
src/common/common_module_tests.c (sae_tests). H&P only; no H2E/SAE-PK claim.
The C helpers compile the driver's SHA-256/HMAC and ECC, not crypto stubs.
"""
from pathlib import Path
import hashlib
import hmac
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
NET = ROOT / "mtk80211" / "openbsd" / "net80211"
SANITIZERS = os.environ.get("MTK_TEST_SANITIZERS", "address,undefined")

P = 2**256 - 2**224 + 2**192 + 2**96 - 1
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)

OWN = bytes.fromhex("001122334455")
PEER = bytes.fromhex("aabbccddeeff")
PASSWORD = "correct horses have broadband"

# Source: https://github.com/vanhoefm/hostap-wpa3/blob/master/src/common/common_module_tests.c
# Retrieved source SHA256: d095597e883b84e48de760ec9ac29f2e616aaddcbac3f8d692cfd73e2ada5e2b
ANNEX = {
    "local_rand": "992465fd3daa3c60aa6565b7f62a2a7f2e12dd12f198faf4fbed89d7ff1ace94",
    "local_mask": "9507a90f777a044d6a0830b91ea3d5dd70bece44e1acffb86983b5e1bf9fb322",
    "local_commit": "13002e2c0f0db52440ad146d967114ce005ce1eab0aa2c2e5c2871b774f6c2575c65d5ad9e00829707aa36ba8b859738fc961d08243505f47c035376d7ac4bc8d7b95083bf43827d0fc31ed778dd3671fd21a46d1091d64b6f9a1e1272621325dbe1",
    "peer_commit": "1300591b96f3397fb945100848e7b550543b6720d88337ee93fc49fd6df7e08b5223e71b9bb048d3873f20556953a96c91536fd8ee6ca9b4a68a148b056a909be03e83ae208f60f8ef5537858074db06687032399862999b511e0a1552a5fea317c2",
    "kck": "1e733f6d9bd53256287304338831b09a39406d121017073a5c30db36f36cb81a",
    "pmk": "4e4dfab1a2dd8ac1a91790f953faaa452ae5c6873ab75b63605ba663f8a7fe59",
    "pmkid": "8747a600eea3f9f22475df58ca1e5498",
}


def b32(value):
    return value.to_bytes(32, "big")


def point_bytes(point):
    return b32(point[0]) + b32(point[1])


def on_curve(point):
    x, y = point
    return 0 <= x < P and 0 <= y < P and (y * y - x * x * x + 3 * x - B) % P == 0


def inv_mod(value):
    return pow(value, P - 2, P)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        slope = (3 * a[0] * a[0] - 3) * inv_mod(2 * a[1]) % P
    else:
        slope = (b[1] - a[1]) * inv_mod(b[0] - a[0]) % P
    x = (slope * slope - a[0] - b[0]) % P
    return x, (slope * (a[0] - x) - a[1]) % P


def point_mul(point, scalar):
    result, addend = None, point
    while scalar:
        if scalar & 1:
            result = addend if result is None else point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def negate(point):
    return point[0], (P - point[1]) % P


def kdf(key, label, context, length):
    out, counter = b"", 1
    while len(out) < length:
        out += hmac.new(key, counter.to_bytes(2, "little") + label + context +
                        (length * 8).to_bytes(2, "little"), hashlib.sha256).digest()
        counter += 1
    return out[:length]


def derive_pwe(own, peer, password):
    token = hmac.new(max(own, peer) + min(own, peer), digestmod=hashlib.sha256)
    chosen = None
    for counter in range(1, 41):
        seed = token.copy()
        seed.update(password + bytes([counter]))
        seed = seed.digest()
        value = int.from_bytes(
            kdf(seed, b"SAE Hunting and Pecking", b32(P), 32), "big")
        if value < P:
            rhs = (value**3 - 3 * value + B) % P
            y = pow(rhs, (P + 1) // 4, P)
            if y * y % P == rhs:
                if (y & 1) != (seed[31] & 1):
                    y = P - y
                if chosen is None:
                    chosen = (value, y)
    if chosen is None:
        raise RuntimeError("no PWE")
    return chosen, 40


def material(rand_a, mask_a, rand_b, mask_b, pwe):
    scalar_a = (rand_a + mask_a) % N
    scalar_b = (rand_b + mask_b) % N
    element_a = negate(point_mul(pwe, mask_a))
    element_b = negate(point_mul(pwe, mask_b))
    pt_a = point_add(point_mul(pwe, scalar_b), element_b)
    pt_b = point_add(point_mul(pwe, scalar_a), element_a)
    k_a = point_mul(pt_a, rand_a)[0]
    k_b = point_mul(pt_b, rand_b)[0]
    assert k_a == k_b
    seed = hmac.new(bytes(32), b32(k_a), hashlib.sha256).digest()
    context = b32((scalar_a + scalar_b) % N)
    keys = kdf(seed, b"SAE KCK and PMK", context, 64)
    return scalar_a, scalar_b, element_a, element_b, context, keys


def confirm(kck, first_scalar, first_element, second_scalar, second_element, counter=1):
    return hmac.new(kck, counter.to_bytes(2, "little") + first_scalar + first_element +
                    second_scalar + second_element, hashlib.sha256).digest()


HELPER = r'''
#include <net80211/ieee80211_sae.h>
#include <stdio.h>
#include <string.h>

static uint8_t stream[16384];
static size_t stream_pos, stream_len;
static int take_random(void *arg, uint8_t *out, size_t len) {
    (void)arg;
    if (len > stream_len - stream_pos) return -1;
    memcpy(out, stream + stream_pos, len);
    stream_pos += len;
    return 0;
}

int main(int argc, char **argv) {
    struct ieee80211_sae sa, sb;
    uint8_t commit_a[98], commit_b[98], confirm_a[34], confirm_b[34];
    FILE *f;
    size_t n;

    if (argc != 3) return 2;
    f = fopen(argv[1], "rb");
    if (!f) return 3;
    n = fread(stream, 1, sizeof(stream), f);
    fclose(f);
    if (n == 0 || n > sizeof(stream)) return 4;
    stream_pos = 0;
    stream_len = n;

    memset(&sa, 0, sizeof(sa));
    ieee80211_sae_test_rng(&sa, take_random, NULL);
    if (ieee80211_sae_start(&sa, OWN_ADDR, PEER_ADDR,
        (const uint8_t *)argv[2], strlen(argv[2])) != 0) return 5;
    if (ieee80211_sae_new_commit(&sa, commit_a) != 0) return 6;
    if (ieee80211_sae_process_commit(&sa, commit_a,
        sizeof(commit_a)) != 1) return 7;

    memset(&sb, 0, sizeof(sb));
    ieee80211_sae_test_rng(&sb, take_random, NULL);
    if (ieee80211_sae_start(&sb, PEER_ADDR, OWN_ADDR,
        (const uint8_t *)argv[2], strlen(argv[2])) != 0) return 9;
    if (ieee80211_sae_new_commit(&sb, commit_b) != 0) return 10;
    if (ieee80211_sae_process_commit(&sb, commit_a,
        sizeof(commit_a)) != 0) return 11;
    if (ieee80211_sae_write_confirm(&sb, confirm_b) != 0) return 12;
    if (ieee80211_sae_process_commit(&sa, commit_b,
        sizeof(commit_b)) != 0) return 13;
    if (ieee80211_sae_write_confirm(&sa, confirm_a) != 0) return 14;
    if (ieee80211_sae_check_confirm(&sa, confirm_b,
        sizeof(confirm_b)) != 0) return 15;
    if (ieee80211_sae_check_confirm(&sb, confirm_a,
        sizeof(confirm_a)) != 0) return 16;

    f = fopen("/dev/stdout", "wb");
    if (!f) return 17;
    fwrite(commit_a, 1, sizeof(commit_a), f);
    fwrite(commit_b, 1, sizeof(commit_b), f);
    fwrite(confirm_a, 1, sizeof(confirm_a), f);
    fwrite(confirm_b, 1, sizeof(confirm_b), f);
    fwrite(sa.pmkid, 1, sizeof(sa.pmkid), f);
    fwrite(sa.pmk, 1, sizeof(sa.pmk), f);
    fclose(f);
    return 0;
}
'''

POINTS = r'''
#include <net80211/ieee80211_sae.h>
#include "sae/uECC.h"
#include <stdio.h>

int main(void) {
    uint8_t a[64], b[64], out[64];
    while (fread(a, 1, sizeof(a), stdin) == sizeof(a)) {
        if (fread(b, 1, sizeof(b), stdin) != sizeof(b)) return 2;
        int ok = uECC_sae_test_point_add(out, a, b);
        fputc(ok, stdout);
        if (ok) fwrite(out, 1, sizeof(out), stdout);
    }
    return feof(stdin) ? 0 : 1;
}
'''

REJECTION = r'''
#include <net80211/ieee80211_sae.h>
#include <string.h>

static uint8_t random_fill;
static int filled_random(void *arg, uint8_t *out, size_t len) {
    (void)arg;
    memset(out, random_fill, len);
    return 0;
}

static int seed(struct ieee80211_sae *sae, uint8_t fill, const uint8_t own[6],
                const uint8_t peer[6]) {
    uint8_t commit[98];
    memset(sae, 0, sizeof(*sae));
    random_fill = fill;
    ieee80211_sae_test_rng(sae, filled_random, NULL);
    if (ieee80211_sae_start(sae, own, peer, (const uint8_t *)"secret", 6) != 0)
        return -1;
    return ieee80211_sae_new_commit(sae, commit);
}

int main(void) {
    const uint8_t own[6] = {1,2,3,4,5,6}, peer[6] = {6,5,4,3,2,1};
    const uint8_t short_frame[97] = {19};
    uint8_t commit[98], peer_commit[98], peer_confirm[34], bad_sc[34] = {2};
    uint8_t junk[98];
    struct ieee80211_sae sae, peer_sae;

    if (seed(&sae, 0x22, own, peer) != 0) return 1;
    if (ieee80211_sae_new_commit(&sae, commit) != 0) return 2;
    if (seed(&peer_sae, 0x44, peer, own) != 0) return 14;
    if (ieee80211_sae_new_commit(&peer_sae, peer_commit) != 0) return 15;
    if (ieee80211_sae_process_commit(&peer_sae, commit,
        sizeof(commit)) != 0) return 17;
    if (ieee80211_sae_write_confirm(&peer_sae, peer_confirm) != 0) return 18;

    if (ieee80211_sae_process_commit(&sae, short_frame,
        sizeof(short_frame)) != -1) return 3;
    memcpy(junk, commit, sizeof(junk));
    junk[0] = 20;
    if (ieee80211_sae_process_commit(&sae, junk, sizeof(junk)) != -1) return 4;
    memcpy(junk, commit, sizeof(junk));
    memset(junk + 2, 0, 32);
    if (ieee80211_sae_process_commit(&sae, junk, sizeof(junk)) != -1) return 5;
    memcpy(junk, commit, sizeof(junk));
    memset(junk + 2, 0xff, 32);
    if (ieee80211_sae_process_commit(&sae, junk, sizeof(junk)) != -1) return 6;
    memcpy(junk, commit, sizeof(junk));
    junk[34] ^= 0xff;
    if (ieee80211_sae_process_commit(&sae, junk, sizeof(junk)) != -1) return 7;
    memcpy(junk, commit, sizeof(junk));
    if (ieee80211_sae_process_commit(&sae, junk,
        sizeof(junk)) != 1) return 8;
    if (ieee80211_sae_process_commit(&sae, peer_commit,
        sizeof(peer_commit)) != 0) return 16;
    if (ieee80211_sae_write_confirm(&sae, junk) != 0) return 9;
    if (ieee80211_sae_check_confirm(&sae, bad_sc,
        sizeof(bad_sc)) != -1) return 10;
    bad_sc[0] = 1;
    if (ieee80211_sae_check_confirm(&sae, bad_sc,
        sizeof(bad_sc)) != -1) return 11;
    if (ieee80211_sae_check_confirm(&sae, peer_confirm,
        sizeof(peer_confirm)) != 0) return 12;
    if (ieee80211_sae_write_confirm(&sae, junk) != -1) return 13;
    return 0;
}
'''

ANNEX_HELPER = r'''
#include <net80211/ieee80211_sae.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int filled_random(void *arg, uint8_t *out, size_t len) {
    (void)arg; memset(out, 0x11, len); return 0;
}
static int failed_random(void *arg, uint8_t *out, size_t len) {
    (void)arg; memset(out, 0xa5, len); return -1;
}
static int zero(const void *p, size_t len) {
    const uint8_t *b = p;
    while (len--) if (*b++) return 0;
    return 1;
}
static void start(struct ieee80211_sae *sae) {
    const uint8_t own[6] = {0x4d,0x3f,0x2f,0xff,0xe3,0x87};
    const uint8_t peer[6] = {0xa5,0xd8,0xaa,0x95,0x8e,0x3c};
    memset(sae, 0, sizeof(*sae));
    ieee80211_sae_test_rng(sae, filled_random, NULL);
    assert(ieee80211_sae_start(sae, own, peer,
        (const uint8_t *)"mekmitasdigoat", sizeof("mekmitasdigoat") - 1) == 0);
}

int main(void) {
    struct ieee80211_sae sae, saved, retry;
    uint8_t out[400], commit[98], auth[34], changed[98];
    uint8_t token[259], low_word_one[32] = {0}, two[32] = {0};
    uint8_t own[6] = {1}, peer[6] = {2}, invalid_password[256] = {0};
    start(&sae);
    assert(ieee80211_sae_test_commit(&sae, local_rand, local_mask, commit) == 0);
    assert(memcmp(commit, local_commit, sizeof(commit)) == 0);
    retry = sae;
    assert(ieee80211_sae_process_commit(&sae, peer_commit, sizeof(peer_commit)) == 0);
    assert(memcmp(sae.kck, kck, 32) == 0);
    assert(memcmp(sae.pmk, pmk, 32) == 0);
    assert(memcmp(sae.pmkid, pmkid, 16) == 0);
    assert(zero(sae.own_rand, sizeof(sae.own_rand)));
    saved = sae;
    assert(ieee80211_sae_process_commit(&sae, peer_commit, sizeof(peer_commit)) == 0);
    assert(memcmp(&sae, &saved, sizeof(sae)) == 0);
    memcpy(changed, peer_commit, sizeof(changed)); changed[2] ^= 1;
    assert(ieee80211_sae_process_commit(&sae, changed, sizeof(changed)) == -1);
    assert(memcmp(&sae, &saved, sizeof(sae)) == 0);
    assert(ieee80211_sae_process_commit(&sae, commit, sizeof(commit)) == 1);
    assert(ieee80211_sae_write_confirm(&sae, auth) == 0);
    assert(auth[0] == 1 && auth[1] == 0); fwrite(auth, 1, sizeof(auth), stdout);
    assert(ieee80211_sae_write_confirm(&sae, auth) == 0);
    assert(auth[0] == 2 && auth[1] == 0); fwrite(auth, 1, sizeof(auth), stdout);
    sae.send_confirm = 65534;
    assert(ieee80211_sae_write_confirm(&sae, auth) == 0);
    assert(auth[0] == 255 && auth[1] == 255); fwrite(auth, 1, sizeof(auth), stdout);
    assert(ieee80211_sae_write_confirm(&sae, out) == 0);
    assert(memcmp(auth, out, sizeof(auth)) == 0);

    /* The AP's first received confirm can be a retransmission (counter 2). */
    assert(fread(auth, 1, sizeof(auth), stdin) == sizeof(auth));
    assert(auth[0] == 2 && auth[1] == 0);
    memcpy(out, auth, sizeof(auth)); out[0] = 0;
    assert(ieee80211_sae_check_confirm(&sae, out, sizeof(auth)) == -1);
    memcpy(out, auth, sizeof(auth)); out[12] ^= 1;
    assert(ieee80211_sae_check_confirm(&sae, out, sizeof(auth)) == -1);
    assert(ieee80211_sae_check_confirm(&sae, auth, sizeof(auth) - 1) == -1);
    assert(ieee80211_sae_check_confirm(&sae, auth, sizeof(auth) + 1) == -1);
    assert(ieee80211_sae_check_confirm(&sae, auth, sizeof(auth)) == 0);
    assert(sae.confirmed && sae.peer_confirm == 2);
    assert(zero(sae.kck, sizeof(sae.kck)) && zero(sae.pwe, sizeof(sae.pwe)));
    assert(memcmp(sae.pmk, pmk, sizeof(pmk)) == 0);
    assert(ieee80211_sae_check_confirm(&sae, auth, sizeof(auth)) == -1);
    assert(ieee80211_sae_process_commit(&sae, peer_commit, sizeof(peer_commit)) == -1);
    assert(ieee80211_sae_write_confirm(&sae, auth) == -1);

    /* Opaque anti-clogging tokens precede the scalar, preserving this commit. */
    for (size_t i = 0; i < sizeof(token); i++) token[i] = (uint8_t)i;
    token[0] = 19; token[1] = 0;
    saved = retry;
    assert(ieee80211_sae_set_token(&retry, token, 2) == -1);
    assert(ieee80211_sae_set_token(&retry, token, sizeof(token)) == -1);
    token[1] = 1;
    assert(ieee80211_sae_set_token(&retry, token, 3) == -1);
    token[1] = 0;
    assert(memcmp(&retry, &saved, sizeof(retry)) == 0);
    assert(ieee80211_sae_set_token(&retry, token, 258) == 0);
    assert(retry.token_len == 256 && retry.token_retries == 1);
    assert(ieee80211_sae_commit_length(&retry) == 354);
    memset(out, 0x9a, sizeof(out));
    assert(ieee80211_sae_new_commit(&retry, out) == -1);
    assert(ieee80211_sae_write_commit(&retry, out, 353) == -1);
    for (size_t i = 0; i < sizeof(out); i++) assert(out[i] == 0x9a);
    assert(ieee80211_sae_write_commit(&retry, out, 354) == 0);
    assert(memcmp(out, token, 258) == 0);
    assert(memcmp(out + 258, local_commit + 2, 96) == 0);
    for (size_t i = 354; i < sizeof(out); i++) assert(out[i] == 0x9a);
    assert(ieee80211_sae_set_token(&retry, token, 3) == 0);
    assert(retry.token_len == 1 && zero(retry.token + 1, 255));
    assert(ieee80211_sae_commit_length(&retry) == 99);
    assert(ieee80211_sae_write_commit(&retry, out, sizeof(out)) == 0);
    assert(memcmp(out, token, 3) == 0 && memcmp(out + 3, local_commit + 2, 96) == 0);
    assert(ieee80211_sae_set_token(&retry, token, 3) == 0);
    saved = retry;
    assert(ieee80211_sae_set_token(&retry, token, 3) == -1);
    assert(memcmp(&retry, &saved, sizeof(retry)) == 0);
    assert(ieee80211_sae_set_token(&sae, token, 3) == -1);

    /* A high scalar with low 64 bits equal to 1 is not scalar 1. */
    start(&sae);
    low_word_one[23] = 1; low_word_one[31] = 1; two[31] = 2;
    assert(ieee80211_sae_test_commit(&sae, low_word_one, two, commit) == 0);
    fwrite(commit, 1, sizeof(commit), stdout);
    assert(ieee80211_sae_test_commit(&sae, two, low_word_one, commit) == 0);
    fwrite(commit, 1, sizeof(commit), stdout);

    /* Failure must not leave an old PMK/ready flag or secret random behind. */
    start(&sae);
    assert(ieee80211_sae_start(&sae, own, own, (const uint8_t *)"x", 1) == -1);
    assert(zero(&sae, sizeof(sae)));
    start(&sae);
    assert(ieee80211_sae_start(&sae, own, peer, NULL, 1) == -1);
    assert(zero(&sae, sizeof(sae)));
    start(&sae);
    assert(ieee80211_sae_start(&sae, own, peer, invalid_password, 0) == -1);
    assert(zero(&sae, sizeof(sae)));
    start(&sae);
    assert(ieee80211_sae_start(&sae, own, peer, invalid_password, 256) == -1);
    assert(zero(&sae, sizeof(sae)));
    start(&sae);
    ieee80211_sae_test_rng(&sae, failed_random, NULL);
    assert(ieee80211_sae_new_commit(&sae, commit) == -1);
    assert(!sae.commit_ready && zero(sae.own_rand, 32));
    assert(zero(sae.own_scalar, 32) && zero(sae.own_element, 64));
    ieee80211_sae_clear(&sae);
    assert(zero(&sae, sizeof(sae)));
    assert(ieee80211_sae_commit_length(NULL) == 0);
    assert(ieee80211_sae_set_token(&sae, token, 3) == -1);
    assert(ieee80211_sae_write_confirm(&sae, auth) == -1);
    return 0;
}
'''

SCALARS = r'''
#include <net80211/ieee80211_sae.h>
#include "sae/uECC.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint8_t sequence[32 * 6];
static size_t offset;
static int sequenced_random(void *arg, uint8_t *out, size_t len) {
    (void)arg;
    if (len != 32 || len > sizeof(sequence) - offset) return -1;
    memcpy(out, sequence + offset, len); offset += len; return 0;
}
static int filled_random(void *arg, uint8_t *out, size_t len) {
    (void)arg; memset(out, 0x22, len); return 0;
}
int main(void) {
    struct ieee80211_sae sae = {0};
    uint8_t a[32], b[32], commit[98];
    unsigned int num, total;
    ieee80211_sae_test_rng(&sae, filled_random, NULL);
    assert(ieee80211_sae_start(&sae, OWN_ADDR, PEER_ADDR,
        (const uint8_t *)"boundary", 8) == 0);
    assert(fread(&total, 1, sizeof(total), stdin) == sizeof(total));
    for (num = 0; num < total; num++) {
        assert(fread(a, 1, 32, stdin) == 32);
        assert(fread(b, 1, 32, stdin) == 32);
        int result = ieee80211_sae_test_commit(&sae, a, b, commit);
        fputc(result == 0, stdout);
        if (result == 0) fwrite(commit, 1, sizeof(commit), stdout);
    }
    /* New commits resample when (rand + mask) mod order is 0 or 1. */
    assert(fread(sequence, 1, sizeof(sequence), stdin) == sizeof(sequence));
    sae.commit_ready = 0;
    ieee80211_sae_test_rng(&sae, sequenced_random, NULL);
    assert(ieee80211_sae_new_commit(&sae, commit) == 0);
    assert(offset == sizeof(sequence));
    fwrite(commit, 1, sizeof(commit), stdout);
    return 0;
}
'''

PWES = r'''
#include <net80211/ieee80211_sae.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned int calls;
static uint8_t fill;
static int filled_random(void *arg, uint8_t *out, size_t len) {
    (void)arg; memset(out, fill, len); calls++; return 0;
}
int main(void) {
    uint8_t head[15], password[256];
    while (fread(head, 1, sizeof(head), stdin) == sizeof(head)) {
        struct ieee80211_sae sae = {0};
        size_t len = head[12] | ((size_t)head[13] << 8);
        assert(len <= sizeof(password));
        assert(fread(password, 1, len, stdin) == len);
        fill = head[14]; calls = 0;
        ieee80211_sae_test_rng(&sae, filled_random, NULL);
        int result = ieee80211_sae_start(&sae, head, head + 6, password, len);
        fputc(result == 0, stdout);
        fwrite(&calls, 1, sizeof(calls), stdout);
        if (result == 0) fwrite(sae.pwe, 1, sizeof(sae.pwe), stdout);
        ieee80211_sae_clear(&sae);
    }
    return feof(stdin) ? 0 : 1;
}
'''

EXCHANGES = r'''
#include <net80211/ieee80211_sae.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int filled_random(void *arg, uint8_t *out, size_t len) {
    (void)arg; memset(out, 0x12, len); return 0;
}
int main(void) {
    uint8_t randoms[128];
    unsigned int index = 0;
    while (fread(randoms, 1, sizeof(randoms), stdin) == sizeof(randoms)) {
        struct ieee80211_sae a = {0}, b = {0};
        uint8_t ca[98], cb[98];
        ieee80211_sae_test_rng(&a, filled_random, NULL);
        assert(ieee80211_sae_start(&a, OWN_ADDR, PEER_ADDR,
            (const uint8_t *)"exchange", 8) == 0);
        ieee80211_sae_test_rng(&b, filled_random, NULL);
        assert(ieee80211_sae_start(&b, PEER_ADDR, OWN_ADDR,
            (const uint8_t *)"exchange", 8) == 0);
        assert(ieee80211_sae_test_commit(&a, randoms, randoms + 32, ca) == 0);
        assert(ieee80211_sae_test_commit(&b, randoms + 64, randoms + 96, cb) == 0);
        int ra = ieee80211_sae_process_commit(&a, cb, sizeof(cb));
        int rb = ieee80211_sae_process_commit(&b, ca, sizeof(ca));
        if (ra || rb) fprintf(stderr, "exchange %u: a=%d b=%d\n", index, ra, rb);
        assert(ra == 0 && rb == 0);
        assert(memcmp(a.kck, b.kck, 32) == 0);
        assert(memcmp(a.pmk, b.pmk, 32) == 0);
        assert(memcmp(a.pmkid, b.pmkid, 16) == 0);
        fwrite(ca, 1, sizeof(ca), stdout); fwrite(cb, 1, sizeof(cb), stdout);
        fwrite(a.kck, 1, 32, stdout); fwrite(a.pmk, 1, 32, stdout);
        fwrite(a.pmkid, 1, 16, stdout);
        index++;
    }
    return feof(stdin) ? 0 : 1;
}
'''


def compile_helper(path, text, stubs):
    source = path.with_suffix(".c")
    binary = path.with_suffix(".out")
    source.write_text(text)
    subprocess.run([
        "clang", "-std=c11", "-O1", "-g", f"-fsanitize={SANITIZERS}",
        "-fno-sanitize-recover=all", "-Wno-unknown-attributes", "-D_DEFAULT_SOURCE",
        "-DIEEE80211_SAE_TESTING",
        "-DOWN_ADDR=((const uint8_t[6]){" +
        ",".join(str(b) for b in OWN) + "})",
        "-DPEER_ADDR=((const uint8_t[6]){" +
        ",".join(str(b) for b in PEER) + "})",
        f"-I{stubs}", f"-I{NET.parent}", f"-I{NET}", str(NET / "ieee80211_sae.c"),
        str(NET / "sae" / "uECC.c"),
        *(str(NET.parent / "crypto" / name) for name in ("sha1.c", "sha2.c", "md5.c", "hmac.c")),
        str(source), "-o", str(binary)
    ], check=True)
    return binary


def run(binary, *args):
    result = subprocess.run([binary, *args], capture_output=True)
    if result.returncode:
        print(result.stdout.decode(errors="replace"))
        print(result.stderr.decode(errors="replace"))
        result.check_returncode()
    return result.stdout


with tempfile.TemporaryDirectory() as directory:
    work = Path(directory)
    stubs = work / "stubs"
    (stubs / "sys").mkdir(parents=True)
    (stubs / "types.h").write_text("""
#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
""")
    (stubs / "sys/systm.h").write_text("""
#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#ifndef BYTE_ORDER
#define BYTE_ORDER __BYTE_ORDER__
#define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#define BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif
""")
    (stubs / "sys/_endian.h").write_text("""
#define _OSSwapInt32(x) __builtin_bswap32(x)
#define _OSSwapInt64(x) __builtin_bswap64(x)
""")
    (stubs / "sys/_arc4random.h").write_text("""
#include <stdlib.h>
/* Every valid test installs a deterministic RNG; accidental fallback fails. */
static void test_unexpected_random(void *out, size_t len) {
    (void)out; (void)len; abort();
}
#define arc4random_buf test_unexpected_random
""")

    def word(fill):
        return bytes([fill]) * 32

    random_path = work / "random.bin"
    # Derive once first so the helper and the Python reference use the same
    # number of Hunting-and-Pecking rounds.
    pwe, rounds = derive_pwe(OWN, PEER, PASSWORD.encode())
    stream = bytes([0x77]) * len(PASSWORD.encode()) + word(0x11) * rounds + word(0x22) + word(0x33)
    stream += bytes([0x88]) * len(PASSWORD.encode()) + word(0x11) * rounds + word(0x44) + word(0x55)
    random_path.write_bytes(stream)

    run(compile_helper(work / "sae-reject", REJECTION, stubs))
    cases = [(G, G), (G, point_mul(G, 2)), (G, point_mul(G, N - 1)),
             (G, negate(G)), ((0, 0), G)]
    for index in range(12):
        a = point_mul(G, int.from_bytes(hashlib.sha256(b"a" + bytes([index])).digest(), "big") % (N - 1) + 1)
        b = point_mul(G, int.from_bytes(hashlib.sha256(b"b" + bytes([index])).digest(), "big") % (N - 1) + 1)
        cases.extend([(a, a), (a, b), (a, negate(a))])
    wire = b"".join(point_bytes(a) + point_bytes(b) for a, b in cases)
    points = subprocess.run([compile_helper(work / "sae-points", POINTS, stubs)],
                            input=wire, capture_output=True, check=True).stdout
    offset = 0
    for a, b in cases:
        expected = point_add(a, b) if on_curve(a) and on_curve(b) else None
        ok = points[offset]
        offset += 1
        assert ok == (expected is not None), (a, b, expected)
        if expected is not None:
            assert points[offset:offset + 64] == point_bytes(expected)
            offset += 64
    assert offset == len(points)
    output = run(compile_helper(work / "sae-helper", HELPER, stubs),
                 random_path, PASSWORD)
    assert len(output) == 98 * 2 + 34 * 2 + 16 + 32
    commit_a, commit_b = output[:98], output[98:196]
    confirm_a, confirm_b = output[196:230], output[230:264]
    pmkid = output[264:280]
    pmk = output[280:312]

    values = {fill: int.from_bytes(word(fill), "big")
              for fill in (0x22, 0x33, 0x44, 0x55)}
    scalar_a, scalar_b, element_a, element_b, context, keys = material(
        values[0x22], values[0x33], values[0x44], values[0x55], pwe)

    assert commit_a == bytes([19, 0]) + b32(scalar_a) + point_bytes(element_a)
    assert commit_b == bytes([19, 0]) + b32(scalar_b) + point_bytes(element_b)
    assert confirm_a[:2] == b"\x01\x00"
    assert confirm_b[:2] == b"\x01\x00"
    assert confirm_a[2:] == confirm(
        keys[:32], b32(scalar_a), point_bytes(element_a),
        b32(scalar_b), point_bytes(element_b))
    assert confirm_b[2:] == confirm(
        keys[:32], b32(scalar_b), point_bytes(element_b),
        b32(scalar_a), point_bytes(element_a))
    assert pmkid == context[:16]
    assert pmk == keys[32:]

    fixed = {name: bytes.fromhex(value) for name, value in ANNEX.items()}
    declarations = "\n".join(
        "static const unsigned char " + name + "[] = {" +
        ",".join(str(byte) for byte in data) + "};"
        for name, data in fixed.items())
    ap_confirm = b"\x02\x00" + confirm(fixed["kck"], fixed["peer_commit"][2:34],
        fixed["peer_commit"][34:], fixed["local_commit"][2:34],
        fixed["local_commit"][34:], counter=2)
    annex = subprocess.run([compile_helper(work / "sae-annex", declarations + ANNEX_HELPER, stubs)],
        input=ap_confirm, capture_output=True)
    if annex.returncode:
        print(annex.stderr.decode(errors="replace"))
    annex.check_returncode()
    assert len(annex.stdout) == 34 * 3 + 98 * 2
    for index, counter in enumerate((1, 2, 65535)):
        assert annex.stdout[index * 34:(index + 1) * 34] == counter.to_bytes(2, "little") + confirm(
            fixed["kck"], fixed["local_commit"][2:34], fixed["local_commit"][34:],
            fixed["peer_commit"][2:34], fixed["peer_commit"][34:], counter)
    pwe_annex, _ = derive_pwe(bytes.fromhex("4d3f2fffe387"),
        bytes.fromhex("a5d8aa958e3c"), b"mekmitasdigoat")
    for index, mask in enumerate((2, 2**64 + 1)):
        assert annex.stdout[102 + index * 98:102 + (index + 1) * 98] == (
            b"\x13\x00" + b32(2**64 + 3) + point_bytes(negate(point_mul(pwe_annex, mask))))

    import struct
    pairs = [(0, 2), (1, 2), (N, 2), (N + 1, 2), (2, 0), (2, 1), (2, N),
             (2, N + 1), (2, N - 2), (2, N - 1), (N - 1, N - 1),
             (2, 2), (2**64 + 1, 2), (2, 2**64 + 1)]
    pairs += [(3, N - delta) for delta in range(1, 17)]
    pairs += [(delta + 2, N - delta) for delta in range(1, 33)]
    scalars_wire = struct.pack("=I", len(pairs)) + b"".join(b32(a) + b32(b) for a, b in pairs)
    scalars_wire += b32(2) + b32(N - 2) + b32(2) + b32(N - 1) + b32(2) + b32(3)
    scalars = subprocess.run([compile_helper(work / "sae-scalars", SCALARS, stubs)],
        input=scalars_wire, capture_output=True)
    if scalars.returncode:
        print(scalars.stderr.decode(errors="replace"))
    scalars.check_returncode()
    pwe_boundary, _ = derive_pwe(OWN, PEER, b"boundary")
    offset = 0
    failures = []
    for rand, mask in pairs:
        expected = 1 < rand < N and 1 < mask < N and (rand + mask) % N > 1
        actual = scalars.stdout[offset]
        if actual != expected:
            failures.append((rand, mask, actual, expected))
        offset += 1
        if actual:
            assert scalars.stdout[offset:offset + 98] == (b"\x13\x00" + b32((rand + mask) % N) +
                point_bytes(negate(point_mul(pwe_boundary, mask))))
            offset += 98
    assert not failures, failures
    assert scalars.stdout[offset:] == b"\x13\x00" + b32(5) + point_bytes(negate(point_mul(pwe_boundary, 3)))

    passwords = [b"x", b"password", bytes(32), bytes(range(64)), b"\xff" * 63,
                 bytes(range(255)), b"x" * 255, PASSWORD.encode()]
    pwe_cases = [(own, peer, password, fill) for password in passwords
                 for own, peer, fill in ((OWN, PEER, 0x11), (PEER, OWN, 0x12))]
    pwe_cases += [(OWN, PEER, b"", 0x11), (OWN, PEER, bytes(256), 0x12), (OWN, OWN, b"x", 0x11)]
    pwe_wire = b"".join(own + peer + len(password).to_bytes(2, "little") + bytes([fill]) + password
                        for own, peer, password, fill in pwe_cases)
    pwes = subprocess.run([compile_helper(work / "sae-pwes", PWES, stubs)],
        input=pwe_wire, capture_output=True)
    if pwes.returncode:
        print(pwes.stderr.decode(errors="replace"))
    pwes.check_returncode()
    offset = 0
    for own, peer, password, fill in pwe_cases:
        expected = own != peer and 0 < len(password) <= 255
        assert pwes.stdout[offset] == expected
        calls = struct.unpack("=I", pwes.stdout[offset + 1:offset + 5])[0]
        offset += 5
        if expected:
            assert calls == 41  # One dummy password, then forty blinded H&P rounds.
            assert pwes.stdout[offset:offset + 64] == point_bytes(derive_pwe(own, peer, password)[0])
            offset += 64
        else:
            assert calls == 0
    assert offset == len(pwes.stdout)

    exchanges = [(N - 1, N - 1, N - 3, 2), (2, N - 4, N - 1, N - 1),
                 (2**64 + 1, 3, 4, 2**64 + 1), (2, 3, 3, 2)]
    for index in range(8):
        exchanges.append(tuple(int.from_bytes(hashlib.sha256(bytes([index, word])).digest(), "big") % (N - 2) + 2
                               for word in range(4)))
    exchange_wire = b"".join(b32(value) for row in exchanges for value in row)
    exchange_result = subprocess.run([compile_helper(work / "sae-exchanges", EXCHANGES, stubs)],
        input=exchange_wire, capture_output=True)
    if exchange_result.returncode:
        print(exchange_result.stderr.decode(errors="replace"))
    exchange_result.check_returncode()
    pwe_exchange = derive_pwe(OWN, PEER, b"exchange")[0]
    assert len(exchange_result.stdout) == len(exchanges) * 276
    for index, values in enumerate(exchanges):
        scalar_a, scalar_b, element_a, element_b, context, keys = material(*values, pwe_exchange)
        expected = (b"\x13\x00" + b32(scalar_a) + point_bytes(element_a) +
                    b"\x13\x00" + b32(scalar_b) + point_bytes(element_b) + keys + context[:16])
        assert exchange_result.stdout[index * 276:(index + 1) * 276] == expected

print(f"PASS SAE IEEE Annex J.10 KCK/PMK/PMKID, independent P-256/confirm vectors, "
      f"scalar boundaries, retry/token bounds, rejection and zeroization ({SANITIZERS}).")
