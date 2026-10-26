/*
 * Simultaneous Authentication of Equals (SAE), IEEE 802.11 group 19.
 * Hunting-and-Pecking, commit/confirm, KCK/PMK and PMKID derivation.
 *
 * Protocol portions follow hostap's src/common/sae.c and dragonfly.c,
 * Copyright (c) 2012-2016 Jouni Malinen and contributors, BSD license.
 * See sae/LICENSE-hostap.txt for the distribution terms.
 * P-256 arithmetic uses micro-ecc; see sae/LICENSE-micro-ecc.txt.
 * Only the station role is implemented. No password or key is logged.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/_arc4random.h>
#include <crypto/sha1.h>
#include <crypto/hmac.h>
#include <net80211/ieee80211_sae.h>
#include "sae/uECC.h"
#include "sae/uECC_vli.h"

#define SAE_WORDS 4
#define SAE_PWE_LOOPS 40

static void
sae_bzero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--)
        *p++ = 0;
}

static void
sae_to_native(uECC_word_t *out, const uint8_t *in)
{
    uECC_vli_bytesToNative(out, in, 32);
}

static void
sae_to_bytes(uint8_t *out, const uECC_word_t *in)
{
    uECC_vli_nativeToBytes(out, 32, in);
}

static void
sae_point_to_native(uECC_word_t *out, const uint8_t *in)
{
    sae_to_native(out, in);
    sae_to_native(out + SAE_WORDS, in + 32);
}

static void
sae_hmacv(const uint8_t *key, size_t key_len, const uint8_t **parts,
    const size_t *lens, unsigned int count, uint8_t out[32])
{
    HMAC_SHA256_CTX ctx;
    unsigned int i;

    HMAC_SHA256_Init(&ctx, key, key_len);
    for (i = 0; i < count; i++) {
        if (parts[i] && lens[i])
            HMAC_SHA256_Update(&ctx, parts[i], lens[i]);
    }
    HMAC_SHA256_Final(out, &ctx);
    sae_bzero(&ctx, sizeof(ctx));
}

static void
sae_kdf(const uint8_t *key, const char *label, const uint8_t *context,
    size_t context_len, uint8_t *out, size_t out_len)
{
    uint8_t counter[2], length[2], digest[32];
    const uint8_t *parts[4];
    size_t lens[4], pos = 0, n;
    uint16_t i;

    /* IEEE 802.11 KDF-Hash-Length encodes both fields little-endian. */
    length[0] = (out_len * 8) & 0xff;
    length[1] = (out_len * 8) >> 8;
    for (i = 1; pos < out_len; i++) {
        counter[0] = i & 0xff;
        counter[1] = i >> 8;
        parts[0] = counter; lens[0] = 2;
        parts[1] = (const uint8_t *)label; lens[1] = strlen(label);
        parts[2] = context; lens[2] = context_len;
        parts[3] = length; lens[3] = 2;
        n = out_len - pos;
        if (n > sizeof(digest))
            n = sizeof(digest);
        sae_hmacv(key, 32, parts, lens, 4, digest);
        memcpy(out + pos, digest, n);
        pos += n;
    }
    sae_bzero(digest, sizeof(digest));
}

static int
sae_random(struct ieee80211_sae *sae, uint8_t *out, size_t len)
{
#ifdef IEEE80211_SAE_TESTING
    if (sae->random)
        return sae->random(sae->random_arg, out, len) == 0 ? 0 : -1;
#endif
    arc4random_buf(out, len);
    return 0;
}

static int
sae_random_bn(struct ieee80211_sae *sae, const uECC_word_t *mod,
    int allow_one, uint8_t *out)
{
    uECC_word_t n[SAE_WORDS], one[SAE_WORDS] = {1};
    unsigned int i;
    int ret = -1;

    for (i = 0; i < 100; i++) {
        if (sae_random(sae, out, 32) != 0)
            break;
        sae_to_native(n, out);
        if (uECC_vli_cmp(mod, n, SAE_WORDS) != 1 ||
            uECC_vli_isZero(n, SAE_WORDS))
            continue;
        if (!allow_one && uECC_vli_equal(n, one, SAE_WORDS))
            continue;
        ret = 0;
        break;
    }
    sae_bzero(n, sizeof(n));
    if (ret != 0)
        sae_bzero(out, 32);
    return ret;
}

static const uECC_word_t *sae_prime(void)
{
    return uECC_curve_p(uECC_secp256r1());
}

static const uECC_word_t *sae_order(void)
{
    return uECC_curve_n(uECC_secp256r1());
}

static void
sae_pow_p(uECC_word_t *out, const uECC_word_t *base,
    const uECC_word_t *exponent)
{
    uECC_Curve curve = uECC_secp256r1();
    uECC_word_t result[SAE_WORDS] = {1};
    int bit;

    /* The exponent is public: either (p-1)/2 or (p+1)/4. */
    for (bit = 255; bit >= 0; bit--) {
        uECC_vli_modSquare_fast(result, result, curve);
        if (uECC_vli_testBit(exponent, bit))
            uECC_vli_modMult_fast(result, result, base, curve);
    }
    uECC_vli_set(out, result, SAE_WORDS);
    sae_bzero(result, sizeof(result));
}

static int
sae_is_qr(const uECC_word_t *value)
{
    uECC_word_t exponent[SAE_WORDS], one[SAE_WORDS] = {1}, out[SAE_WORDS];
    int ret;

    uECC_vli_sub(exponent, sae_prime(), one, SAE_WORDS);
    uECC_vli_rshift1(exponent, SAE_WORDS);
    sae_pow_p(out, value, exponent);
    ret = uECC_vli_equal(out, one, SAE_WORDS) == 1;
    sae_bzero(out, sizeof(out));
    return ret;
}

static uint8_t
sae_bytes_lt(const uint8_t a[32], const uint8_t b[32])
{
    uint16_t borrow = 0;
    int i;

    for (i = 31; i >= 0; i--)
        borrow = ((uint16_t)((uint16_t)a[i] - b[i] - borrow)) >> 15;
    return borrow;
}

static void
sae_rhs(uECC_word_t *out, const uint8_t *x)
{
    uECC_word_t xn[SAE_WORDS], reduced[SAE_WORDS], borrow, keep;
    unsigned int i;

    sae_to_native(xn, x);
    borrow = uECC_vli_sub(reduced, xn, sae_prime(), SAE_WORDS);
    keep = (uECC_word_t)0 - borrow;
    for (i = 0; i < SAE_WORDS; i++)
        xn[i] = (xn[i] & keep) | (reduced[i] & ~keep);
    uECC_sae_x_side(out, xn);
    sae_bzero(xn, sizeof(xn));
    sae_bzero(reduced, sizeof(reduced));
}

static int
sae_derive_pwe(struct ieee80211_sae *sae, const uint8_t *password,
    size_t password_len)
{
    static const char label[] = "SAE Hunting and Pecking";
    uint8_t addrs[12], prime_bin[32], seed[32], value[32];
    uint8_t x[32], chosen[64], rbin[32], opposite[32];
    uint8_t stub_password[IEEE80211_SAE_MAX_PASSWORD_LEN];
    uint8_t candidate_password[IEEE80211_SAE_MAX_PASSWORD_LEN];
    uECC_word_t r[SAE_WORDS], rhs[SAE_WORDS], num[SAE_WORDS];
    uECC_word_t blinded[SAE_WORDS];
    uECC_word_t qnr[SAE_WORDS], exponent[SAE_WORDS], one[SAE_WORDS] = {1};
    uint8_t counter, selected_odd = 0, found = 0;
    int ok = -1;

    if (password_len == 0 ||
        password_len > IEEE80211_SAE_MAX_PASSWORD_LEN)
        return -1;
    if (sae_random(sae, stub_password, password_len) != 0)
        goto out;
    if (memcmp(sae->own_addr, sae->peer_addr, 6) > 0) {
        memcpy(addrs, sae->own_addr, 6);
        memcpy(addrs + 6, sae->peer_addr, 6);
    } else {
        memcpy(addrs, sae->peer_addr, 6);
        memcpy(addrs + 6, sae->own_addr, 6);
    }
    sae_to_bytes(prime_bin, sae_prime());
    memset(x, 0, sizeof(x));
    memset(rbin, 0, sizeof(rbin));
    rbin[31] = 3; /* qnr = 3; Legendre(3, p) = -1 for P-256. */
    sae_to_native(qnr, rbin);
    for (counter = 1; counter <= SAE_PWE_LOOPS || !found; counter++) {
        uint8_t odd, valid, is_qr, accept, take;
        unsigned int j;

        if (counter == 0 || counter > 200)
            goto out;
        {
            const uint8_t *parts[2] = { candidate_password, &counter };
            size_t lens[2] = { password_len, 1 };

            /* Once found, run the remaining blinding rounds on random data. */
            for (j = 0; j < password_len; j++)
                candidate_password[j] = (password[j] & (uint8_t)~found) |
                    (stub_password[j] & found);
            sae_hmacv(addrs, sizeof(addrs), parts, lens, 2, seed);
        }
        sae_kdf(seed, label, prime_bin, sizeof(prime_bin), value, 32);
        odd = seed[31] & 1;
        valid = sae_bytes_lt(value, prime_bin);
        sae_rhs(rhs, value);
        if (sae_random_bn(sae, sae_prime(), 1, rbin) != 0)
            goto out;
        sae_to_native(r, rbin);
        /* Blind rhs by r^2, optionally multiplied by the public qnr. */
        uECC_vli_modSquare_fast(num, r, uECC_secp256r1());
        uECC_vli_modMult_fast(num, num, rhs, uECC_secp256r1());
        uECC_vli_modMult_fast(blinded, num, qnr, uECC_secp256r1());
        {
            uECC_word_t even_mask = (uECC_word_t)0 - ((r[0] & 1) ^ 1);
            for (j = 0; j < SAE_WORDS; j++)
                num[j] = (num[j] & ~even_mask) | (blinded[j] & even_mask);
        }
        is_qr = sae_is_qr(num) ^ ((r[0] & 1) == 0);
        accept = valid & is_qr;
        take = (uint8_t)(0 - accept) & (uint8_t)~found;
        for (j = 0; j < 32; j++)
            x[j] = (x[j] & ~take) | (value[j] & take);
        selected_odd = (selected_odd & ~take) | (odd & take);
        found |= (uint8_t)(0 - accept);
    }
    /* y = sqrt(x^3 - 3x + b), with the sign selected by pwd-seed. */
    sae_rhs(rhs, x);
    uECC_vli_add(exponent, sae_prime(), one, SAE_WORDS);
    uECC_vli_rshift1(exponent, SAE_WORDS);
    uECC_vli_rshift1(exponent, SAE_WORDS);
    sae_pow_p(rhs, rhs, exponent);
    sae_to_bytes(chosen + 32, rhs);
    {
        uint8_t negate_mask = 0 - ((chosen[63] & 1) ^ selected_odd);
        unsigned int j;

        uECC_vli_sub(rhs, sae_prime(), rhs, SAE_WORDS);
        sae_to_bytes(opposite, rhs);
        for (j = 0; j < 32; j++)
            chosen[j + 32] = (chosen[j + 32] & (uint8_t)~negate_mask) |
                (opposite[j] & negate_mask);
    }
    memcpy(chosen, x, 32);
    if (!uECC_valid_public_key(chosen, uECC_secp256r1()))
        goto out;
    memcpy(sae->pwe, chosen, sizeof(sae->pwe));
    sae->pwe_ready = 1;
    ok = 0;
out:
    sae_bzero(addrs, sizeof(addrs));
    sae_bzero(prime_bin, sizeof(prime_bin));
    sae_bzero(seed, sizeof(seed));
    sae_bzero(value, sizeof(value));
    sae_bzero(x, sizeof(x));
    sae_bzero(chosen, sizeof(chosen));
    sae_bzero(opposite, sizeof(opposite));
    sae_bzero(stub_password, sizeof(stub_password));
    sae_bzero(candidate_password, sizeof(candidate_password));
    sae_bzero(rbin, sizeof(rbin));
    sae_bzero(r, sizeof(r));
    sae_bzero(rhs, sizeof(rhs));
    sae_bzero(num, sizeof(num));
    sae_bzero(blinded, sizeof(blinded));
    sae_bzero(qnr, sizeof(qnr));
    sae_bzero(exponent, sizeof(exponent));
    return ok;
}

void
ieee80211_sae_clear(struct ieee80211_sae *sae)
{
    if (sae)
        sae_bzero(sae, sizeof(*sae));
}

#ifdef IEEE80211_SAE_TESTING
void
ieee80211_sae_test_rng(struct ieee80211_sae *sae,
    int (*random)(void *, uint8_t *, size_t), void *arg)
{
    sae->random = random;
    sae->random_arg = arg;
}

int
ieee80211_sae_test_pwe(struct ieee80211_sae *sae, const uint8_t own[6],
    const uint8_t peer[6], const uint8_t *password, size_t len,
    uint8_t out[64])
{
    if (ieee80211_sae_start(sae, own, peer, password, len) != 0)
        return -1;
    memcpy(out, sae->pwe, 64);
    return 0;
}
#endif

int
ieee80211_sae_start(struct ieee80211_sae *sae, const uint8_t own[6],
    const uint8_t peer[6], const uint8_t *password, size_t len)
{
#ifdef IEEE80211_SAE_TESTING
    int (*rng)(void *, uint8_t *, size_t) = sae ? sae->random : NULL;
    void *arg = sae ? sae->random_arg : NULL;
#endif
    int ret;

    if (!sae)
        return -1;
    ieee80211_sae_clear(sae);
    if (!own || !peer || !password || !memcmp(own, peer, 6))
        return -1;
#ifdef IEEE80211_SAE_TESTING
    sae->random = rng;
    sae->random_arg = arg;
#endif
    memcpy(sae->own_addr, own, 6);
    memcpy(sae->peer_addr, peer, 6);
    ret = sae_derive_pwe(sae, password, len);
    if (ret != 0)
        ieee80211_sae_clear(sae);
    return ret;
}

static void
sae_encode_commit(struct ieee80211_sae *sae, uint8_t out[98])
{
    out[0] = IEEE80211_SAE_GROUP;
    out[1] = 0;
    memcpy(out + 2, sae->own_scalar, 32);
    memcpy(out + 34, sae->own_element, 64);
}

static int
sae_make_commit(struct ieee80211_sae *sae)
{
    uECC_word_t pwe[2 * SAE_WORDS];
    uint8_t mask[32];
    unsigned int attempt;
    int ret = -1;

    if (!sae->pwe_ready)
        return -1;
    sae_point_to_native(pwe, sae->pwe);
    for (attempt = 0; attempt < 100; attempt++) {
        if (sae_random_bn(sae, sae_order(), 0, sae->own_rand) != 0 ||
            sae_random_bn(sae, sae_order(), 0, mask) != 0)
            goto out;
        /* The sum must also exclude 0 and 1, even for valid rand/mask. */
        if (!uECC_sae_commit(pwe, sae->own_rand, mask, sae->own_scalar,
            sae->own_element))
            continue;
        sae->commit_ready = 1;
        ret = 0;
        break;
    }
out:
    sae_bzero(pwe, sizeof(pwe));
    sae_bzero(mask, sizeof(mask));
    if (ret != 0) {
        sae_bzero(sae->own_rand, sizeof(sae->own_rand));
        sae_bzero(sae->own_scalar, sizeof(sae->own_scalar));
        sae_bzero(sae->own_element, sizeof(sae->own_element));
    }
    return ret;
}

#ifdef IEEE80211_SAE_TESTING
int
ieee80211_sae_test_commit(struct ieee80211_sae *sae, const uint8_t rnd[32],
    const uint8_t mask[32], uint8_t out[98])
{
    uECC_word_t pwe[2 * SAE_WORDS];
    int ok;

    if (!sae->pwe_ready)
        return -1;
    sae_point_to_native(pwe, sae->pwe);
    ok = uECC_sae_commit(pwe, rnd, mask, sae->own_scalar,
        sae->own_element);
    sae_bzero(pwe, sizeof(pwe));
    if (!ok)
        return -1;
    memcpy(sae->own_rand, rnd, 32);
    sae->commit_ready = 1;
    sae_encode_commit(sae, out);
    return 0;
}
#endif

int
ieee80211_sae_new_commit(struct ieee80211_sae *sae, uint8_t out[98])
{
    return ieee80211_sae_write_commit(sae, out, IEEE80211_SAE_COMMIT_LEN);
}

size_t
ieee80211_sae_commit_length(const struct ieee80211_sae *sae)
{
    if (!sae || sae->token_len > sizeof(sae->token))
        return 0;
    return IEEE80211_SAE_COMMIT_LEN + sae->token_len;
}

int
ieee80211_sae_set_token(struct ieee80211_sae *sae, const uint8_t *buf,
    size_t len)
{
    /* H&P status 76 carries group followed by the opaque AP token. */
    if (!sae || !buf || len <= 2 || len > 2 + sizeof(sae->token) ||
        buf[0] != IEEE80211_SAE_GROUP || buf[1] != 0 ||
        !sae->commit_ready || sae->peer_ready || sae->confirmed ||
        sae->token_retries >= IEEE80211_SAE_MAX_TOKEN_RETRIES)
        return -1;
    sae_bzero(sae->token, sizeof(sae->token));
    memcpy(sae->token, buf + 2, len - 2);
    sae->token_len = len - 2;
    sae->token_retries++;
    return 0;
}

int
ieee80211_sae_write_commit(struct ieee80211_sae *sae, uint8_t *out,
    size_t capacity)
{
    size_t length = ieee80211_sae_commit_length(sae);

    if (!sae || !out || !length || capacity < length || sae->confirmed)
        return -1;
    if (!sae->commit_ready && sae_make_commit(sae) != 0)
        return -1;
    out[0] = IEEE80211_SAE_GROUP;
    out[1] = 0;
    memcpy(out + 2, sae->token, sae->token_len);
    memcpy(out + 2 + sae->token_len, sae->own_scalar, 32);
    memcpy(out + 34 + sae->token_len, sae->own_element, 64);
    return 0;
}

int
ieee80211_sae_process_commit(struct ieee80211_sae *sae, const uint8_t *buf,
    size_t len)
{
    uECC_word_t pwe[2 * SAE_WORDS], peer[2 * SAE_WORDS];
    uECC_word_t peer_scalar[SAE_WORDS], own_scalar[SAE_WORDS];
    uECC_word_t own_rand[SAE_WORDS], sum[SAE_WORDS];
    uint8_t k[32];
    int ret = -1;

    if (!sae || !buf || len != IEEE80211_SAE_COMMIT_LEN ||
        !sae->commit_ready || sae->confirmed ||
        buf[0] != IEEE80211_SAE_GROUP || buf[1] != 0)
        return -1;
    if (!memcmp(buf + 2, sae->own_scalar, 32) &&
        !memcmp(buf + 34, sae->own_element, 64))
        return 1; /* reflected commit: silently discard */
    /* A retried commit must use the already derived keys, not erased rand. */
    if (sae->peer_ready)
        return !memcmp(buf + 2, sae->peer_scalar, 32) &&
            !memcmp(buf + 34, sae->peer_element, 64) ? 0 : -1;
    sae_to_native(peer_scalar, buf + 2);
    {
        uECC_word_t one[SAE_WORDS] = {1};
        if (uECC_vli_isZero(peer_scalar, SAE_WORDS) ||
            uECC_vli_equal(peer_scalar, one, SAE_WORDS) ||
            uECC_vli_cmp(sae_order(), peer_scalar, SAE_WORDS) != 1 ||
            !uECC_valid_public_key(buf + 34, uECC_secp256r1()))
            goto out;
    }
    sae_point_to_native(pwe, sae->pwe);
    sae_point_to_native(peer, buf + 34);
    sae_to_native(own_rand, sae->own_rand);
    if (!uECC_sae_derive_k(pwe, peer, peer_scalar, own_rand, k))
        goto out;
    {
        uint8_t zero[32] = {0}, seed[32], keys[64], context[32];
        static const char label[] = "SAE KCK and PMK";
        const uint8_t *parts[1] = { k };
        size_t lens[1] = { sizeof(k) };

        sae_hmacv(zero, sizeof(zero), parts, lens, 1, seed);
        sae_to_native(own_scalar, sae->own_scalar);
        uECC_vli_modAdd(sum, own_scalar, peer_scalar, sae_order(),
            SAE_WORDS);
        sae_to_bytes(context, sum);
        sae_kdf(seed, label, context, sizeof(context), keys, sizeof(keys));
        memcpy(sae->kck, keys, 32);
        memcpy(sae->pmk, keys + 32, 32);
        memcpy(sae->pmkid, context, 16);
        memcpy(sae->peer_scalar, buf + 2, 32);
        memcpy(sae->peer_element, buf + 34, 64);
        sae->peer_ready = 1;
        sae_bzero(sae->own_rand, sizeof(sae->own_rand));
        sae_bzero(seed, sizeof(seed));
        sae_bzero(keys, sizeof(keys));
        sae_bzero(context, sizeof(context));
        ret = 0;
    }
out:
    sae_bzero(pwe, sizeof(pwe));
    sae_bzero(peer, sizeof(peer));
    sae_bzero(peer_scalar, sizeof(peer_scalar));
    sae_bzero(own_scalar, sizeof(own_scalar));
    sae_bzero(own_rand, sizeof(own_rand));
    sae_bzero(sum, sizeof(sum));
    sae_bzero(k, sizeof(k));
    return ret;
}

static void
sae_confirm(const uint8_t kck[32], uint16_t send_confirm,
    const uint8_t *scalar1, const uint8_t *element1,
    const uint8_t *scalar2, const uint8_t *element2, uint8_t out[32])
{
    uint8_t sc[2];
    const uint8_t *parts[5] = { sc, scalar1, element1, scalar2, element2 };
    size_t lens[5] = { 2, 32, 64, 32, 64 };

    sc[0] = send_confirm;
    sc[1] = send_confirm >> 8;
    sae_hmacv(kck, 32, parts, lens, 5, out);
}

int
ieee80211_sae_write_confirm(struct ieee80211_sae *sae, uint8_t out[34])
{
    if (!sae || !out || !sae->peer_ready || !sae->commit_ready ||
        sae->confirmed)
        return -1;
    if (sae->send_confirm != 0xffff)
        sae->send_confirm++;
    out[0] = sae->send_confirm;
    out[1] = sae->send_confirm >> 8;
    sae_confirm(sae->kck, sae->send_confirm,
        sae->own_scalar, sae->own_element,
        sae->peer_scalar, sae->peer_element, out + 2);
    return 0;
}

int
ieee80211_sae_check_confirm(struct ieee80211_sae *sae, const uint8_t *buf,
    size_t len)
{
    uint8_t verifier[32];
    uint16_t sc;
    uint8_t diff = 0;
    unsigned int i;

    if (!sae || !buf || len != IEEE80211_SAE_CONFIRM_LEN ||
        !sae->peer_ready || !sae->commit_ready || sae->confirmed)
        return -1;
    sc = buf[0] | ((uint16_t)buf[1] << 8);
    if (sc == 0 || sc <= sae->peer_confirm)
        return -1;
    sae_confirm(sae->kck, sc, sae->peer_scalar, sae->peer_element,
        sae->own_scalar, sae->own_element, verifier);
    for (i = 0; i < sizeof(verifier); i++)
        diff |= verifier[i] ^ buf[i + 2];
    sae_bzero(verifier, sizeof(verifier));
    if (diff)
        return -1;
    sae->peer_confirm = sc;
    sae->confirmed = 1;
    sae_bzero(sae->kck, sizeof(sae->kck));
    sae_bzero(sae->pwe, sizeof(sae->pwe));
    sae->pwe_ready = 0;
    return 0;
}
