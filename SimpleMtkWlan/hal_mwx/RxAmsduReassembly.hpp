#ifndef MtkRxAmsduReassembly_hpp
#define MtkRxAmsduReassembly_hpp

/* Include after kpi_mbuf.h and ieee80211_node.h. Caller serializes all access.
 * Linux mt7921/mac.c removes a two-byte gap after the 802.11 header. The
 * remaining hardware subframe contains an 802.11 header followed by a normal
 * A-MSDU Ethernet header and its length-delimited body (including LLC). Linux
 * mt76/mac80211.c groups these packets before reorder/PN validation; cfg80211
 * util.c:ieee80211_amsdu_to_8023s accepts at most the ordinary terminal padding.
 * Here we reconstruct one MPDU for net80211, which has no subframe reorder ABI.
 * No IV/MIC/FCS bytes are guessed or trimmed. Protected frames require CCMP PN
 * metadata; caller restores one CCMP header and performs post-reorder replay
 * validation. This helper never delivers packets or changes replay counters. */
enum { MTK_RX_AMSDU_TIDS = 16, MTK_RX_AMSDU_SUBFRAMES = 64,
    MTK_RX_AMSDU_MAX_BODY = 7935, MTK_RX_AMSDU_MAX_HEADER = 30,
    MTK_RX_AMSDU_TIMEOUT_MS = 100 };

struct MtkRxAmsduMeta {
    uint32_t epoch;
    uint16_t wcid, seqctl;
    uint8_t queue, tid, cipher, key, format, hdrlen;
    bool protected_frame, hwdec, pn_valid;
    uint8_t pn[6]; /* PN0 (least significant) first. */
    struct ieee80211_rxinfo rxi;
};
struct MtkRxAmsduStats {
    uint64_t started, completed, subframes, singleton, orphan, mismatch;
    uint64_t invalid, timeout, allocfail, pending;
};
struct MtkRxAmsduTombstone {
    MtkRxAmsduMeta meta;
    uint64_t until_ms;
    bool valid;
};
struct MtkRxAmsduContext {
    MtkRxAmsduMeta first;
    mbuf_t frames[MTK_RX_AMSDU_SUBFRAMES];
    uint16_t lengths[MTK_RX_AMSDU_SUBFRAMES];
    uint8_t header[MTK_RX_AMSDU_MAX_HEADER];
    uint16_t count, body_len;
    uint64_t born_ms;
    MtkRxAmsduTombstone dead[2];
};
struct MtkRxAmsduState {
    MtkRxAmsduContext contexts[MTK_RX_AMSDU_TIDS];
    MtkRxAmsduStats stats;
};

inline bool mtkRxAmsduSameKey(const MtkRxAmsduMeta &a,
    const MtkRxAmsduMeta &b)
{
    return a.epoch == b.epoch && a.wcid == b.wcid && a.seqctl == b.seqctl &&
        a.queue == b.queue && a.tid == b.tid && a.cipher == b.cipher &&
        a.key == b.key && a.hdrlen == b.hdrlen &&
        a.protected_frame == b.protected_frame && a.hwdec == b.hwdec &&
        a.pn_valid == b.pn_valid && (!a.pn_valid || memcmp(a.pn, b.pn, 6) == 0);
}

inline void mtkRxAmsduRemember(MtkRxAmsduContext &c,
    const MtkRxAmsduMeta &meta, uint64_t now_ms)
{
    c.dead[1] = c.dead[0];
    c.dead[0].meta = meta;
    c.dead[0].until_ms = now_ms + MTK_RX_AMSDU_TIMEOUT_MS;
    c.dead[0].valid = true;
}

inline void mtkRxAmsduClear(MtkRxAmsduState &s, MtkRxAmsduContext &c)
{
    if (c.count) {
        for (unsigned i = 0; i < c.count; i++) {
            mbuf_freem(c.frames[i]);
            c.frames[i] = NULL;
        }
        c.count = c.body_len = 0;
        s.stats.pending--;
    }
}

/* Lifetime teardown owns and frees every retained mbuf. No state may outlive
 * its driver object. Purges preserve a short tombstone for the old group. */
inline void mtkRxAmsduPurge(MtkRxAmsduState &s, int tid = -1)
{
    for (unsigned i = 0; i < MTK_RX_AMSDU_TIDS; i++) {
        if (tid >= 0 && i != (unsigned)tid)
            continue;
        MtkRxAmsduContext &c = s.contexts[i];
        if (c.count) {
            mtkRxAmsduRemember(c, c.first, c.born_ms);
            /* Purge has no clock argument. Arm at the next timed operation,
             * so an old group's birth time cannot expire its tombstone early. */
            c.dead[0].until_ms = 0;
        }
        mtkRxAmsduClear(s, c);
    }
}

inline void mtkRxAmsduExpire(MtkRxAmsduState &s, uint64_t now_ms)
{
    for (unsigned i = 0; i < MTK_RX_AMSDU_TIDS; i++) {
        MtkRxAmsduContext &c = s.contexts[i];
        for (unsigned j = 0; j < 2; j++) {
            if (c.dead[j].valid && c.dead[j].until_ms == 0)
                c.dead[j].until_ms = now_ms + MTK_RX_AMSDU_TIMEOUT_MS;
            if (c.dead[j].valid && now_ms >= c.dead[j].until_ms)
                c.dead[j].valid = false;
        }
        if (c.count && (now_ms < c.born_ms ||
            now_ms - c.born_ms >= MTK_RX_AMSDU_TIMEOUT_MS)) {
            s.stats.timeout++;
            mtkRxAmsduRemember(c, c.first, now_ms);
            mtkRxAmsduClear(s, c);
        }
    }
}

/* Input is one complete hardware subframe after RXD and extra 2B pad removal.
 * Always consumes input. NULL means retained or discarded; non-NULL transfers
 * sole ownership of a complete contiguous MPDU to the caller, with first_out
 * containing the first frame's metadata. first_out may be NULL. */
inline mbuf_t mtkRxAmsduFeed(MtkRxAmsduState &s, mbuf_t input,
    const MtkRxAmsduMeta &meta, uint64_t now_ms, MtkRxAmsduMeta *first_out)
{
    mtkRxAmsduExpire(s, now_ms);
    if (!input || meta.tid >= MTK_RX_AMSDU_TIDS) {
        s.stats.invalid++;
        if (input) mbuf_freem(input);
        return NULL;
    }
    MtkRxAmsduContext &c = s.contexts[meta.tid];
    uint8_t h[MTK_RX_AMSDU_MAX_HEADER], eth[14];
    const size_t packet_len = mbuf_pkthdr_len(input);
    bool valid = meta.format >= 1 && meta.format <= 3 &&
        (meta.hdrlen == 26 || meta.hdrlen == 30) &&
        packet_len >= (size_t)meta.hdrlen + sizeof(eth) + 8 &&
        packet_len <= (size_t)meta.hdrlen + MTK_RX_AMSDU_MAX_BODY + 3 &&
        mbuf_nextpkt(input) == NULL &&
        mbuf_copydata(input, 0, meta.hdrlen, h) == 0 &&
        mbuf_copydata(input, meta.hdrlen, sizeof(eth), eth) == 0;
    size_t sub_len = 0;
    if (valid) {
        const unsigned qos_off = 24;
        /* STA FromDS QoS data, no fragmentation or A4; optional HT control. */
        valid = h[0] == 0x88 && (h[1] & 7) == 2 &&
            meta.hdrlen == ((h[1] & 0x80) ? 30 : 26) &&
            (h[qos_off] & 0x80) != 0 && (h[qos_off] & 15) == meta.tid &&
            (meta.seqctl & 15) == 0 &&
            meta.seqctl == (uint16_t)(h[22] | ((uint16_t)h[23] << 8)) &&
            memcmp(eth, h + 4, 6) == 0;
        static const uint8_t fake_da[6] = { 0xaa, 0xaa, 3, 0, 0, 0 };
        valid = valid && memcmp(eth, fake_da, 6) != 0;
        if (meta.protected_frame)
            valid = valid && meta.hwdec && meta.cipher == 4 &&
                meta.key <= 3 && meta.pn_valid;
        else
            valid = valid && !meta.hwdec && meta.cipher == 0 && !meta.pn_valid &&
                (h[1] & 0x40) == 0;
        const size_t payload = ((size_t)eth[12] << 8) | eth[13];
        sub_len = sizeof(eth) + payload;
        const size_t body = packet_len - meta.hdrlen;
        const size_t pad = (4 - (sub_len & 3)) & 3;
        valid = valid && payload >= 8 && sub_len <= MTK_RX_AMSDU_MAX_BODY &&
            sub_len <= body && body - sub_len <= pad;
    }
    if (!valid) {
        s.stats.invalid++;
        if (c.count) mtkRxAmsduRemember(c, c.first, now_ms);
        mtkRxAmsduClear(s, c);
        mtkRxAmsduRemember(c, meta, now_ms);
        mbuf_freem(input);
        return NULL;
    }
    for (unsigned i = 0; i < 2; i++) {
        if (c.dead[i].valid && mtkRxAmsduSameKey(c.dead[i].meta, meta)) {
            /* A new FIRST is an explicit restart, unlike an orphan tail. */
            if (meta.format == 3) {
                c.dead[i].valid = false;
                continue;
            }
            s.stats.orphan++;
            mbuf_freem(input);
            return NULL;
        }
    }
    if (meta.format == 3 && c.count) {
        if (!mtkRxAmsduSameKey(c.first, meta))
            mtkRxAmsduRemember(c, c.first, now_ms);
        mtkRxAmsduClear(s, c);
    }
    if (c.count) {
        bool same = mtkRxAmsduSameKey(c.first, meta);
        for (unsigned i = 0; same && i < meta.hdrlen; i++) {
            if (i == 2 || i == 3) continue; /* Duration is not an invariant. */
            const uint8_t mask = i == 1 ? (uint8_t)~0x08 : 0xff;
            same = (h[i] & mask) == (c.header[i] & mask); /* Retry may differ. */
        }
        if (!same) {
            s.stats.mismatch++;
            mtkRxAmsduRemember(c, c.first, now_ms);
            mtkRxAmsduClear(s, c);
            mtkRxAmsduRemember(c, meta, now_ms);
            mbuf_freem(input);
            return NULL;
        }
    } else {
        if (meta.format == 2) {
            s.stats.orphan++;
            mtkRxAmsduRemember(c, meta, now_ms);
            mbuf_freem(input);
            return NULL;
        }
        c.first = meta;
        memcpy(c.header, h, meta.hdrlen);
        c.born_ms = now_ms;
        s.stats.started++;
        s.stats.pending++;
        if (meta.format == 1) s.stats.singleton++;
    }
    const unsigned pad = c.count ? ((4 - (c.body_len & 3)) & 3) : 0;
    if (c.count >= MTK_RX_AMSDU_SUBFRAMES ||
        (size_t)c.body_len + pad + sub_len > MTK_RX_AMSDU_MAX_BODY) {
        s.stats.invalid++;
        mtkRxAmsduRemember(c, c.first, now_ms);
        mtkRxAmsduClear(s, c);
        mbuf_freem(input);
        return NULL;
    }
    c.frames[c.count] = input;
    c.lengths[c.count++] = (uint16_t)sub_len;
    c.body_len = (uint16_t)(c.body_len + pad + sub_len);
    s.stats.subframes++;
    if (meta.format != 1) return NULL;

    /* Reserve CCMP space before the header. The caller can move only the
     * small 802.11 header back into it, leaving the assembled payload intact. */
    const size_t total = c.first.hdrlen + c.body_len;
    const size_t reserve = c.first.protected_frame ? 8 : 0;
    mbuf_t result = NULL;
    uint32_t chunks = 1;
    if (mbuf_allocpacket(MBUF_DONTWAIT, total + reserve, &chunks, &result) != 0 ||
        !result || mbuf_next(result) != NULL ||
        mbuf_len(result) + mbuf_trailingspace(result) < total + reserve) {
        if (result) mbuf_freem(result);
        s.stats.allocfail++;
        mtkRxAmsduRemember(c, c.first, now_ms);
        mtkRxAmsduClear(s, c);
        return NULL;
    }
    uint8_t *dst = (uint8_t *)mbuf_data(result) + reserve;
    if (mbuf_setdata(result, dst, total) != 0) {
        mbuf_freem(result);
        s.stats.allocfail++;
        mtkRxAmsduRemember(c, c.first, now_ms);
        mtkRxAmsduClear(s, c);
        return NULL;
    }
    memcpy(dst, c.header, c.first.hdrlen);
    size_t off = c.first.hdrlen;
    for (unsigned i = 0; i < c.count; i++) {
        if (i) {
            const unsigned gap = (4 - (c.lengths[i - 1] & 3)) & 3;
            memset(dst + off, 0, gap);
            off += gap;
        }
        if (mbuf_copydata(c.frames[i], c.first.hdrlen, c.lengths[i], dst + off) != 0) {
            mbuf_freem(result);
            s.stats.invalid++;
            mtkRxAmsduRemember(c, c.first, now_ms);
            mtkRxAmsduClear(s, c);
            return NULL;
        }
        off += c.lengths[i];
    }
    mbuf_setlen(result, total);
    mbuf_pkthdr_setlen(result, total);
    if (first_out) *first_out = c.first;
    s.stats.completed++;
    mtkRxAmsduClear(s, c);
    return result;
}

#endif
