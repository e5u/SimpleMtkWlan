/* SPDX-License-Identifier: ISC
 * MT7921/MT7922 non-translated RX A-MSDU metadata and CCMP restoration.
 * Layout follows Linux mt76 mt7921/mac.c and enum mt76_cipher_type in mt76.h.
 * GROUP_1 data[0..5] are PN0..PN5 (Linux stores the reverse for memcmp).
 * Include after sys/kpi_mbuf.h and if_mwxreg.h. No device state is changed.
 */
#ifndef MTK_RX_AMSDU_METADATA_HPP
#define MTK_RX_AMSDU_METADATA_HPP

struct MtkRxDescriptorMeta {
    uint16_t wcid, seqctl, hdr_gap;
    uint8_t hdrlen, tid, cipher, key, format;
    bool protected_frame, hwdec, pn_valid, unicast;
    uint8_t pn[6];
};

static inline uint16_t
mtkRxAmsduLe16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint32_t
mtkRxAmsduLe32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* 0: ordinary RXD4 format; 1: supported aggregate; -1: invalid aggregate.
 * Read-only: the caller retains the input. On an error, format/WCID and any
 * available TID are kept so the caller can discard a pending matching group.
 * Ordinary frames do not acquire new validation or crypto requirements.
 */
static inline int
mtkRxAmsduReadDescriptor(mbuf_t m, MtkRxDescriptorMeta &meta)
{
    meta = {};
    if (m == NULL || mbuf_len(m) < 24 || mbuf_pkthdr_len(m) < 24)
        return -1;
    const uint8_t *data = (const uint8_t *)mbuf_data(m);
    const uint32_t rxd1 = mtkRxAmsduLe32(data + 4);
    const uint32_t rxd2 = mtkRxAmsduLe32(data + 8);
    const uint32_t rxd3 = mtkRxAmsduLe32(data + 12);
    const uint32_t rxd4 = mtkRxAmsduLe32(data + 16);
    meta.format = rxd4 & MT_RXD4_NORMAL_PAYLOAD_FORMAT;
    meta.wcid = rxd1 & MT_RXD1_NORMAL_WLAN_IDX_MASK;
    meta.cipher = (rxd1 & MT_RXD1_NORMAL_SEC_MODE_MASK) >>
        MT_RXD1_NORMAL_SEC_MODE_SHIFT;
    meta.key = (rxd1 & MT_RXD1_NORMAL_KEY_ID_MASK) >> 21;
    meta.unicast = (rxd3 & MT_RXD3_NORMAL_ADDR_TYPE_MASK) ==
        MT_RXD3_NORMAL_U2M;
    meta.hwdec = meta.cipher != 0 &&
        !(rxd1 & (MT_RXD1_NORMAL_CM | MT_RXD1_NORMAL_CLM));
    if (meta.format == 0)
        return 0;
    if (!meta.unicast ||
        (rxd1 & (MT_RXD1_NORMAL_BAND_IDX | MT_RXD1_NORMAL_ICV_ERR |
            MT_RXD1_NORMAL_FCS_ERR | MT_RXD1_NORMAL_TKIP_MIC_ERR)) ||
        (rxd2 & (MT_RXD2_NORMAL_HDR_TRANS | MT_RXD2_NORMAL_AMSDU_ERR |
            MT_RXD2_NORMAL_MAX_LEN_ERROR | MT_RXD2_NORMAL_HDR_TRANS_ERROR |
            MT_RXD2_NORMAL_FRAG | MT_RXD2_NORMAL_NULL_FRAME |
            MT_RXD2_NORMAL_NDATA)))
        return -1;
    if ((rxd1 & MT_RXD1_NORMAL_GROUP_5) &&
        !(rxd1 & MT_RXD1_NORMAL_GROUP_3))
        return -1;

    size_t offset = 24;
    if (rxd1 & MT_RXD1_NORMAL_GROUP_4)
        offset += 16;
    const size_t group1 = offset;
    if (rxd1 & MT_RXD1_NORMAL_GROUP_1)
        offset += 16;
    if (rxd1 & MT_RXD1_NORMAL_GROUP_2)
        offset += 8;
    if (rxd1 & MT_RXD1_NORMAL_GROUP_3) {
        offset += 8;
        if (rxd1 & MT_RXD1_NORMAL_GROUP_5)
            offset += 72;
    }
    offset += 2 * ((rxd2 & MT_RXD2_NORMAL_HDR_OFFSET_MASK) >>
        MT_RXD2_NORMAL_HDR_OFFSET_SHIFT);
    meta.hdr_gap = (uint16_t)offset;
    meta.hdrlen = 26; /* This path deliberately supports three-address QoS. */
    if (mbuf_len(m) < offset + meta.hdrlen + 2 ||
        mbuf_pkthdr_len(m) < offset + meta.hdrlen + 2 + 14 + 8)
        return -1;
    if (meta.cipher == 4 && meta.hwdec && (rxd1 & MT_RXD1_NORMAL_GROUP_1)) {
        for (unsigned i = 0; i != 6; ++i)
            meta.pn[i] = data[group1 + i];
        meta.pn_valid = true;
    }
    const uint8_t *wh = data + offset;
    meta.seqctl = mtkRxAmsduLe16(wh + 22);
    meta.tid = wh[24] & 0x0f;
    meta.protected_frame = (wh[1] & 0x40) != 0;
    /* QoS data, FromDS, no MoreFrag/HT-Control, no sequence fragment. */
    if (wh[0] != 0x88 || (wh[1] & 0x87) != 0x02 || (wh[4] & 1) ||
        (meta.seqctl & 0x0f) != 0 || !(wh[24] & 0x80))
        return -1;
    /* AES-CCMP is enum mt76_cipher_type value 4, not the MCU cipher enum.
     * Only this supported protected format may reach the reassembler. */
    if (meta.cipher == 0)
        return !meta.protected_frame && !meta.hwdec ? 1 : -1;
    return meta.cipher == 4 && meta.hwdec && meta.pn_valid ? 1 : -1;
}

/* Called after mt7921_mac_fill_rx stripped hdr_gap. Non-consuming; unchanged
 * on failure. Linux non-header-translated deagg inserts two bytes AFTER the
 * 802.11 header. Shift that header forward, then remove those two bytes.
 */
static inline bool
mtkRxAmsduRemovePad(mbuf_t m, const MtkRxDescriptorMeta &meta)
{
    if (m == NULL || meta.format == 0 || meta.hdrlen != 26 ||
        mbuf_len(m) < (size_t)meta.hdrlen + 2 ||
        mbuf_pkthdr_len(m) < (size_t)meta.hdrlen + 2 + 14 + 8)
        return false;
    uint8_t *data = (uint8_t *)mbuf_data(m);
    memmove(data + 2, data, meta.hdrlen);
    mbuf_adj(m, 2);
    return true;
}

/* Always consumes m. Call ONCE after a complete aggregate was reconstructed.
 * It restores only the stripped CCMP header so net80211 validates PN once,
 * after BA reordering. The MIC is already stripped; this helper never adds or removes tail bytes.
 * A failed allocation/copy releases every owned buffer and returns NULL.
 */
static inline mbuf_t
mtkRxAmsduRestoreCcmp(mbuf_t m, const MtkRxDescriptorMeta &meta)
{
    if (m == NULL)
        return NULL;
    const size_t length = mbuf_pkthdr_len(m);
    if (meta.hdrlen != 26 || length < (size_t)meta.hdrlen + 14 + 8 ||
        length > (size_t)meta.hdrlen + 7935 || mbuf_len(m) < meta.hdrlen) {
        mbuf_freem(m);
        return NULL;
    }
    uint8_t *header = (uint8_t *)mbuf_data(m);
    /* The caller may restore the original Protected bit for group validation.
     * No IV exists yet in either case; this helper inserts exactly one.
     * Validate the header before restoring bytes at the wrong offset. */
    if (header[0] != 0x88 || (header[1] & 0x87) != 0x02 ||
        (mtkRxAmsduLe16(header + 22) & 0x0f) != 0 ||
        mtkRxAmsduLe16(header + 22) != meta.seqctl ||
        (header[24] & 0x0f) != meta.tid || !(header[24] & 0x80)) {
        mbuf_freem(m);
        return NULL;
    }
    if (meta.cipher == 0 && !meta.protected_frame && !meta.hwdec &&
        !(header[1] & 0x40))
        return m;
    if (meta.cipher != 4 || !meta.hwdec || !meta.pn_valid || meta.key > 3) {
        mbuf_freem(m);
        return NULL;
    }
    mbuf_t result = NULL;
    uint8_t *dest;
    if (mbuf_next(m) == NULL && mbuf_len(m) == length &&
        !mbuf_mclhasreference(m) && mbuf_leadingspace(m) >= 8) {
        /* Reassembly returned an exclusive packet with reserved headroom.
         * Grow backward without allocating or moving any payload bytes. */
        dest = header - 8;
        if (mbuf_setdata(m, dest, length + 8) != 0) {
            mbuf_freem(m);
            return NULL;
        }
        memmove(dest, header, meta.hdrlen);
        result = m;
    } else {
        /* Keep the consuming fallback for shared, chained or unreserved input. */
        unsigned int chunks = 1;
        if (mbuf_allocpacket(MBUF_DONTWAIT, length + 8, &chunks, &result) != 0 ||
            result == NULL) {
            if (result != NULL)
                mbuf_freem(result);
            mbuf_freem(m);
            return NULL;
        }
        if (mbuf_next(result) != NULL ||
            mbuf_len(result) + mbuf_trailingspace(result) < length + 8) {
            mbuf_freem(result);
            mbuf_freem(m);
            return NULL;
        }
        dest = (uint8_t *)mbuf_data(result);
        if (mbuf_copydata(m, 0, meta.hdrlen, dest) != 0 ||
            mbuf_copydata(m, meta.hdrlen, length - meta.hdrlen,
                dest + meta.hdrlen + 8) != 0) {
            mbuf_freem(result);
            mbuf_freem(m);
            return NULL;
        }
    }
    uint8_t *iv = dest + meta.hdrlen;
    iv[0] = meta.pn[0]; iv[1] = meta.pn[1]; iv[2] = 0;
    iv[3] = (uint8_t)((meta.key << 6) | 0x20);
    for (unsigned i = 2; i != 6; ++i)
        iv[i + 2] = meta.pn[i];
    dest[1] |= 0x40;
    mbuf_setlen(result, length + 8);
    mbuf_pkthdr_setlen(result, length + 8);
    if (result != m)
        mbuf_freem(m);
    return result;
}
#endif
