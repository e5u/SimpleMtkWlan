#ifndef MtkRxAmpduStats_hpp
#define MtkRxAmpduStats_hpp
#include <stdint.h>

/* Host-observed MPDUs, not an estimate of frames transmitted over the air.
 * Linux mt7921/mac.c gives every MPDU in one A-MPDU the GROUP_2 timestamp.
 * Descriptors omitted/dropped before this observer are not measurable here. */
struct MtkRxAmpduStats {
    uint64_t groups, mpdus, bins[6], nonAmpdu, missingGroup2, deaggregated;
    uint64_t uncertainGroups;
    uint32_t timestamp, pending, maximum;
    bool active;
};

inline void mtkRxAmpduClose(MtkRxAmpduStats &s)
{
    if (!s.active) return;
    ++s.groups;
    s.mpdus += s.pending;
    unsigned bin = s.pending == 1 ? 0 : s.pending < 4 ? 1 :
        s.pending < 8 ? 2 : s.pending < 16 ? 3 : s.pending < 32 ? 4 : 5;
    ++s.bins[bin];
    if (s.pending > s.maximum) s.maximum = s.pending;
    s.active = false;
    s.pending = 0;
}

inline void mtkRxAmpduObserve(MtkRxAmpduStats &s, bool group2,
    uint32_t timestamp, bool nonAmpdu, bool deaggregated)
{
    if (!group2 || deaggregated) {
        if (!group2) ++s.missingGroup2;
        if (deaggregated) ++s.deaggregated;
        /* Unknown boundaries must not silently turn into completed groups. */
        if (s.active) ++s.uncertainGroups;
        s.active = false;
        s.pending = 0;
        return;
    }
    if (nonAmpdu) {
        mtkRxAmpduClose(s);
        ++s.nonAmpdu;
        return;
    }
    if (s.active && timestamp != s.timestamp) mtkRxAmpduClose(s);
    if (!s.active) {
        s.active = true;
        s.timestamp = timestamp;
    }
    ++s.pending;
}

/* Keep an unfinished group across log intervals; never split it in two. */
inline void mtkRxAmpduResetInterval(MtkRxAmpduStats &s)
{
    s.groups = s.mpdus = s.nonAmpdu = s.missingGroup2 = 0;
    s.deaggregated = s.uncertainGroups = 0;
    s.maximum = 0;
    for (unsigned i = 0; i < 6; ++i) s.bins[i] = 0;
}
#endif
