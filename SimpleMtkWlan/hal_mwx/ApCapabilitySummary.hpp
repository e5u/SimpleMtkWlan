#ifndef MtkApCapabilitySummary_hpp
#define MtkApCapabilitySummary_hpp
#include <stddef.h>
#include <stdint.h>

/* Diagnostic only: cached raw IEs before local capability intersection. */
struct MtkApCapabilitySummary {
    bool vht, operation;
    uint32_t vhtCaps;
    uint8_t width, center0, center1, heCapabilityBytes;
};
inline bool mtkParseApCapabilities(const uint8_t *data, size_t length,
    MtkApCapabilitySummary &out)
{
    out = {};
    if (!data || !length || length > 1024) return false;
    MtkApCapabilitySummary parsed = {};
    for (size_t offset = 0; offset < length;) {
        if (length - offset < 2) return false;
        const uint8_t id = data[offset], n = data[offset + 1];
        offset += 2;
        if (n > length - offset) return false;
        const uint8_t *v = data + offset;
        if (id == 191) {
            if (n != 12 || parsed.vht) return false;
            parsed.vht = true;
            parsed.vhtCaps = uint32_t(v[0]) | (uint32_t(v[1]) << 8) |
                (uint32_t(v[2]) << 16) | (uint32_t(v[3]) << 24);
        } else if (id == 192) {
            if (n != 5 || parsed.operation) return false;
            parsed.operation = true;
            parsed.width = v[0];
            parsed.center0 = v[1];
            parsed.center1 = v[2];
        } else if (id == 255) {
            if (!n) return false;
            /* Presence/declared length only, not HE validity or support. */
            if (v[0] == 35) {
                if (n < 22 || parsed.heCapabilityBytes) return false;
                parsed.heCapabilityBytes = n;
            }
        }
        offset += n;
    }
    out = parsed;
    return true;
}
#endif
