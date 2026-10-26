#ifndef AirportMtkWlan_WCL_CardCapabilities_hpp
#define AirportMtkWlan_WCL_CardCapabilities_hpp

#include <stddef.h>
#include <stdint.h>

namespace MtkWclCardCapabilities {

// Tahoe's Apple80211Associate2 checks global capability bits 75 and 76
// before it submits an SAE association to the driver.
static const uint8_t kSae = 0x08;
static const uint8_t kBip = 0x10;

template <size_t N>
inline void advertiseWpa3(uint8_t (&capabilities)[N], bool wpa3Enabled,
                          bool mfpSupported)
{
    static_assert(N > 9, "SAE/BIP require capability byte 9");
    if (wpa3Enabled && mfpSupported)
        capabilities[9] |= kSae | kBip;
}

} // namespace MtkWclCardCapabilities

#endif
