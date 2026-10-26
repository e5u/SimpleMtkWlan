#!/usr/bin/env python3
"""Exercise the Tahoe SAE/BIP capability helper used by the real driver."""

from pathlib import Path
import os
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "CardCapabilities.hpp"

struct Buffer {
    uint32_t version;
    uint8_t capabilities[21];
    uint8_t guard[32];
};

static void assertOnlySaeBipChanged(const Buffer &before, const Buffer &after)
{
    assert(before.version == after.version);
    assert(!memcmp(before.guard, after.guard, sizeof(before.guard)));
    for (size_t i = 0; i < sizeof(before.capabilities); ++i) {
        if (i != 9)
            assert(before.capabilities[i] == after.capabilities[i]);
    }
}

int main()
{
    Buffer baseline = {};
    baseline.version = 1;
    baseline.capabilities[0] = 0x0c; // TKIP + AES-CCMP
    baseline.capabilities[1] = 0x46; // WPA2 + TKIP MIC, without WPA1
    baseline.capabilities[2] = 0x70; // WME + short GI
    baseline.capabilities[5] = 0x40; // Scan completion
    baseline.capabilities[17] = 0x80; // HE
    memset(baseline.guard, 0xa5, sizeof(baseline.guard));

    Buffer actual = baseline;
    MtkWclCardCapabilities::advertiseWpa3(actual.capabilities, false, false);
    assert(!memcmp(&baseline, &actual, sizeof(actual)));
    MtkWclCardCapabilities::advertiseWpa3(actual.capabilities, false, true);
    assert(!memcmp(&baseline, &actual, sizeof(actual)));
    MtkWclCardCapabilities::advertiseWpa3(actual.capabilities, true, false);
    assert(!memcmp(&baseline, &actual, sizeof(actual)));

    MtkWclCardCapabilities::advertiseWpa3(actual.capabilities, true, true);
    assertOnlySaeBipChanged(baseline, actual);
    assert(actual.capabilities[9] ==
           (MtkWclCardCapabilities::kSae | MtkWclCardCapabilities::kBip));
    assert(actual.capabilities[9] == 0x18);

    // Existing capabilities, including unrelated bits in byte 9, survive.
    actual.capabilities[9] = 0xe7;
    Buffer before = actual;
    MtkWclCardCapabilities::advertiseWpa3(actual.capabilities, true, true);
    assertOnlySaeBipChanged(before, actual);
    assert(actual.capabilities[9] == 0xff);
    puts("PASS Tahoe card capabilities: SAE/BIP bits 75/76, opt-in and MFP gates, "
         "21-byte bounds, WPA2/HE preservation");
}
'''


def main():
    driver = (ROOT / "AirportMtkWlan/AirportItlwmV2.cpp").read_text()
    attach = driver.index("if (!fHalService->attach(pciNub))")
    boot_args = driver.index('PE_parse_boot_argn("-mtkwpa3"')
    assert boot_args < attach, "WPA3 must be fixed before HAL attach/capability discovery"
    assert "MtkWclCardCapabilities::advertiseWpa3(cd->capabilities" in driver
    assert "#if __IO80211_TARGET == __MAC_26_0" in driver

    with tempfile.TemporaryDirectory(prefix="mtk-card-capabilities-") as tmp:
        tmp = Path(tmp)
        test = tmp / "test.cpp"
        binary = tmp / "test"
        test.write_text(SOURCE)
        subprocess.run([
            "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=" + os.environ.get("MTK_TEST_SANITIZERS", "undefined"),
            "-fno-sanitize-recover=all",
            "-I", str(ROOT / "AirportMtkWlan/WCL"), str(test), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
