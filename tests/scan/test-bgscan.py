"""Exercise the real background-scan admission function with a fake MCU/clock."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text()
start = source.index('int\nmwx_bgscan(struct ieee80211com *ic)')
function = source[start:source.index('\nvoid\nmwx_bgscan_done(', start)]
pre = r'''
#include <cstdint>
#include <cerrno>
#include <cassert>
#define IEEE80211_S_RUN 4
#define MWX_FLAG_SCANNING 1
#define MWX_FLAG_BGSCAN 2
#define DEVNAME(sc) "test"
#define printf(...) ((void)0)
#define MWX_DEV_LOG(...) ((void)0)
struct ieee80211com { void *ic_softc; int ic_state;
 bool ic_wcl_scan_requested, ic_wcl_scan_restricted; uint8_t ic_wcl_scan_ssid_length; };
struct mwx_softc { uint64_t sc_last_bgscan_ns; unsigned sc_flags; int calls; int error; };
static uint64_t clock_ns;
static uint64_t mach_absolute_time() { return clock_ns; }
static void absolutetime_to_nanoseconds(uint64_t n, uint64_t *out) { *out=n; }
static int mt7921_mcu_hw_scan(mwx_softc *sc, int bg) {
 assert(bg==1); ++sc->calls;
 if (!sc->error) sc->sc_flags |= MWX_FLAG_SCANNING;
 return sc->error;
}
'''
post = r'''
static constexpr uint64_t second=1000000000ULL;
int main() {
 mwx_softc a={}, b={};
 ieee80211com ia={&a,IEEE80211_S_RUN,true,true};
 ieee80211com ib={&b,IEEE80211_S_RUN,true,true};
 // Allocation or MCU send failures do not consume admission quota.
 clock_ns=200*second;
 for (int error : {ENOMEM,EIO}) {
  a.error=error; assert(mwx_bgscan(&ia)==error);
  assert(a.sc_last_bgscan_ns==0 && a.sc_flags==0);
 }
 a.error=0; assert(mwx_bgscan(&ia)==0 && a.calls==3);
 assert(a.sc_last_bgscan_ns==clock_ns);
 // A hardware-active scan cannot be reported as a successful new scan.
 assert(mwx_bgscan(&ia)==EBUSY && a.calls==3);
 a.sc_flags=0;
 // Another adapter's first request is independent of this adapter's quota.
 assert(mwx_bgscan(&ib)==0 && b.calls==1);
#ifdef AIRPORT_WCL
 // An explicit SSID-directed UI scan bypasses the broad-cache rate limit.
 clock_ns=201*second;
 ia.ic_wcl_scan_ssid_length=13;
 assert(mwx_bgscan(&ia)==0 && a.calls==4);
 assert(a.sc_last_bgscan_ns==clock_ns);
 a.sc_flags=0; ia.ic_wcl_scan_ssid_length=0;
 clock_ns=210*second+999999999ULL;
 assert(mwx_bgscan(&ia)==EBUSY && a.calls==4);
 clock_ns=211*second;
 assert(mwx_bgscan(&ia)==0 && a.calls==5);
 a.sc_flags=0;
 // Full sweeps retain the 120 second protection after a short scan.
 ia.ic_wcl_scan_restricted=false;
 clock_ns=331*second-1;
 assert(mwx_bgscan(&ia)==EBUSY && a.calls==5);
 clock_ns=331*second;
 assert(mwx_bgscan(&ia)==0 && a.calls==6);
 a.sc_flags=0;
 ia.ic_wcl_scan_restricted=true;
 clock_ns=341*second;
 a.error=EIO;
 assert(mwx_bgscan(&ia)==EIO && a.sc_last_bgscan_ns==331*second);
 a.error=0;
 assert(mwx_bgscan(&ia)==0 && a.calls==8);
#else
 clock_ns=320*second-1;
 assert(mwx_bgscan(&ia)==EBUSY && a.calls==3);
 clock_ns=320*second;
 assert(mwx_bgscan(&ia)==0 && a.calls==4);
#endif
 // Unassociated scans are not throttled and don't overwrite the quota.
 a.sc_flags=0; ia.ic_state=0; clock_ns+=second;
 uint64_t saved=a.sc_last_bgscan_ns;
 assert(mwx_bgscan(&ia)==0 && a.sc_last_bgscan_ns==saved);
}
'''
# The development Hackintosh cannot execute ASan binaries; CI may opt in.
sanitizers = os.environ.get('MTK_TEST_SANITIZERS', 'undefined')
with tempfile.TemporaryDirectory(prefix='mtk-bgscan-') as directory:
    path = Path(directory) / 'test.cpp'
    path.write_text('#include <initializer_list>\n' + pre + function + post)
    for wcl in (False, True):
        binary = Path(directory) / ('wcl' if wcl else 'simple')
        command = ['clang++', '-std=c++14', '-fsanitize=' + sanitizers]
        if wcl:
            command.append('-DAIRPORT_WCL')
        subprocess.run(command + [str(path), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
print('PASS real bgscan busy/error/retry paths, targeted WCL admission, throttling, adapter isolation and non-RUN admission (WCL + Simple)')
