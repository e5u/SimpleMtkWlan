#!/usr/bin/env python3
"""Run the actual VHT negotiator against legacy/revised width wire fixtures."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
net = root / 'mtk80211/openbsd/net80211'
source = (net / 'ieee80211_proto.c').read_text()
start = source.index('void\nieee80211_vht_negotiate(')
end = source.index('\nvoid\nieee80211_he_negotiate(', start)
fn = source[start:end]
headers = '\n'.join((net / p).read_text() for p in [
    'ieee80211.h', 'ieee80211_var.h', 'ieee80211_node.h', 'ieee80211_ioctl.h'])
names = [
    'IEEE80211_NODE_VHT', 'IEEE80211_NODE_VHTCAP',
    'IEEE80211_NODE_VHT_SGI80', 'IEEE80211_NODE_VHT_SGI160',
    'IEEE80211_F_NOVHT', 'IEEE80211_F_VHTON', 'IEEE80211_F_WEPON',
    'IEEE80211_F_RSNON', 'IEEE80211_C_SUPPORTS_VHT_EXT_NSS_BW',
    'IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_MASK',
    'IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_160MHZ',
    'IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_160_80P80MHZ',
    'IEEE80211_VHTCAP_EXT_NSS_BW_MASK',
    'IEEE80211_VHTCAP_EXT_NSS_BW_SHIFT',
    'IEEE80211_HT_OP_MODE_CCFS2_MASK',
    'IEEE80211_HT_OP_MODE_CCFS2_SHIFT',
    'IEEE80211_VHT_CHANWIDTH_USE_HT', 'IEEE80211_VHT_CHANWIDTH_80MHZ',
    'IEEE80211_VHT_CHANWIDTH_160MHZ', 'IEEE80211_VHT_CHANWIDTH_80P80MHZ',
    'IEEE80211_VHTCAP_SHORT_GI_80', 'IEEE80211_VHTCAP_SHORT_GI_160']
defines = '\n'.join(re.search(r'^#define\s+' + re.escape(name) +
    r'\s+[^\n]+', headers, re.M).group() for name in names)
stub = r'''
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <libkern/OSByteOrder.h>
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define XYLog(...) ((void)0)
#define IEEE80211_MODE_11AC 5
#define IEEE80211_CIPHER_USEGROUP 1
#define IEEE80211_CIPHER_TKIP 4
enum { IEEE80211_CHAN_WIDTH_20_NOHT, IEEE80211_CHAN_WIDTH_20,
 IEEE80211_CHAN_WIDTH_40, IEEE80211_CHAN_WIDTH_80,
 IEEE80211_CHAN_WIDTH_80P80, IEEE80211_CHAN_WIDTH_160 };
struct ieee80211_channel { int ic_freq=5200; uint32_t ic_flags=0;
 int ic_center_freq1=5210,ic_center_freq2=0; };
struct ieee80211_node {
 uint32_t ni_flags=IEEE80211_NODE_VHTCAP;
 ieee80211_channel *ni_chan; uint32_t ni_vhtcaps=0,ni_rsnciphers=0;
 uint8_t ni_vht_chan1=42,ni_vht_chan2=0,ni_vht_chanwidth=1;
 uint16_t ni_htop1=0; int ni_chw=IEEE80211_CHAN_WIDTH_40;
};
struct ieee80211com {
 uint32_t ic_modecaps=1<<IEEE80211_MODE_11AC,ic_userflags=0;
 uint32_t ic_flags=IEEE80211_F_VHTON,ic_caps=0,ic_vhtcaps=0;
 struct { unsigned is_vht_nego_no_mandatory_mcs=0,
 is_vht_nego_bad_crypto=0; } ic_stats;
};
#define IEEE80211_IS_CHAN_5GHZ(c) ((c)->ic_freq >= 5000)
bool ieee80211_node_supports_vht(ieee80211_node*n) {
 return n->ni_flags&IEEE80211_NODE_VHTCAP; }
bool ieee80211_node_supports_vht_sgi80(ieee80211_node*n) {
 return n->ni_vhtcaps&IEEE80211_VHTCAP_SHORT_GI_80; }
bool ieee80211_node_supports_vht_sgi160(ieee80211_node*n) {
 return n->ni_vhtcaps&IEEE80211_VHTCAP_SHORT_GI_160; }
uint32_t u32_get_bits(uint32_t x,uint32_t mask) {
 return (x&mask)>>__builtin_ctz(mask); }
int ieee80211_ieee2mhz(int channel,uint32_t) {return 5000+5*channel;}
'''
main = r'''
struct Fixture { ieee80211_channel c; ieee80211_node n; ieee80211com ic;
 Fixture():n{ } {n.ni_chan=&c;}
 void width(uint32_t own,uint32_t peer,int operation,int c0,int c1) {
  ic.ic_vhtcaps=own;n.ni_vhtcaps=peer;
  n.ni_vht_chanwidth=operation;n.ni_vht_chan1=c0;n.ni_vht_chan2=c1;
  c.ic_center_freq2=9999;
  ieee80211_vht_negotiate(&ic,&n);
 }
 void check(int width,int center,int second=0) {
  assert(n.ni_flags&IEEE80211_NODE_VHT);
  assert(n.ni_chw==width);assert(c.ic_center_freq1==center);
  assert(c.ic_center_freq2==second);
 }
};
int main() {
 constexpr uint32_t cap160=IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_160MHZ;
 constexpr uint32_t cap8080=IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_160_80P80MHZ;
 {Fixture f;f.width(cap160,cap160,2,50,0);
  f.check(IEEE80211_CHAN_WIDTH_160,5250);}
 {Fixture f;f.width(cap160,cap160,1,42,50);
  f.check(IEEE80211_CHAN_WIDTH_160,5250);}
 {Fixture f;f.c.ic_freq=5280;f.width(cap160,cap160,1,58,50);
  f.check(IEEE80211_CHAN_WIDTH_160,5250);}
 {Fixture f;f.width(0,0,1,42,0);
  f.check(IEEE80211_CHAN_WIDTH_80,5210);}
 {Fixture f;f.width(0,cap160,1,42,50);
  f.check(IEEE80211_CHAN_WIDTH_80,5210);}
 {Fixture f;f.width(0,cap160,2,50,0);
  f.check(IEEE80211_CHAN_WIDTH_80,5210);}
 {Fixture f;f.c.ic_freq=5280;f.width(0,cap160,2,50,0);
  f.check(IEEE80211_CHAN_WIDTH_80,5290);}
 {Fixture f;f.width(cap160,0,2,50,0);
  f.check(IEEE80211_CHAN_WIDTH_80,5210);}
 {Fixture f;f.width(cap160,cap8080,3,42,106);
  f.check(IEEE80211_CHAN_WIDTH_80,5210);}
 {Fixture f;f.width(cap160,cap8080,1,42,106);
  f.check(IEEE80211_CHAN_WIDTH_80,5210);}
 {Fixture f;f.width(cap8080,cap8080,3,42,106);
  f.check(IEEE80211_CHAN_WIDTH_80P80,5210,5530);}
 {Fixture f;f.width(cap8080,cap8080,1,42,106);
  f.check(IEEE80211_CHAN_WIDTH_80P80,5210,5530);}
 {Fixture f;f.width(cap160,cap160,0,0,0);
  f.check(IEEE80211_CHAN_WIDTH_40,5210);}
 {Fixture f;f.width(cap160,cap160,2,0,0);
  assert(!(f.n.ni_flags&IEEE80211_NODE_VHT));
  assert(f.n.ni_chw==IEEE80211_CHAN_WIDTH_40);}
 {Fixture f;f.ic.ic_userflags=IEEE80211_F_NOVHT;
  f.width(cap160,cap160,1,42,50);
  assert(!(f.n.ni_flags&IEEE80211_NODE_VHT));}
 puts("PASS actual VHT negotiator: legacy/revised 160, both 80 MHz halves, local/peer limits, 80+80 fallback, HT, missing center and disabled VHT.");
}
'''
with tempfile.TemporaryDirectory(prefix='mtk-vht-width-') as tmp:
    path = Path(tmp) / 'vht-width.cpp'
    path.write_text(defines + '\n' + stub + fn + main)
    exe = path.with_suffix('')
    subprocess.run(['clang++', '-std=c++14', '-fsanitize=undefined',
        '-fno-sanitize-recover=undefined', str(path), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
