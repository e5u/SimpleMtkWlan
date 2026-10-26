#!/usr/bin/env python3
"""Run the real RX parser under ASan/UBSan with truncated optional RX groups."""
from pathlib import Path
import re, subprocess, tempfile, sys
root = Path(__file__).resolve().parents[2]
s = (root / 'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text()
f = s[s.index('int\nmt7921_mac_fill_rx('):s.index('\nuint32_t\nmt7921_mac_tx_rate_val(')]
if '--test-original' in sys.argv:
 start=f.index('\n\t/* Validate the entire optional descriptor')
 end=f.index('\n\tif (rxd1 & MT_RXD1_NORMAL_BAND_IDX)', start)
 f=f[:start]+f[end:]
h = (root / 'SimpleMtkWlan/hal_mwx/if_mwxreg.h').read_text()
defines = '\n'.join(line for line in h.splitlines() if re.match(r'#define\s+MT_(RXD[0-9]|PRXV_RCPI)', line) and not line.endswith('\\'))
stub = r'''
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include "RxAmpduStats.hpp"
#include <sys/mman.h>
#include <unistd.h>
#define MWX_DEV_LOG(...) ((void)0)
#define MWX_RX_DROP_LOG(...) ((void)0)
#define le32toh(v) (v)
#define MAX(a,b) ((a)>(b)?(a):(b))
#define DEVNAME(sc) "test"
#define IEEE80211_S_RUN 5
#define IEEE80211_RXI_HWDEC 1
#define IEEE80211_FC1_PROTECTED 0x40
#define IEEE80211_FC0_TYPE_MASK 0x0c
#define IEEE80211_FC0_TYPE_MGT 0
#define IEEE80211_FC0_TYPE_DATA 0x08
#define IEEE80211_FC0_SUBTYPE_NODATA 0x40
#define IEEE80211_CCMP_HDRLEN 8
#define IEEE80211_IS_MULTICAST(a) ((a)[0]&1)
struct mbuf { uint8_t *data; size_t len; };
size_t mbuf_len(mbuf *m) { return m->len; }
#define mtod(m,t) reinterpret_cast<t>((m)->data)
void m_adj(mbuf *m, size_t n) { m->data += n; m->len -= n; }
struct ieee80211_frame_min { uint8_t data[10]; };
struct ieee80211_frame { uint8_t i_fc[2],i_dur[2],i_addr1[6],i_addr2[6],i_addr3[6],i_seq[2]; };
unsigned ieee80211_get_hdrlen(const ieee80211_frame *wh) { return 24+((wh->i_fc[1]&0x80)?4:0); }
struct ieee80211_rxinfo { unsigned rxi_flags=0; int rxi_rssi=0; unsigned rxi_chan=0; };
struct ieee80211com { int ic_state=0; struct { unsigned is_rx_decryptcrc=0, is_rx_locmicfail=0; } ic_stats; };
struct mwx_softc { ieee80211com sc_ic; MtkRxAmpduStats sc_rx_ampdu_stats={}; unsigned sc_rx_fill_fail=0; struct { int num_streams=2; unsigned antenna_mask=3; } sc_capa; };
void ieee80211_michael_mic_failure(ieee80211com*, int) {}
int rcpi_to_rssi(unsigned shift, uint32_t value) { return int((value >> shift) & 255) / 2 - 110; }
void mwx_rx_rate_account(uint32_t) {}
'''
main = r'''
int main() {
 unsigned flags[] = {MT_RXD1_NORMAL_GROUP_1, MT_RXD1_NORMAL_GROUP_2,
  MT_RXD1_NORMAL_GROUP_3, MT_RXD1_NORMAL_GROUP_4, MT_RXD1_NORMAL_GROUP_5};
 unsigned rejected=0, accepted=0;
 for (unsigned mask=0; mask<32; ++mask) {
  unsigned rxd1=0, words=6;
  for (unsigned i=0;i<5;++i) if(mask & (1u<<i)) rxd1 |= flags[i];
  if(mask&1)words+=4;if(mask&2)words+=2;if(mask&4)words+=2;if(mask&8)words+=4;
  if((mask&4)&&(mask&16))words+=18;
  for (unsigned len=24;len<words*4+sizeof(ieee80211_frame_min);len+=4) {
   size_t page=static_cast<size_t>(getpagesize());
   auto region=static_cast<uint8_t*>(mmap(nullptr,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0));
   assert(region!=MAP_FAILED);assert(mprotect(region+page,page,PROT_NONE)==0);
   auto raw=region+page-len;memset(raw,0,len);
   memcpy(raw+4,&rxd1,4);mbuf m{raw,len};mwx_softc sc;ieee80211_rxinfo rx;
   assert(mt7921_mac_fill_rx(&sc,&m,&rx)!=0);++rejected;assert(munmap(region,page*2)==0);
  }
  unsigned len=words*4+sizeof(ieee80211_frame_min);
  auto raw=static_cast<uint8_t*>(malloc(len));memset(raw,0,len);memcpy(raw+4,&rxd1,4);
  mbuf m{raw,len};mwx_softc sc;ieee80211_rxinfo rx;
  assert(mt7921_mac_fill_rx(&sc,&m,&rx)==0);++accepted;free(raw);
 }
 for(unsigned key=0;key<4;key++)for(unsigned order=0;order<2;order++) {
  alignas(4) uint8_t raw[128]={};
  const unsigned hdr=24+4*order,gap=40,body=12;
  uint32_t rxd1=MT_RXD1_NORMAL_GROUP_1|(4u<<MT_RXD1_NORMAL_SEC_MODE_SHIFT)|(key<<21);
  memcpy(raw+4,&rxd1,4);const uint8_t pn[6]={0x06,0x05,0x04,0x03,0x02,0x01};memcpy(raw+24,pn,6);
  raw[gap]=0xd0;raw[gap+1]=0x40|(order?0x80:0);raw[gap+4]=2;
  uint8_t expected[12];for(unsigned i=0;i<body;i++)raw[gap+hdr+i]=expected[i]=0xa0+i;
  mbuf m{raw,gap+hdr+body};mwx_softc sc;ieee80211_rxinfo rx;
  assert(mt7921_mac_fill_rx(&sc,&m,&rx)==0&&m.len==hdr+8+body);
  assert((rx.rxi_flags&IEEE80211_RXI_HWDEC)&&(m.data[1]&0x40));
  const uint8_t iv[8]={6,5,0,uint8_t((key<<6)|0x20),4,3,2,1};
  assert(!memcmp(m.data+hdr,iv,8)&&!memcmp(m.data+hdr+8,expected,body));
 }
 for(unsigned group=0;group<2;group++)for(unsigned cipher=3;cipher<=4;cipher++)for(unsigned pn=0;pn<2;pn++) {
  alignas(4) uint8_t raw[128]={};unsigned gap=pn?40:24;
  uint32_t rxd1=(cipher<<MT_RXD1_NORMAL_SEC_MODE_SHIFT)|(pn?MT_RXD1_NORMAL_GROUP_1:0);memcpy(raw+4,&rxd1,4);
  raw[gap]=0xc0;raw[gap+4]=group?0xff:2;raw[gap+24]=0x80;
  mbuf m{raw,gap+42};mwx_softc sc;ieee80211_rxinfo rx;
  int result=mt7921_mac_fill_rx(&sc,&m,&rx);
  assert((result==0)==(group||(cipher==4&&pn)));
  if(group)assert(m.len==42&&m.data[24]==0x80&&!(m.data[1]&0x40));
 }
 { // Existing data RX remains IV-stripped even without GROUP_1.
  alignas(4) uint8_t raw[64]={};uint32_t rxd1=4u<<MT_RXD1_NORMAL_SEC_MODE_SHIFT;memcpy(raw+4,&rxd1,4);
  raw[24]=8;raw[25]=0x42;raw[48]=0xab;mbuf m{raw,60};mwx_softc sc;ieee80211_rxinfo rx;
  assert(mt7921_mac_fill_rx(&sc,&m,&rx)==0&&m.len==36&&!(m.data[1]&0x40)&&m.data[24]==0xab);
 }
 printf("PASS: %u truncated descriptors rejected; %u complete layouts; management CCMP IV/PN restoration, missing-PN rejection and unchanged data/group RX\n",rejected,accepted);
}
'''
with tempfile.TemporaryDirectory(prefix='mtk-rx-bounds-') as d:
 p=Path(d);(p/'test.cpp').write_text(stub+defines+'\n'+f+main)
 sanitizers = ([] if '--no-sanitizers' in sys.argv else
  ['-fsanitize=undefined'] if '--ubsan' in sys.argv else ['-fsanitize=' + __import__('os').environ.get('MTK_TEST_SANITIZERS', 'address,undefined')])
 subprocess.run(['clang++','-std=c++14','-I',str(root/'SimpleMtkWlan/hal_mwx')]+sanitizers+['-g',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 r=subprocess.run([str(p/'test')])
 if '--test-original' in sys.argv:
  assert r.returncode < 0, 'Original parser should fault against a protected guard page'
  print('PASS: original parser faults on truncated optional RX group as expected')
 else:
  r.check_returncode()
