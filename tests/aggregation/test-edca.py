"""Execute the driver's actual EDCA builder and callback with UBSan."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / 'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text()


def function(name):
    m = re.search(r'(?m)^(?:int|void)\n' + name + r'\([^;]+?\)\s*\{', SRC)
    assert m, name
    end, depth = SRC.index('{', m.start()) + 1, 1
    while depth:
        depth += (SRC[end] == '{') - (SRC[end] == '}')
        end += 1
    return SRC[m.start():end]


builder = function('mt7921_mcu_set_tx')
callback = function('mwx_updateedca')
state = function('mwx_newstate_task')
# Execute the exact post-BSS association fragment as well as both real functions.
start = state.index('\t\trv = mt7921_mcu_set_associated_bss(sc, 1);')
end = state.index('\t\tmt7921_mcu_set_rts_thresh(sc, 0x92b, 0);', start)
end += len('\t\tmt7921_mcu_set_rts_thresh(sc, 0x92b, 0);')
associated = state[start:end]
init_match = re.search(r'\trv = mt7921_mcu_set_tx\(sc, &sc->sc_vif\);\n\tif \(rv\) \{.*?\n\t\}\n\tMWX_DEV_LOG\(sc, "init set tx ok\\n"\);', SRC, re.S)
assert init_match
assert 'ic->ic_updateedca = mwx_updateedca;' in SRC

pre = r"""
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>
using u_int = unsigned;
#define __packed __attribute__((packed))
#define MWX_DEV_LOG(...) ((void)0)
#ifndef htole16
#define htole16(x) (x)
#endif
#define IEEE80211_AID(x) ((x) & 0x3fff)
#define IEEE80211_F_QOS 0x00080000
#define IEEE80211_NODE_QOS 0x1
#define IEEE80211_NUM_ACS 4
#define EDCA_NUM_AC 4
#define IFF_RUNNING 0x40
#define MCU_CE_CMD_SET_EDCA_PARMS 0x1234
#define IEEE80211_S_INIT 0
#define IEEE80211_S_SCAN 1
#define IEEE80211_S_AUTH 2
#define IEEE80211_S_ASSOC 3
#define IEEE80211_S_RUN 4
struct ieee80211_edca_ac_params {
 uint8_t ac_ecwmin=0, ac_ecwmax=0, ac_aifsn=0;
 uint16_t ac_txoplimit=0; uint8_t ac_acm=0;
};
struct ieee80211_node { uint16_t ni_associd=0; unsigned ni_flags=0; };
struct ieee80211com {
 void *ic_softc=nullptr; unsigned ic_flags=0; int ic_state=IEEE80211_S_INIT;
 ieee80211_node *ic_bss=nullptr;
 struct { unsigned if_flags=0; } ic_if;
 ieee80211_edca_ac_params ic_edca_ac[4]; unsigned ic_edca_updtcount=0;
};
struct mwx_vif { uint8_t idx=7, wmm_idx=2; };
struct mwx_softc {
 ieee80211com sc_ic; mwx_vif sc_vif; int sc_sta_added=0, sc_suspended=0;
};
static std::vector<uint8_t> wire;
static int calls=0, send_result=0, bss_result=0, peer_result=0, rts_calls=0;
static std::vector<int> order;
int mwx_mcu_send_msg(mwx_softc*,int cmd,void *data,size_t len,void *seq) {
 assert(cmd==MCU_CE_CMD_SET_EDCA_PARMS && seq==nullptr && len==44);
 auto *p=static_cast<uint8_t*>(data); wire.assign(p,p+len); ++calls;
 order.push_back(3); return send_result;
}
int mt7921_mcu_set_associated_bss(mwx_softc*,int on) {
 assert(on==1);order.push_back(1);return bss_result;
}
int mt7921_mcu_set_associated_peer(mwx_softc*) {
 order.push_back(2);return peer_result;
}
void mt7921_mcu_set_rts_thresh(mwx_softc*,unsigned v,int band) {
 assert(v==0x92b && band==0);++rts_calls;order.push_back(4);
}
int mt7921_mcu_set_tx(mwx_softc*,mwx_vif*);
uint16_t u16(size_t p) {return wire[p] | unsigned(wire[p+1])<<8;}
"""
post = r"""
void setup(mwx_softc &sc,ieee80211_node &ni) {
 sc=mwx_softc{};ni=ieee80211_node{};
 sc.sc_ic.ic_softc=&sc;sc.sc_ic.ic_bss=&ni;sc.sc_sta_added=1;
 sc.sc_ic.ic_state=IEEE80211_S_RUN;sc.sc_ic.ic_flags=IEEE80211_F_QOS;
 sc.sc_ic.ic_if.if_flags=IFF_RUNNING;sc.sc_ic.ic_edca_updtcount=9;
 ni.ni_associd=7;ni.ni_flags=IEEE80211_NODE_QOS;
 const uint8_t mins[4]={4,4,3,2}, maxs[4]={10,10,4,3}, aifs[4]={3,7,2,2};
 const uint16_t txops[4]={0,0,94,47};
 for(int ac=0;ac<4;++ac) {
  auto &q=sc.sc_ic.ic_edca_ac[ac];q.ac_ecwmin=mins[ac];q.ac_ecwmax=maxs[ac];
  q.ac_aifsn=aifs[ac];q.ac_txoplimit=txops[ac];q.ac_acm=ac%2;
 }
}
void check_defaults() {
 assert(wire.size()==44 && wire[40]==7 && wire[41]==0 && wire[42]==2 && wire[43]==0);
 for(int ac=0;ac<4;++ac) {
  size_t p=ac*10;assert(u16(p)==5 && u16(p+2)==10 && u16(p+4)==0 && u16(p+6)==2);
  assert(wire[p+8]==0 && wire[p+9]==0);
 }
}
void check_qos() {
 // Independent golden record order: VI, VO, BE, BK. Actual CW, not exponents.
 const uint8_t expected[44]={
  7,0,15,0,94,0,2,0,0,0,
  3,0,7,0,47,0,2,0,0,1,
  15,0,255,3,0,0,3,0,0,0,
  15,0,255,3,0,0,7,0,0,1,
  7,1,2,0};
 assert(wire.size()==44 && std::equal(wire.begin(),wire.end(),expected));
}
int association(mwx_softc *sc) {int rv=0;do { @ASSOCIATED@ }while(false);return rv;}
int initialization(mwx_softc *sc) {int rv=0; @INITIALIZATION@ return 0;}
int main() {
 mwx_softc sc{};ieee80211_node ni{};setup(sc,ni);
 assert(mt7921_mcu_set_tx(&sc,&sc.sc_vif)==0);check_qos();
 // AP updates flow to the wire, including all ACs and 16-bit TXOP without scaling.
 for(int ac=0;ac<4;++ac) {
  const int slots[4]={2,3,0,1};auto old=sc.sc_ic.ic_edca_ac[ac];
  auto &q=sc.sc_ic.ic_edca_ac[ac];q.ac_txoplimit=0x1234;q.ac_aifsn=11;
  mwx_updateedca(&sc.sc_ic);assert(u16(slots[ac]*10+4)==0x1234);
  assert(u16(slots[ac]*10+6)==11);q=old;
 }
 // Exhaust all valid 4-bit exponent pairs, including CW=0 and max 32767.
 for(unsigned lo=0;lo<=15;++lo) for(unsigned hi=lo;hi<=15;++hi) {
  auto &q=sc.sc_ic.ic_edca_ac[0];q.ac_ecwmin=lo;q.ac_ecwmax=hi;
  assert(mt7921_mcu_set_tx(&sc,&sc.sc_vif)==0);
  assert(u16(20)==(1U<<lo)-1 && u16(22)==(1U<<hi)-1);
 }
 setup(sc,ni);
 // Non-QoS cases keep the old initialization bytes; invalid inactive ACs ignored.
 for(int cause=0;cause<6;++cause) {
  setup(sc,ni);sc.sc_ic.ic_edca_ac[0].ac_ecwmin=255;
  if(cause==0)sc.sc_ic.ic_flags=0;
  if(cause==1)sc.sc_sta_added=0;
  if(cause==2)sc.sc_ic.ic_bss=nullptr;
  if(cause==3)ni.ni_associd=0;
  if(cause==4)ni.ni_flags=0;
  if(cause==5)sc.sc_ic.ic_state=IEEE80211_S_INIT;
  assert(mt7921_mcu_set_tx(&sc,&sc.sc_vif)==0);check_defaults();
 }
 // Malformed active EDCA never reaches the MCU; retryable callback failure.
 for(int cause=0;cause<5;++cause) {
  setup(sc,ni);auto &q=sc.sc_ic.ic_edca_ac[0];
  if(cause==0)q.ac_ecwmin=16;
  if(cause==1)q.ac_ecwmax=255;
  if(cause==2)q.ac_aifsn=0;
  if(cause==3)q.ac_aifsn=16;
  if(cause==4){q.ac_ecwmin=10;q.ac_ecwmax=4;}
  int before=calls;assert(mt7921_mcu_set_tx(&sc,&sc.sc_vif)==EINVAL);
  assert(calls==before);mwx_updateedca(&sc.sc_ic);
  assert(calls==before && sc.sc_ic.ic_edca_updtcount==unsigned(-1));
 }
 // Missing/offline/transitioning peers cannot submit EDCA from RX callback.
 for(int cause=0;cause<5;++cause) {
  setup(sc,ni);int before=calls;
  if(cause==0)sc.sc_ic.ic_softc=nullptr;
  if(cause==1)sc.sc_suspended=1;
  if(cause==2)sc.sc_ic.ic_if.if_flags=0;
  if(cause==3)sc.sc_ic.ic_state=IEEE80211_S_ASSOC;
  if(cause==4)sc.sc_sta_added=0;
  mwx_updateedca(&sc.sc_ic);assert(calls==before);
 }
 setup(sc,ni);send_result=EIO;mwx_updateedca(&sc.sc_ic);
 assert(sc.sc_ic.ic_edca_updtcount==unsigned(-1));
 send_result=0;int before=calls;mwx_updateedca(&sc.sc_ic);assert(calls==before+1);check_qos();
 // First association applies QoS after both associated records, before RTS/data.
 setup(sc,ni);sc.sc_ic.ic_state=IEEE80211_S_ASSOC;order.clear();
 assert(association(&sc)==0 && (order==std::vector<int>{1,2,3,4}));check_qos();
 for(int cause=0;cause<3;++cause) {
  setup(sc,ni);order.clear();bss_result=peer_result=send_result=0;
  if(cause==0)bss_result=EIO;if(cause==1)peer_result=EIO;if(cause==2)send_result=EIO;
  assert(association(&sc)==EIO && order.back()!=4);
  assert(order.size()==unsigned(cause+1));
 }
 bss_result=peer_result=send_result=0;sc=mwx_softc{};
 assert(initialization(&sc)==0);check_defaults();send_result=ENOBUFS;
 assert(initialization(&sc)==ENOBUFS);
 puts("PASS actual EDCA builder/callback and RUN/init fragments: 4 AC golden bytes, numeric CW exhaustive 0..15, TXOP units, QoS gating, AP updates, invalid params, offline callbacks, failed submission retry and association ordering (UBSan).");
}
"""
post=post.replace('@ASSOCIATED@',associated).replace('@INITIALIZATION@',init_match.group())
source=pre+builder+callback+post
with tempfile.TemporaryDirectory(prefix='mtk-edca-') as tmp:
    cpp,binary=Path(tmp)/'test.cpp',Path(tmp)/'test'
    cpp.write_text(source)
    subprocess.run(['clang++','-std=c++14','-O1','-g','-fsanitize=undefined',
                    '-fno-sanitize-recover=all',str(cpp),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1:print_stacktrace=1'})
