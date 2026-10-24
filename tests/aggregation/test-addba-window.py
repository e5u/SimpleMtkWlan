"""Exercise actual ADDBA response parser and callback window ordering."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / 'mtk80211/openbsd/net80211/ieee80211_input.c').read_text()
HEADERS = '\n'.join((ROOT / ('mtk80211/openbsd/net80211/' + n)).read_text()
                    for n in ['ieee80211.h', 'ieee80211_node.h', 'ieee80211_var.h'])
start = SRC.index('void\nieee80211_recv_addba_resp(')
end = SRC.index('{', start) + 1
depth = 1
while depth:
    depth += (SRC[end] == '{') - (SRC[end] == '}')
    end += 1
function = SRC[start:end]
constants = ['IEEE80211_ADDBA_BUFSZ_MASK', 'IEEE80211_ADDBA_BUFSZ_SHIFT',
             'IEEE80211_ADDBA_AMSDU', 'IEEE80211_BA_MAX_WINSZ',
             'IEEE80211_BA_INIT', 'IEEE80211_BA_REQUESTED', 'IEEE80211_BA_AGREED',
             'IEEE80211_ADDBA_REQ_INTVAL_MAX', 'IEEE80211_C_TX_AMSDU_IN_AMPDU']
defines = []
for name in constants:
    match = re.search(r'(?m)^#define[ \t]+' + name + r'[ \t]+[^\n]*', HEADERS)
    assert match, name
    defines.append(match.group())

pre = r'''
#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <sys/types.h>
#include <initializer_list>
#define DPRINTF(x) ((void)0)
#define IEEE80211_STATUS_SUCCESS 0
#define IEEE80211_STATUS_UNSPECIFIED 1
#define IEEE80211_SEND_ACTION(...) (++actions)
#define LE_READ_2(p) (uint16_t((p)[0]) | uint16_t((p)[1]) << 8)
'''
stubs = r'''
struct ieee80211_frame {uint8_t bytes[24];};
struct mbuf {alignas(8) uint8_t bytes[33];size_t len=sizeof(bytes);};
using mbuf_t=mbuf*;
#define mtod(m,t) reinterpret_cast<t>((m)->bytes)
size_t mbuf_len(mbuf *m) {return m->len;}
struct ieee80211_tx_ba {
 int ba_state=IEEE80211_BA_REQUESTED;uint8_t ba_token=0x5a;int ba_to=0;
 uint16_t ba_winsize=64,ba_params=0;
};
struct ieee80211_node {
 ieee80211_tx_ba ni_tx_ba[16];uint8_t ni_addba_req_intval[16]={};
};
struct ieee80211com {
 uint32_t ic_caps=0;int (*ic_ampdu_tx_start)(ieee80211com*,ieee80211_node*,uint8_t)=nullptr;
};
int starts=0,accepts=0,refuses=0,actions=0,timers=0,driver_error=0;
uint8_t expected_tid=3;uint16_t expected_window=0,last_refusal=0;
bool expected_amsdu=false;
void timeout_del(int*) {++timers;}
int driver_start(ieee80211com*,ieee80211_node *ni,uint8_t tid) {
 assert(tid==expected_tid);auto &b=ni->ni_tx_ba[tid];
 assert(b.ba_state==IEEE80211_BA_REQUESTED);assert(b.ba_winsize==expected_window);
 assert(((b.ba_params&IEEE80211_ADDBA_BUFSZ_MASK)>>IEEE80211_ADDBA_BUFSZ_SHIFT)==expected_window);
 assert(bool(b.ba_params&IEEE80211_ADDBA_AMSDU)==expected_amsdu);
 assert((b.ba_params&0x003e)==uint16_t(2|(tid<<2)));++starts;return driver_error;
}
void ieee80211_addba_resp_refuse(ieee80211com*,ieee80211_node *ni,uint8_t tid,uint16_t status) {
 ++refuses;last_refusal=status;ni->ni_tx_ba[tid].ba_state=IEEE80211_BA_INIT;
}
void ieee80211_addba_resp_accept(ieee80211com*,ieee80211_node *ni,uint8_t tid) {
 ++accepts;ni->ni_tx_ba[tid].ba_state=IEEE80211_BA_AGREED;
}
void put16(uint8_t *p,uint16_t v) {p[0]=v;p[1]=v>>8;}
mbuf response(unsigned peer,uint8_t token=0x5a,uint16_t status=0,bool amsdu=false) {
 mbuf m{};auto *p=m.bytes+24;p[0]=3;p[1]=1;p[2]=token;
 put16(p+3,status);put16(p+5,(peer<<6)|(expected_tid<<2)|2|(amsdu?1:0));
 put16(p+7,0);return m;
}
void reset() {starts=accepts=refuses=actions=timers=driver_error=0;last_refusal=0;}
void requested(ieee80211_node &n,unsigned window=64) {
 n.ni_tx_ba[expected_tid].ba_winsize=window;
 n.ni_tx_ba[expected_tid].ba_params=(window<<6)|2|(expected_tid<<2)|1;
}
'''
post = r'''
void window_case(unsigned requested_window,unsigned peer,unsigned want,bool cap=false,bool peer_amsdu=false) {
 reset();ieee80211com ic{};ieee80211_node ni{};requested(ni,requested_window);
 ic.ic_ampdu_tx_start=driver_start;ic.ic_caps=cap?IEEE80211_C_TX_AMSDU_IN_AMPDU:0;
 expected_window=want;expected_amsdu=cap&&peer_amsdu;
 auto m=response(peer,0x5a,0,peer_amsdu);ieee80211_recv_addba_resp(&ic,&m,&ni);
 assert(starts==1 && accepts==1 && refuses==0 && actions==0 && timers==1);
 assert(ni.ni_tx_ba[expected_tid].ba_winsize==want);
 assert(ni.ni_tx_ba[expected_tid].ba_state==IEEE80211_BA_AGREED);
}
int main() {
 window_case(64,8,8);window_case(64,32,32);window_case(64,64,64);
 window_case(64,0,64);window_case(64,1023,64);window_case(64,65,64);
 window_case(8,64,8);window_case(8,0,8);window_case(8,1023,8);
 window_case(0,32,32);window_case(0,0,64);
 for(unsigned request=1;request<=64;++request)for(unsigned peer=0;peer<=1023;++peer) {
  unsigned bounded=peer==0 || peer>64?64:peer;
  window_case(request,peer,request<bounded?request:bounded);
 }
 window_case(64,8,8,true,true);window_case(64,32,32,true,false);
 window_case(64,32,32,false,true);
 reset();ieee80211com ic{};ieee80211_node ni{};requested(ni);
 ic.ic_ampdu_tx_start=driver_start;auto wrong=response(8,0x5b);
 ieee80211_recv_addba_resp(&ic,&wrong,&ni);
 assert(starts==0 && accepts==0 && refuses==0 && timers==0 && actions==0);
 assert(ni.ni_tx_ba[expected_tid].ba_winsize==64);
 auto rejected=response(8,0x5a,37);ieee80211_recv_addba_resp(&ic,&rejected,&ni);
 assert(starts==0 && accepts==0 && refuses==1 && last_refusal==37 && timers==1 && actions==1);
 assert(ni.ni_addba_req_intval[expected_tid]==1);
 for(int state:{IEEE80211_BA_INIT,IEEE80211_BA_AGREED}) {
  reset();ni=ieee80211_node{};requested(ni);ni.ni_tx_ba[expected_tid].ba_state=state;
  auto m=response(8);ieee80211_recv_addba_resp(&ic,&m,&ni);
  assert(starts==0 && accepts==0 && refuses==0 && timers==0);
 }
 reset();ni=ieee80211_node{};requested(ni);auto short_m=response(8);short_m.len=32;
 ieee80211_recv_addba_resp(&ic,&short_m,&ni);assert(starts==0 && timers==0);
 for(int error:{EBUSY,EIO}) {
  reset();ni=ieee80211_node{};requested(ni);expected_window=8;expected_amsdu=false;
  driver_error=error;auto m=response(8);ieee80211_recv_addba_resp(&ic,&m,&ni);
  assert(starts==1 && accepts==0 && timers==1);
  assert(error==EBUSY ? (refuses==0 && ni.ni_tx_ba[expected_tid].ba_state==IEEE80211_BA_REQUESTED) :
   (refuses==1 && last_refusal==IEEE80211_STATUS_UNSPECIFIED && ni.ni_tx_ba[expected_tid].ba_state==IEEE80211_BA_INIT));
 }
 puts("PASS actual ADDBA response parser: exhaustive request 1..64/peer 0..1023 windows, callback sees negotiated window, zero/oversize fallback, A-MSDU, rejection/token/state/length guards and driver failures (UBSan).");
}
'''
source = pre + '\n'.join(defines) + stubs + function + post
with tempfile.TemporaryDirectory(prefix='mtk-addba-window-') as tmp:
    cpp, binary = Path(tmp) / 'test.cpp', Path(tmp) / 'test'
    cpp.write_text(source)
    subprocess.run(['clang++', '-std=c++14', '-O1', '-g', '-fsanitize=undefined',
                    '-fno-sanitize-recover=all', str(cpp), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'})
