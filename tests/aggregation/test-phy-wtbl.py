"""Verify actual PHY WTBL builders and packed wire structs under UBSan."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / 'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text()
WIRE = (ROOT / 'SimpleMtkWlan/hal_mwx/if_mwxreg.h').read_text()
HEADERS = '\n'.join((ROOT / ('mtk80211/openbsd/net80211/' + n)).read_text()
                    for n in ['ieee80211.h', 'ieee80211_node.h'])


def function(name):
    match = re.search(r'(?m)^(?:int\s+|int\n)' + name + r'\([^;]+?\)\s*\{', SRC)
    assert match, name
    end = SRC.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (SRC[end] == '{') - (SRC[end] == '}')
        end += 1
    return SRC[match.start():end]


def structure(name):
    match = re.search(r'struct ' + name + r'\s*\{.*?\} __packed;', WIRE, re.S)
    assert match, name
    return match.group()


def define(name, source):
    match = re.search(r'(?m)^#define[ \t]+' + name + r'[ \t]+(?:[^\n]*\\\n)*[^\n]*', source)
    assert match, name
    return match.group()


constants = ['WTBL_HT', 'WTBL_VHT', 'WTBL_SMPS', 'WTBL_SET',
             'WTBL_RESET_AND_SET', 'STA_REC_WTBL', 'STA_REC_HT', 'STA_REC_PHY',
             'STA_REC_RA', 'STA_REC_STATE', 'STA_REC_VHT', 'STA_REC_HW_AMSDU',
             'HT_MCS_MASK_NUM', 'RA_LEGACY_OFDM']
bandwidth_enum = re.search(r'enum \{\s*CMD_CBW_20MHZ,.*?\};', WIRE, re.S).group()
capabilities = ['IEEE80211_NODE_HT', 'IEEE80211_NODE_VHT', 'IEEE80211_NODE_HE', 'IEEE80211_HTCAP_LDPC',
                'IEEE80211_VHTCAP_RXLDPC',
                'IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK',
                'IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT']
structs = ['wtbl_ht', 'wtbl_vht', 'wtbl_smps', 'sta_rec_wtbl', 'sta_req_hdr',
           'sta_rec_ht_v1', 'sta_rec_phy', 'sta_rec_ra_info', 'sta_rec_state',
           'sta_rec_vht_v1', 'sta_rec_amsdu']
helper = function('mt7921_mcu_wtbl_ht_tlv')
associated = function('mt7921_mcu_set_associated_peer')

pre = r'''
#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <vector>
#define __packed __attribute__((packed))
#define MWX_DEV_LOG(...) ((void)0)
#define IEEE80211_AID(x) ((x) & 0x3fff)
#define MCU_UNI_CMD_STA_REC_UPDATE 0x20003
#ifndef htole16
#define htole16(x) (x)
#define htole32(x) (x)
#define le16toh(x) (x)
#endif
'''
stubs = r'''
struct ieee80211_node {
 uint16_t ni_associd=37; uint32_t ni_flags=0; uint16_t ni_htcaps=0; uint8_t hecap[17]={};
 uint8_t ni_ampdu_param=0, ni_rxmcs[10]={}; uint32_t ni_vhtcaps=0;
 struct {uint16_t rx_mcs_map, rx_highest, tx_mcs_map, tx_highest;} ni_vht_mcsinfo={};
 int ni_chw=0;
};
struct mwx_node {ieee80211_node ni; uint16_t wcid=0x11f;};
static_assert(offsetof(mwx_node, ni)==0, "node cast must match driver");
struct mwx_vif {uint8_t omac_idx=3;};
struct mwx_softc {
 struct {ieee80211_node *ic_bss=nullptr; uint8_t ic_sup_mcs[10]={};} sc_ic;
 mwx_vif sc_vif; struct {uint8_t num_streams=2;} sc_capa; int8_t sc_tx_amsdu=0; int8_t sc_he_enabled=0;
};
struct mbuf {alignas(8) uint8_t bytes[1024]; size_t len=0;};
mbuf storage; uint16_t outer_count=0; int sends=0;
void *mwx_append_tlv(mbuf *m,uint16_t *n,int tag,int len) {
 assert(len>=4 && m->len+len<=sizeof(m->bytes));
 uint8_t *p=m->bytes+m->len; memset(p,0,len);
 uint16_t wiretag=htole16(tag), wirelen=htole16(len);
 memcpy(p,&wiretag,2);memcpy(p+2,&wirelen,2);
 m->len+=len; ++*n; return p;
}
mbuf *mwx_alloc_sta_req_tlv(size_t len) {
 memset(&storage,0,sizeof(storage)); storage.len=len; return &storage;
}
void mt7921_mcu_add_basic_tlv(mbuf *m,uint16_t *n,mwx_softc*,ieee80211_node*,int add,int isnew) {
 assert(add==1 && isnew==0);mwx_append_tlv(m,n,0,20);
}
uint8_t mt7921_get_phy_mode_v2(mwx_softc*,ieee80211_node*) {return 0x38;}
void mwx_add_sta_he_tlvs(mbuf*,uint16_t*,ieee80211_node*) {assert(false);}
void mwx_node_chan_width(ieee80211_node *ni,uint8_t *bw,uint8_t *center) {*bw=ni->ni_chw;*center=42;}
mbuf *mwx_fill_sta_req_hdr(mbuf *m,mwx_vif*,uint8_t omac,uint16_t wcid,uint16_t n) {
 assert(omac==3 && wcid==0x11f); outer_count=n;return m;
}
int mwx_mcu_send_mbuf(mwx_softc*,int cmd,mbuf*,int *seq) {
 assert(cmd==MCU_UNI_CMD_STA_REC_UPDATE && seq); *seq=7; ++sends;return 0;
}
int mwx_mcu_wait_resp_int(mwx_softc*,int cmd,int seq,uint32_t *status) {
 assert(cmd==MCU_UNI_CMD_STA_REC_UPDATE && seq==7);*status=0;return 0;
}
uint16_t u16(const uint8_t *p) {return uint16_t(p[0]) | uint16_t(p[1])<<8;}
std::vector<const uint8_t*> top_tlvs(const mbuf &m) {
 std::vector<const uint8_t*> v; size_t pos=sizeof(sta_req_hdr);
 while(pos<m.len) {assert(pos+4<=m.len);const auto *p=m.bytes+pos;
  auto len=u16(p+2);assert(len>=4 && pos+len<=m.len);v.push_back(p);pos+=len;}
 assert(pos==m.len);return v;
}
void check_reserved(const uint8_t *p,size_t begin,size_t end) {
 for(size_t i=begin;i<end;++i) assert(p[i]==0);
}
'''
post = r'''
static_assert(sizeof(wtbl_ht)==12,"WTBL_HT wire size");
static_assert(sizeof(wtbl_vht)==12,"WTBL_VHT wire size");
static_assert(sizeof(wtbl_smps)==8,"WTBL_SMPS wire size");
static_assert(sizeof(sta_rec_wtbl)==12,"STA_REC_WTBL wire size");
void helper_case(uint32_t flags,unsigned ht_af,unsigned density,unsigned vht_af,bool hldpc,bool vldpc) {
 mwx_softc sc{};ieee80211_node ni{};ni.ni_flags=flags;
 ni.ni_ampdu_param=uint8_t(ht_af | density<<2);
 ni.ni_htcaps=hldpc?IEEE80211_HTCAP_LDPC:0;
 ni.ni_vhtcaps=(vht_af<<IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT) |
  (vldpc?IEEE80211_VHTCAP_RXLDPC:0);
 mbuf m{};memset(m.bytes,0xa5,sizeof(m.bytes));uint16_t count=0;
 int len=mt7921_mcu_wtbl_ht_tlv(&m,&count,&sc,&ni);
 bool ht=flags&IEEE80211_NODE_HT,vht=flags&IEEE80211_NODE_VHT;
 assert(len==int((ht?12:0)+(vht?12:0)+8));assert(m.len==size_t(len));
 assert(count==unsigned(ht)+unsigned(vht)+1);
 size_t pos=0;
 if(ht) {auto *p=m.bytes+pos;assert(u16(p)==WTBL_HT && u16(p+2)==12);
  assert(p[4]==1 && p[5]==hldpc);
  assert(p[6]==(vht && vht_af>ht_af?vht_af:ht_af));assert(p[7]==density);
  check_reserved(p,8,12);pos+=12;}
 if(vht) {auto *p=m.bytes+pos;assert(u16(p)==WTBL_VHT && u16(p+2)==12);
  assert(p[4]==vldpc && p[5]==0 && p[6]==1 && p[7]==0);
  check_reserved(p,8,12);pos+=12;}
 auto *p=m.bytes+pos;assert(u16(p)==WTBL_SMPS && u16(p+2)==8);
 check_reserved(p,4,8);assert(m.bytes[m.len]==0xa5);
}
void associated_case(bool vht) {
 mwx_node n{};mwx_softc sc{};sc.sc_ic.ic_bss=&n.ni;
 n.ni.ni_flags=IEEE80211_NODE_HT | (vht?IEEE80211_NODE_VHT:0);
 n.ni.ni_htcaps=IEEE80211_HTCAP_LDPC;n.ni.ni_ampdu_param=0x17;
 n.ni.ni_vhtcaps=IEEE80211_VHTCAP_RXLDPC |
  (7U<<IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT);
 n.ni.ni_chw=CMD_CBW_80MHZ;int before=sends;
 assert(mt7921_mcu_set_associated_peer(&sc)==0 && sends==before+1);
 auto tops=top_tlvs(storage);assert(tops.size()==outer_count);
 unsigned seen=0;
 for(auto *p:tops) if(u16(p)==STA_REC_WTBL) {
  ++seen;auto *w=reinterpret_cast<const sta_rec_wtbl*>(p);
  assert(w->wlan_idx_lo==0x1f && w->wlan_idx_hi==1);
  assert(w->operation==WTBL_SET && w->operation!=WTBL_RESET_AND_SET);
  assert(le16toh(w->tlv_num)==(vht?3:2));
  assert(u16(p+2)==sizeof(*w)+(vht?32:20));
  check_reserved(p,9,12);size_t pos=sizeof(*w);unsigned nchild=0;
  while(pos<u16(p+2)) {assert(pos+4<=u16(p+2));auto *c=p+pos;
   assert(u16(c)==WTBL_HT || u16(c)==WTBL_VHT || u16(c)==WTBL_SMPS);
   auto len=u16(c+2);assert(len>=8 && pos+len<=u16(p+2));
   pos+=len;++nchild;}
  assert(pos==u16(p+2) && nchild==le16toh(w->tlv_num));
 }
 assert(seen==1);
}
int main() {
 for(unsigned af=0;af<4;++af) for(unsigned density=0;density<8;++density)
  for(unsigned vf=0;vf<8;++vf) for(unsigned ldpc=0;ldpc<4;++ldpc) {
   helper_case(IEEE80211_NODE_HT|IEEE80211_NODE_VHT,af,density,vf,ldpc&1,ldpc&2);
   helper_case(IEEE80211_NODE_HT,af,density,vf,ldpc&1,ldpc&2);
  }
 helper_case(0,3,7,7,true,true);
 helper_case(IEEE80211_NODE_VHT,3,7,7,true,true);
 associated_case(false);associated_case(true);
 puts("PASS actual PHY WTBL helper: wire sizes 12/12/8, exhaustive AF/density/LDPC, negotiated flags, reserved bytes, nested counts/lengths/WCID, WTBL_SET without reset (UBSan).");
}
'''
source = (pre + '\n'.join(define(n, WIRE) for n in constants) + '\n' +
          '\n'.join(define(n, HEADERS) for n in capabilities) + '\n' +
          bandwidth_enum + '\n'.join(structure(n) for n in structs) + stubs + helper + associated + post)
with tempfile.TemporaryDirectory(prefix='mtk-phy-wtbl-') as tmp:
    cpp, binary = Path(tmp) / 'test.cpp', Path(tmp) / 'test'
    cpp.write_text(source)
    subprocess.run(['clang++', '-std=c++14', '-O1', '-g', '-fsanitize=undefined',
                    '-fno-sanitize-recover=all', str(cpp), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'})
