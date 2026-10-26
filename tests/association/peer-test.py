#!/usr/bin/env python3
"""Exercise actual associated-peer and WTBL capability builders with UBSan."""
from pathlib import Path
import re, subprocess, tempfile
root=Path(__file__).resolve().parents[2]
source=(root/'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text()
wire=(root/'SimpleMtkWlan/hal_mwx/if_mwxreg.h').read_text()
net=root/'mtk80211/openbsd/net80211'
headers=wire+'\n'+'\n'.join((net/p).read_text() for p in ['ieee80211.h','ieee80211_var.h','ieee80211_node.h'])
headers=headers.replace('\\\n','')
def function(signature):
    a=source.index(signature);return source[a:source.index('\n}\n',a)+3]
names=['STA_REC_BASIC','STA_REC_STATE','STA_REC_HT','STA_REC_PHY','STA_REC_RA','STA_REC_HW_AMSDU','STA_REC_VHT','STA_REC_WTBL','WTBL_SET','WTBL_HT','WTBL_VHT','WTBL_SMPS','HT_MCS_MASK_NUM','RA_LEGACY_OFDM','STA_TYPE_AP','STA_TYPE_BC','NETWORK_INFRA','CONN_STATE_DISCONNECT','CONN_STATE_PORT_SECURE','IEEE80211_NODE_HT','IEEE80211_NODE_VHT','IEEE80211_NODE_HE','IEEE80211_NODE_QOS','IEEE80211_HTCAP_LDPC','IEEE80211_HTCAP_CBW20_40','IEEE80211_HTCAP_SGI40','IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_160MHZ','IEEE80211_VHTCAP_RXLDPC','IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK','IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT']
defines='\n'.join(re.search(r'^#define\s+'+re.escape(n)+r'\s+[^\n]+',headers,re.M).group() for n in names)
structs='\n'.join(re.search(r'struct '+n+r' \{.*?\} __packed;',wire,re.S).group() for n in ['sta_rec_basic','sta_rec_state','sta_rec_wtbl','sta_rec_ht_v1','sta_rec_phy','sta_rec_ra_info','sta_rec_amsdu','sta_rec_vht_v1','wtbl_ht','wtbl_vht','wtbl_smps'])
pre=r'''
#include <cstdint>
#include <cstring>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <libkern/OSByteOrder.h>
#define __packed __attribute__((packed))
#define IEEE80211_STA_ONLY
#define IEEE80211_ADDR_LEN 6
#define IEEE80211_AID(x) ((x)&0x3fff)
#define MWX_DEV_LOG(...) ((void)0)
#define MCU_UNI_CMD_STA_REC_UPDATE 0x20003
#define IEEE80211_M_STA 1
#define IEEE80211_M_MONITOR 8
#define htole16(x) OSSwapHostToLittleInt16(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
enum{CMD_CBW_20MHZ,CMD_CBW_40MHZ,CMD_CBW_80MHZ,CMD_CBW_160MHZ};
enum{IEEE80211_CHAN_WIDTH_20_NOHT,IEEE80211_CHAN_WIDTH_20,IEEE80211_CHAN_WIDTH_40,IEEE80211_CHAN_WIDTH_80,IEEE80211_CHAN_WIDTH_80P80,IEEE80211_CHAN_WIDTH_160};
struct ieee80211_he_cap_elem{uint8_t mac[6],phy[11];};struct ieee80211_he_mcs_nss_supp{uint16_t v[6];};
struct ieee80211_channel{int ic_freq=5200,ic_center_freq1=5200;uint32_t ic_flags=0;};
struct ieee80211_node{
 uint16_t ni_associd=uint16_t(0xc000|37);uint32_t ni_flags=0;uint16_t ni_htcaps=0;
 uint8_t ni_ampdu_param=0,ni_rxmcs[10]={};uint32_t ni_vhtcaps=0;
 struct{uint16_t rx_mcs_map,rx_highest,tx_mcs_map,tx_highest;}ni_vht_mcsinfo={};
 int ni_chw=IEEE80211_CHAN_WIDTH_20;ieee80211_channel*ni_chan=nullptr;
 uint8_t ni_macaddr[6]={0x10,0x20,0x30,0x40,0x50,0x60};ieee80211_he_cap_elem ni_he_cap_elem{};ieee80211_he_mcs_nss_supp ni_he_mcs_nss_supp{};};
struct mwx_node{ieee80211_node ni;uint16_t wcid=287;};
struct mwx_vif{uint8_t omac_idx=3;};
struct ieee80211com{ieee80211_node*ic_bss;uint8_t ic_sup_mcs[10]={};int ic_opmode=IEEE80211_M_STA;};
struct mwx_softc{ieee80211com sc_ic;mwx_vif sc_vif;struct{uint8_t num_streams=2;}sc_capa;int8_t sc_tx_amsdu=0;int8_t sc_he_enabled=0;};
struct sta_req_hdr{uint8_t unused[8];};
struct mbuf{alignas(8) unsigned char bytes[1024];size_t len;};
mbuf storage;bool alloc_fail=false,header_fail=false;int send_rc=0,wait_rc=0,sends=0,waits=0;uint32_t fw=0;unsigned sent_tlv_count=0;
int ieee80211_mhz2ieee(int f,uint32_t){return(f-5000)/5;}
void panic(const char*){std::abort();}
uint8_t mt7921_get_phy_mode_v2(mwx_softc*,ieee80211_node*){return 0x31;}
mbuf*mwx_alloc_sta_req_tlv(size_t n){assert(n==sizeof(sta_req_hdr));memset(&storage,0xbd,sizeof(storage));storage.len=0;return alloc_fail?nullptr:&storage;}
void*mwx_append_tlv(mbuf*m,uint16_t*n,int tag,int len){assert(len>=4&&m->len+len<=sizeof(m->bytes));auto*p=m->bytes+m->len;memset(p,0,len);uint16_t h[2]={htole16(tag),htole16(len)};memcpy(p,h,4);m->len+=len;(*n)++;return p;}
mbuf*mwx_fill_sta_req_hdr(mbuf*m,mwx_vif*,uint8_t omac,uint16_t wcid,uint16_t n){assert(omac==3&&wcid==287);sent_tlv_count=n;return header_fail?nullptr:m;}
void verify_payload(mwx_softc*,mbuf*);
void mwx_add_sta_he_tlvs(mbuf*,uint16_t*,ieee80211_node*){assert(false);}
int mwx_mcu_send_mbuf(mwx_softc*sc,int cmd,mbuf*m,int*seq){assert(cmd==0x20003);verify_payload(sc,m);*seq=9;sends++;return send_rc;}
int mwx_mcu_wait_resp_int(mwx_softc*,int cmd,int seq,uint32_t*status){assert(cmd==0x20003&&seq==9);*status=fw;waits++;return wait_rc;}
'''
checks=r'''
struct Header{uint16_t tag,len;}__packed;
static Header hdr(mbuf*m,size_t p){assert(p+4<=m->len);Header h;memcpy(&h,m->bytes+p,4);h.tag=le16toh(h.tag);h.len=le16toh(h.len);assert(h.len>=4&&p+h.len<=m->len);return h;}
template<class T>const T*consume(mbuf*m,size_t&p,uint16_t tag){auto h=hdr(m,p);assert(h.tag==tag&&h.len==sizeof(T));auto*t=reinterpret_cast<const T*>(m->bytes+p);p+=h.len;return t;}
void verify_payload(mwx_softc*sc,mbuf*m){
 const auto*ni=sc->sc_ic.ic_bss;size_t p=0;unsigned count=0;
 auto*basic=consume<sta_rec_basic>(m,p,0x00);count++;
 assert(le16toh(basic->aid)==37&&le32toh(basic->conn_type)==0x10002);
 assert(basic->conn_state==2&&le16toh(basic->extra_info)==1);
 assert(!memcmp(basic->peer_addr,ni->ni_macaddr,6));assert(basic->qos==bool(ni->ni_flags&IEEE80211_NODE_QOS));
 if(ni->ni_flags&IEEE80211_NODE_HT){
  auto*ht=consume<sta_rec_ht_v1>(m,p,0x09);count++;assert(le16toh(ht->ht_cap)==ni->ni_htcaps&&ht->rsv==0);
  auto*phy=consume<sta_rec_phy>(m,p,0x15);count++;assert(le16toh(phy->basic_rate)==0x0150&&phy->phy_type==0x31);assert(phy->ampdu==(ni->ni_ampdu_param&0x1f)&&phy->rcpi==0xdc);
  auto*ra=consume<sta_rec_ra_info>(m,p,0x01);count++;assert(le16toh(ra->legacy)==0x3fc0);
  for(int i=0;i<10;i++)assert(ra->rx_mcs_bitmask[i]==(ni->ni_rxmcs[i]&(i<2?sc->sc_ic.ic_sup_mcs[i]:0)));
  if(sc->sc_tx_amsdu){auto*a=consume<sta_rec_amsdu>(m,p,0x0f);count++;assert(a->max_amsdu_num==8&&a->max_mpdu_size==1&&a->amsdu_en==1&&a->rsv==0);}
 }
 if(ni->ni_flags&IEEE80211_NODE_VHT){auto*v=consume<sta_rec_vht_v1>(m,p,0x0a);count++;assert(le32toh(v->vht_cap)==ni->ni_vhtcaps);assert(v->vht_rx_mcs_map==htole16(ni->ni_vht_mcsinfo.rx_mcs_map));assert(v->vht_tx_mcs_map==htole16(ni->ni_vht_mcsinfo.tx_mcs_map));}
 auto*state=consume<sta_rec_state>(m,p,0x07);count++;assert(!le32toh(state->flags)&&state->state==2&&!state->action&&!state->rsv[0]);
 if(ni->ni_flags&IEEE80211_NODE_VHT){int w=ni->ni_chw==IEEE80211_CHAN_WIDTH_160?3:ni->ni_chw==IEEE80211_CHAN_WIDTH_80?2:ni->ni_chw==IEEE80211_CHAN_WIDTH_40?1:0;assert(state->vht_opmode==(w|((sc->sc_capa.num_streams>1?1:0)<<4)));}
 else{unsigned char golden[]={7,0,12,0,0,0,0,0,2,0,0,0};assert(sizeof(sta_rec_state)==12&&!memcmp(state,golden,12));}
 if(ni->ni_flags&IEEE80211_NODE_HT){
  size_t begin=p;auto top=hdr(m,begin);assert(top.tag==0x0d&&top.len>=sizeof(sta_rec_wtbl));auto*w=reinterpret_cast<const sta_rec_wtbl*>(m->bytes+begin);count++;
  assert(w->wlan_idx_lo==0x1f&&w->wlan_idx_hi==1);assert(w->operation==2); // WTBL_SET, not RESET_AND_SET.
  assert(!w->rsv[0]&&!w->rsv[1]&&!w->rsv[2]);p+=sizeof(*w);unsigned nested=0;
  auto*ht=consume<wtbl_ht>(m,p,0x02);nested++;assert(ht->ht==1&&ht->ldpc==bool(ni->ni_htcaps&IEEE80211_HTCAP_LDPC));
  unsigned af=ni->ni_ampdu_param&3;if(ni->ni_flags&IEEE80211_NODE_VHT){unsigned a=(ni->ni_vhtcaps&IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK)>>IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT;if(a>af)af=a;}
  assert(ht->af==af&&ht->mm==((ni->ni_ampdu_param>>2)&7));
  if(ni->ni_flags&IEEE80211_NODE_VHT){auto*v=consume<wtbl_vht>(m,p,0x03);nested++;assert(v->vht==1&&v->ldpc==bool(ni->ni_vhtcaps&IEEE80211_VHTCAP_RXLDPC));assert(!v->dyn_bw&&!v->txop_ps);}
  auto*smps=consume<wtbl_smps>(m,p,0x0d);nested++;assert(!smps->smps&&!smps->rsv[0]&&!smps->rsv[1]&&!smps->rsv[2]);
  assert(le16toh(w->tlv_num)==nested&&top.len==p-begin);
 }
 assert(p==m->len&&sent_tlv_count==count);
}
'''
post=r'''
int main(){
 mwx_node n;ieee80211_channel c;n.ni.ni_chan=&c;mwx_softc sc{{&n.ni},{3}};
 assert(mt7921_mcu_set_associated_peer(&sc)==0);assert(sends==1&&waits==1);
 fw=7;assert(mt7921_mcu_set_associated_peer(&sc)==EIO);fw=0;
 wait_rc=ETIMEDOUT;assert(mt7921_mcu_set_associated_peer(&sc)==ETIMEDOUT);wait_rc=0;
 int before=waits;send_rc=ENOBUFS;assert(mt7921_mcu_set_associated_peer(&sc)==ENOBUFS&&waits==before);send_rc=0;
 before=sends;alloc_fail=true;assert(mt7921_mcu_set_associated_peer(&sc)==ENOBUFS&&sends==before);alloc_fail=false;
 header_fail=true;assert(mt7921_mcu_set_associated_peer(&sc)==ENOBUFS&&sends==before);header_fail=false;
 n.ni.ni_associd=0;assert(mt7921_mcu_set_associated_peer(&sc)==EINVAL&&sends==before);
 sc.sc_ic.ic_bss=nullptr;assert(mt7921_mcu_set_associated_peer(&sc)==EINVAL&&sends==before);
 sc.sc_ic.ic_bss=&n.ni;n.ni.ni_associd=uint16_t(0xc000|37);
 n.ni.ni_flags=IEEE80211_NODE_HT|IEEE80211_NODE_QOS;
 n.ni.ni_htcaps=IEEE80211_HTCAP_LDPC|IEEE80211_HTCAP_CBW20_40|IEEE80211_HTCAP_SGI40;
 n.ni.ni_ampdu_param=0x16;memset(n.ni.ni_rxmcs,0xff,10);sc.sc_ic.ic_sup_mcs[0]=0xff;sc.sc_ic.ic_sup_mcs[1]=0x0f;
 assert(mt7921_mcu_set_associated_peer(&sc)==0);
 n.ni.ni_flags|=IEEE80211_NODE_VHT;n.ni.ni_vhtcaps=IEEE80211_VHTCAP_RXLDPC|IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_160MHZ|(5U<<IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT);
 n.ni.ni_vht_mcsinfo.rx_mcs_map=n.ni.ni_vht_mcsinfo.tx_mcs_map=0xfffa;
 for(int streams:{1,2}){sc.sc_capa.num_streams=streams;
  for(int w:{IEEE80211_CHAN_WIDTH_20,IEEE80211_CHAN_WIDTH_40,IEEE80211_CHAN_WIDTH_80,IEEE80211_CHAN_WIDTH_160}){
   n.ni.ni_chw=w;c.ic_center_freq1=w==IEEE80211_CHAN_WIDTH_160?5250:w==IEEE80211_CHAN_WIDTH_80?5210:w==IEEE80211_CHAN_WIDTH_40?5190:5200;
   for(int a:{0,1}){sc.sc_tx_amsdu=a;assert(mt7921_mcu_set_associated_peer(&sc)==0);}
  }
 }
 n.ni.ni_htcaps=0;n.ni.ni_vhtcaps=0;assert(mt7921_mcu_set_associated_peer(&sc)==0);
 puts("PASS actual peer/BASIC/WTBL/width builders: golden STATE, AID/WCID, exact nesting/length/count, WTBL_SET, LDPC/AF/MM/MCS, 20/40/80/160 opmode, preserved160, AMSDU and all failure guards.");
}
'''
helpers='\n'.join([function('void\nmt7921_mcu_add_basic_tlv('),function('int\nmt7921_mcu_wtbl_ht_tlv('),function('static void\nmwx_node_chan_width(')])
fn=function('int mt7921_mcu_set_associated_peer(struct mwx_softc *sc)\n{')
with tempfile.TemporaryDirectory(prefix='mtk-peer-wire-') as tmp:
    path=Path(tmp)/'peer-test.cpp';path.write_text(defines+'\n'+pre+structs+'\n'+helpers+fn+checks+post)
    exe=path.with_suffix('')
    subprocess.run(['clang++','-std=c++14','-fsanitize=undefined','-fno-sanitize-recover=undefined',str(path),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
