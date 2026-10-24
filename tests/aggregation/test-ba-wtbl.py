#!/usr/bin/env python3
"""Validate real BA/WTBL builders against Linux wire bytes using UBSan.
Host allocation/mbuf/MCU stubs validate layout/order/failures, not radio or ACKs.
"""
from pathlib import Path
import re, subprocess, tempfile
root=Path(__file__).resolve().parents[2]
s=(root/'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text()
h=(root/'SimpleMtkWlan/hal_mwx/if_mwxreg.h').read_text()
def fn(name):
 m=re.search(r'(?m)^(?:static\s+)?(?:struct mbuf \*|void \*|int)\s*\n'+re.escape(name)+r'\([^;]*?\)\s*\n\{',s)
 assert m, 'Missing actual driver function: '+name
 return s[m.start():s.index('\n}',m.end())+2]+'\n'
def struct(name):
 m=re.search(r'(?m)^struct '+re.escape(name)+r' \{.*?^\} __packed(?: __aligned\(4\))?;',h,re.S|re.M)
 assert m,'Missing actual protocol structure: '+name
 return m.group()+'\n'
wire=''.join(struct(n) for n in ('sta_req_hdr','sta_rec_wtbl','sta_rec_ba','wtbl_ba','mwx_mcu_txd'))
constants='\n'.join(l for l in h.splitlines() if re.match(r'#define\s+(STA_REC_WTBL|STA_REC_BA|WTBL_SET|WTBL_BA|MT_BA_TYPE_ORIGINATOR|MT_BA_TYPE_RECIPIENT|RST_BA_MAC_TID_MATCH)\b',l))
node_header=(root/'mtk80211/openbsd/net80211/ieee80211_node.h').read_text()
max_window=re.search(r'(?m)^#define\s+IEEE80211_BA_MAX_WINSZ\s+64\b.*$',node_header)
assert max_window, 'Inspect changed maximum BA window before updating golden protocol bytes'
constants+='\n'+max_window.group()
real='\n'.join(fn(n) for n in ('mwx_alloc_sta_req_tlv','mwx_append_len','mwx_append_tlv','mwx_fill_sta_req_hdr','mwx_mcu_wtbl_ba','mwx_mcu_sta_ba'))
pre=r'''
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>
#include <sys/types.h>
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#define IEEE80211_ADDR_LEN 6
#define IEEE80211_ADDR_COPY(a,b) memcpy((a),(b),6)
#define MWX_DEV_LOG(...) ((void)0)
#define KASSERT(x,...) assert(x)
#define MCLBYTES 2048
#define M_DONTWAIT 0
#define MCU_UNI_CMD_STA_REC_UPDATE 0x20003
#ifndef htole16
#define htole16(x) uint16_t(x)
#define le16toh(x) uint16_t(x)
#endif
#ifndef htole32
#define htole32(x) uint32_t(x)
#define le32toh(x) uint32_t(x)
#endif
struct ieee80211_node { uint8_t ni_macaddr[6]; };
struct mwx_node { ieee80211_node ni; uint16_t wcid; };
struct mwx_vif { uint8_t idx,omac_idx,band_idx; };
struct mwx_softc { mwx_vif sc_vif; int8_t sc_wtbl_ba; };
struct mbuf { alignas(8) uint8_t raw[2048]; size_t off,len,pktlen; };
using Packet=std::vector<uint8_t>;
static std::vector<Packet> sent;
static unsigned allocs,prepends,live,frees,alloc_fail_at,prepend_fail_at,send_fail_at;
static mbuf *MCLGETL(void*,int,size_t bytes){assert(bytes<=2048);if(++allocs==alloc_fail_at)return nullptr;auto*m=new mbuf;memset(m,0xa5,sizeof(*m));m->off=m->len=m->pktlen=0;++live;return m;}
static void m_freem(mbuf*m){if(m){assert(live);--live;++frees;delete m;}}
static void*mbuf_data(mbuf*m){return m->raw+m->off;}
static size_t mbuf_len(mbuf*m){return m->len;}
static size_t mbuf_pkthdr_len(mbuf*m){return m->pktlen;}
static void mbuf_setdata(mbuf*m,void*p,size_t len){auto off=static_cast<uint8_t*>(p)-m->raw;assert(off>=0&&size_t(off)+len<=sizeof(m->raw));m->off=off;m->len=len;}
static void mbuf_setlen(mbuf*m,size_t len){assert(m->off+len<=sizeof(m->raw));m->len=len;}
static void mbuf_pkthdr_setlen(mbuf*m,size_t len){m->pktlen=len;}
static size_t m_leadingspace(mbuf*m){return m->off;}
static size_t m_trailingspace(mbuf*m){return sizeof(m->raw)-m->off-m->len;}
#define mtod(m,t) reinterpret_cast<t>((m)->raw+(m)->off)
static mbuf*m_prepend(mbuf*m,size_t len,int){if(++prepends==prepend_fail_at){m_freem(m);return nullptr;}assert(m->off>=len);m->off-=len;m->len+=len;m->pktlen+=len;return m;}
static int mwx_mcu_send_mbuf(mwx_softc*,uint32_t cmd,mbuf*m,int*seq){assert(cmd==MCU_UNI_CMD_STA_REC_UPDATE&&seq==nullptr);assert(m->len==m->pktlen);sent.emplace_back(mtod(m,uint8_t*),mtod(m,uint8_t*)+m->len);m_freem(m);return sent.size()==send_fail_at?EIO:0;}
'''
post=r'''
static_assert(sizeof(sta_req_hdr)==8,"STA header size");
static_assert(sizeof(sta_rec_wtbl)==12&&sizeof(sta_rec_ba)==12,"STA TLV sizes");
static_assert(sizeof(wtbl_ba)==28,"WTBL BA size");
static_assert(offsetof(sta_rec_wtbl,operation)==5&&offsetof(sta_rec_wtbl,tlv_num)==6&&offsetof(sta_rec_wtbl,wlan_idx_hi)==8,"WTBL wrapper offsets");
static_assert(offsetof(wtbl_ba,tid)==4&&offsetof(wtbl_ba,ba_type)==5,"BA common offsets");
static_assert(offsetof(wtbl_ba,sn)==8&&offsetof(wtbl_ba,ba_en)==10&&offsetof(wtbl_ba,ba_winsize_idx)==11,"BA TX offsets");
static_assert(offsetof(wtbl_ba,ba_winsize)==12&&offsetof(wtbl_ba,peer_addr)==14,"BA window/address offsets");
static_assert(offsetof(wtbl_ba,rst_ba_tid)==20&&offsetof(wtbl_ba,rst_ba_sel)==21&&offsetof(wtbl_ba,rst_ba_sb)==22&&offsetof(wtbl_ba,band_idx)==23,"RX reset offsets");
static_assert(offsetof(sta_rec_ba,ba_en)==7&&offsetof(sta_rec_ba,ssn)==8,"STA BA offsets");
static void reset(){assert(live==0);sent.clear();allocs=prepends=frees=alloc_fail_at=prepend_fail_at=send_fail_at=0;}
static void equal(const Packet&a,const Packet&g){if(a!=g){fprintf(stderr,"wire mismatch actual=%zu expected=%zu\n",a.size(),g.size());for(auto b:a)fprintf(stderr,"%02x ",b);fputc('\n',stderr);for(auto b:g)fprintf(stderr,"%02x ",b);fputc('\n',stderr);abort();}}
static Packet golden_wtbl(uint8_t tid,bool enable,bool tx){
 // STA8 + WTBL12 + BA28; these constants do not use driver structures.
 Packet p={2,0x1f,1,0,1,3,1,0, 0x0d,0,40,0,0x1f,2,1,0,1,0,0,0,
 8,0,28,0,tid,uint8_t(tx?1:2),0,0, 0,0,0,0,0,0, 0,0,0,0,0,0, 0,0,0,0, 0,0,0,0};
 if(enable)p[32]=64;
 if(tx){if(enable){p[28]=0xbc;p[29]=0x0a;p[30]=1;}}
 else{const uint8_t peer[]={0xe4,0x4e,0x12,0x96,0xc4,0x20};std::copy(peer,peer+6,p.begin()+34);p[40]=tid;p[41]=0;p[42]=1;}
 return p;
}
static Packet golden_sta(uint8_t tid,bool enable,bool tx,int amsdu){return{2,0x1f,1,0,1,3,1,0,6,0,12,0,tid,uint8_t(tx?1:2),uint8_t(amsdu?1:0),uint8_t(enable?(1u<<tid):0),uint8_t(enable?0xbc:0),uint8_t(enable?0x0a:0),uint8_t(enable?64:0),0};}
int main(){
 const uint16_t endian=1;assert(*reinterpret_cast<const uint8_t*>(&endian)==1);
 assert(STA_REC_WTBL==0x0d&&STA_REC_BA==6&&WTBL_SET==2&&WTBL_BA==8);
 mwx_node node{{{0xe4,0x4e,0x12,0x96,0xc4,0x20}},0x11f};mwx_softc sc{{2,3,0},1};unsigned cases=0;
 for(uint8_t tid:{uint8_t(0),uint8_t(7)})for(bool tx:{false,true})for(bool enable:{false,true}){
  reset();int amsdu=tx?1:0;assert(mwx_mcu_sta_ba(&sc,&node.ni,tid,enable?0xabc:0,enable?64:0,enable,tx,amsdu)==0);
  assert(sent.size()==2&&allocs==2&&prepends==2&&live==0);equal(sent[0],golden_wtbl(tid,enable,tx));equal(sent[1],golden_sta(tid,enable,tx,amsdu));++cases;
 }
 reset();sc.sc_wtbl_ba=0;assert(mwx_mcu_sta_ba(&sc,&node.ni,7,0xabc,64,1,1,1)==0);assert(sent.size()==1&&allocs==1);equal(sent[0],golden_sta(7,true,true,1));sc.sc_wtbl_ba=1;
 reset();assert(mwx_mcu_sta_ba(&sc,nullptr,0,0,64,1,1,0)==EINVAL);
 for(uint8_t tid:{uint8_t(8),uint8_t(255)})assert(mwx_mcu_sta_ba(&sc,&node.ni,tid,0,64,1,1,0)==EINVAL);
 for(uint16_t win:{uint16_t(0),uint16_t(65),uint16_t(65535)})assert(mwx_mcu_sta_ba(&sc,&node.ni,0,0,win,1,1,0)==EINVAL);
 assert(sent.empty()&&allocs==0&&live==0);
 reset();alloc_fail_at=1;assert(mwx_mcu_sta_ba(&sc,&node.ni,0,0xabc,64,1,1,1)==ENOBUFS);assert(allocs==1&&sent.empty()&&live==0);
 reset();prepend_fail_at=1;assert(mwx_mcu_sta_ba(&sc,&node.ni,0,0xabc,64,1,1,1)==ENOBUFS);assert(allocs==1&&sent.empty()&&live==0);
 reset();send_fail_at=1;assert(mwx_mcu_sta_ba(&sc,&node.ni,0,0xabc,64,1,1,1)==EIO);assert(allocs==1&&sent.size()==1&&live==0);
 reset();alloc_fail_at=2;assert(mwx_mcu_sta_ba(&sc,&node.ni,0,0xabc,64,1,1,1)==ENOBUFS);assert(allocs==2&&sent.size()==1&&live==0);
 reset();prepend_fail_at=2;assert(mwx_mcu_sta_ba(&sc,&node.ni,0,0xabc,64,1,1,1)==ENOBUFS);assert(allocs==2&&sent.size()==1&&live==0);
 reset();send_fail_at=2;assert(mwx_mcu_sta_ba(&sc,&node.ni,0,0xabc,64,1,1,1)==EIO);assert(allocs==2&&sent.size()==2&&live==0);
 printf("PASS actual BA/WTBL builders: %u TX/RX TID0/7 start/stop golden pairs; packed offsets; WTBL_SET before STA_REC_BA; fallback/input/allocation/header/send failures; UBSan. Host wire contract only.\n",cases);
}
'''
with tempfile.TemporaryDirectory(prefix='mtk-ba-wtbl-') as td:
 p=Path(td);cpp=p/'test.cpp';cpp.write_text(pre+wire+constants+'\n'+real+post)
 subprocess.run(['clang++','-std=c++14','-fsanitize=undefined','-fno-sanitize-recover=all','-g',str(cpp),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
