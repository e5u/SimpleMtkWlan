#!/usr/bin/env python3
"""Exercise real passive STA result logging and P-RXV-derived RX rates.
The derived PHY rates are observations of received frames, not TX measurement
or TCP throughput. UBSan validates the actual source against small host stubs.
"""
from pathlib import Path
import re, subprocess, tempfile
root=Path(__file__).resolve().parents[2]
s=(root/'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text()
h=(root/'SimpleMtkWlan/hal_mwx/if_mwxreg.h').read_text()
def function(name):
 m=re.search(r'(?m)^static void\n'+re.escape(name)+r'\([^;]*?\)\s*\n\{',s)
 assert m,'Missing actual source function: '+name
 return s[m.start():s.index('\n}',m.end())+2]+'\n'
event=re.search(r'(?m)^struct mt7921_mcu_uni_event \{.*?^\} __packed;',h,re.S|re.M)
assert event,'Missing actual unified result wire structure'
constants='\n'.join(l for l in h.splitlines() if re.match(r'#define\s+(MCU_CMD_FIELD_ID_MASK|MCU_UNI_CMD_STA_REC_UPDATE|MCU_UNI_EVENT_RESULT)\b',l))
rate_start=s.rfind('/*',0,s.index('#define MWX_PRXV_TX_RATE'))
rate_end=s.index('\nextern uint32_t ieee80211_bar_rx_count;',rate_start)
rate=s[rate_start:rate_end]
assert 'static const uint16_t mwx_vht_rate[4][10]' in rate
assert 'Last unicast RX rate' in rate, 'Keep RX-derived observation provenance explicit'
assert 'mwx_rx_rate_account(uint32_t v0)' in rate
pre=r'''
#include <cassert>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <climits>
#include <string>
#include <vector>
#define __packed __attribute__((packed))
#ifndef le32toh
#define le32toh(x) uint32_t(x)
#endif
struct mwx_softc { uint64_t sentinel=0x0123456789abcdefULL; };
enum { MT_PHY_TYPE_CCK=0,MT_PHY_TYPE_OFDM=1,MT_PHY_TYPE_HT=2,MT_PHY_TYPE_HT_GF=3,MT_PHY_TYPE_VHT=4,MT_PHY_TYPE_HE_SU=8,MT_PHY_TYPE_HE_EXT_SU=9,MT_PHY_TYPE_HE_TB=10,MT_PHY_TYPE_HE_MU=11 };
struct ieee80211_he_rateset{uint32_t nrates;uint32_t rates[12];int num_ss;};
static const ieee80211_he_rateset ieee80211_std_ratesets_11ax[8]={};
struct mbuf { uint8_t *data; size_t len; };
static size_t mbuf_len(mbuf *m){return m->len;}
#define mtod(m,t) reinterpret_cast<t>((m)->data)
static std::vector<std::string> logs;
static void capture_log(const char *fmt,...){char message[256];va_list args;va_start(args,fmt);int n=vsnprintf(message,sizeof(message),fmt,args);va_end(args);assert(n>=0&&size_t(n)<sizeof(message));logs.emplace_back(message);}
#define MWX_DEV_LOG(sc,fmt,...) capture_log(fmt,##__VA_ARGS__)
'''
post=r'''
static_assert(sizeof(mt7921_mcu_uni_event)==8,"unified result wire size");
static_assert(offsetof(mt7921_mcu_uni_event,cid)==0,"result CID wire offset");
static_assert(offsetof(mt7921_mcu_uni_event,status)==4,"result status wire offset");
static void status_tests(){
 assert(MCU_UNI_EVENT_RESULT==1&&MCU_UNI_CMD_STA_REC_UPDATE==0x20003&&MCU_CMD_FIELD_ID_MASK==0xff);
 mwx_softc sc;mbuf no_data{nullptr,0};
 // No read from absent payload for any truncated length.
 for(size_t len=0;len<8;++len){no_data.len=len;mwx_mcu_trace_sta_status(&sc,1,9,&no_data);assert(logs.empty());}
 // Wrong event identifier must return before touching even an inaccessible payload.
 no_data.len=8;for(uint8_t eid:{uint8_t(0),uint8_t(2),uint8_t(255)}){mwx_mcu_trace_sta_status(&sc,eid,9,&no_data);assert(logs.empty());}
 alignas(8) uint8_t raw[12]={2,0xa5,0x5a,0xff,0x78,0x56,0x34,0x12,0xff,0xff,0xff,0xff};mbuf m{raw,8};
 uint8_t before[12];memcpy(before,raw,sizeof(raw));
 mwx_mcu_trace_sta_status(&sc,1,9,&m);assert(logs.empty());assert(!memcmp(before,raw,sizeof(raw)));
 // Success and failure are both observable without consuming/mutating the event.
 raw[0]=3;memset(raw+4,0,4);mwx_mcu_trace_sta_status(&sc,1,9,&m);
 assert(logs.size()==1&&logs.back()=="STA_REC firmware result seq=9 status=0\n");
 raw[4]=0x78;raw[5]=0x56;raw[6]=0x34;raw[7]=0x12;memcpy(before,raw,sizeof(raw));m.len=12;
 mwx_mcu_trace_sta_status(&sc,1,15,&m);
 assert(logs.size()==2&&logs.back()=="STA_REC firmware result seq=15 status=305419896\n");
 assert(m.data==raw&&m.len==12&&!memcmp(before,raw,sizeof(raw))&&sc.sentinel==0x0123456789abcdefULL);
 // Full unsigned firmware status must not print as a negative signed value.
 memset(raw+4,0xff,4);mwx_mcu_trace_sta_status(&sc,1,0,&m);
 assert(logs.size()==3&&logs.back()=="STA_REC firmware result seq=0 status=4294967295\n");
}
static uint32_t descriptor(uint8_t bw,bool short_gi,uint8_t nss=2,uint8_t mcs=9,uint8_t mode=4){
 // Independent P-RXV layout: rate[6:0], NSTS[9:7], BW[14:12], GI[16:15], mode[27:24].
 assert(bw<4&&nss>=1&&nss<=8&&mcs<128&&mode<16);
 return uint32_t(mcs)|(uint32_t(nss-1)<<7)|(uint32_t(bw)<<12)|(uint32_t(short_gi)<<15)|(uint32_t(mode)<<24);
}
static void rate_tests(){
 const uint32_t d80=0x04002089,d160=0x04003089;
 assert(descriptor(2,false)==d80&&descriptor(3,false)==d160);
 const uint32_t descs[]={d80,d80|0x8000u,d160,d160|0x8000u};
 const uint32_t expected[]={780000,866666,1560000,1733333};
 for(unsigned i=0;i<4;++i){mwx_rx_rate_account(descs[i]);assert(mwx_rxr_last_kbps==expected[i]&&mwx_rxr_last_mcs==9);}
 assert(mwx_rxr_total==4&&mwx_rxr_mode[4]==4&&mwx_rxr_bw[2]==2&&mwx_rxr_bw[3]==2);
 assert(mwx_rxr_nss[1]==4&&mwx_rxr_mcs[9]==4&&mwx_rxr_sgi==2&&mwx_rxr_stbc==0&&mwx_rxr_ldpc==0);
 // Largest representable VHT NSTS ensures the multiplication cannot narrow to 16-bit or overflow signed arithmetic.
 mwx_rx_rate_account(descriptor(3,true,8));assert(mwx_rxr_last_kbps==6933333);
 assert(mwx_rxr_last_kbps==uint64_t(780000)*8*10/9);
 // Independent long-GI MCS9 rate expectations for every supported bandwidth and NSS.
 const uint32_t one_ss_lgi[]={86700,180000,390000,780000};
 for(uint8_t bw=0;bw<4;++bw)for(uint8_t nss=1;nss<=8;++nss)for(bool gi:{false,true}){
  const uint64_t lgi=uint64_t(one_ss_lgi[bw])*nss;const uint64_t want=gi?lgi*10/9:lgi;assert(want<UINT32_MAX);
  mwx_rx_rate_account(descriptor(bw,gi,nss));assert(mwx_rxr_last_kbps==want&&mwx_rxr_last_mcs==9);
 }
 // HT index15 is two streams MCS7, not an extra NSTS count.
 mwx_rx_rate_account(descriptor(1,false,1,15,2));assert(mwx_rxr_last_mcs==15&&mwx_rxr_last_kbps==270000);
 // Unsupported encoding or MCS records a histogram entry without manufacturing a new PHY rate.
 uint32_t previous=mwx_rxr_last_kbps;int mcs=mwx_rxr_last_mcs;
 mwx_rx_rate_account(descriptor(2,false,2,10));assert(mwx_rxr_last_kbps==previous&&mwx_rxr_last_mcs==mcs);
 mwx_rx_rate_account(descriptor(2,false,2,11,8));assert(mwx_rxr_last_kbps==previous&&mwx_rxr_last_mcs==mcs);
 mwx_rx_rate_account(UINT32_MAX);assert(mwx_rxr_last_kbps==previous&&mwx_rxr_last_mcs==mcs);
 // LDPC and STBC observability is separate from the rate observation.
 auto ldpc_before=mwx_rxr_ldpc,stbc_before=mwx_rxr_stbc;
 mwx_rx_rate_account(d80|(1u<<11)|(1u<<22));assert(mwx_rxr_ldpc==ldpc_before+1&&mwx_rxr_stbc==stbc_before+1);
}
int main(){const uint16_t little=1;assert(*reinterpret_cast<const uint8_t*>(&little)==1);status_tests();rate_tests();puts("PASS actual passive STA status logger: bounds/eid/cid/success/error/seq; real P-RXV RX rate accounting: 80/160MHz 2SS MCS9 LGI/SGI, 160 SGI=1733333kbps, maximum NSS and invalid descriptors; UBSan. RX-derived PHY observation, not measured TX or TCP throughput.");}
'''
with tempfile.TemporaryDirectory(prefix='mtk-status-rate-') as td:
 p=Path(td);cpp=p/'test.cpp';cpp.write_text(pre+event.group()+'\n'+constants+'\n'+function('mwx_mcu_trace_sta_status')+'\n'+rate+'\n'+post)
 subprocess.run(['clang++','-std=c++14','-fsanitize=undefined','-fno-sanitize-recover=all','-g',str(cpp),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
