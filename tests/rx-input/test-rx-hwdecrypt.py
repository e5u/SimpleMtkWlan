#!/usr/bin/env python3
"""Actual hwdecrypt + key lookup/CCMP/TKIP readers; verify error ownership."""
from pathlib import Path
import re,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[2]
D=ROOT/'mtk80211/openbsd/net80211'
def function(filename,name):
 s=(D/filename).read_text();m=re.search(r'(?m)^(?:struct ieee80211_key \*|mbuf_t|int)\n'+name+r'\([^;]+?\)\s*\{',s);assert m,name
 start=m.start();p=s.index('{',start)+1;depth=1
 while depth:depth+=(s[p]=='{')-(s[p]=='}');p+=1
 return s[start:p]
pre=r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <vector>
using namespace std;
using u_int8_t=uint8_t;using u_int16_t=uint16_t;using u_int64_t=uint64_t;using caddr_t=char*;
struct ieee80211_frame {uint8_t i_fc[2],dur[2],i_addr1[6],a2[6],a3[6],seq[2];};
struct Packet{vector<uint8_t>b;size_t offset=0,len=0,pklen=0;Packet*next=nullptr;};
using mbuf_t=Packet*;
static set<mbuf_t>live;static unsigned freed=0;
static mbuf_t packet(vector<uint8_t>b){auto*m=new Packet;m->b=b;m->len=m->pklen=b.size();assert(live.insert(m).second);return m;}
static void mbuf_freem(mbuf_t m){while(m){assert(live.erase(m)==1);auto*n=m->next;delete m;m=n;freed++;}}
#define mtod(m,t) ((t)((m)->b.data()+(m)->offset))
static size_t mbuf_len(mbuf_t m){return m->len;}
static size_t mbuf_pkthdr_len(mbuf_t m){return m->pklen;}
static void mbuf_adj(mbuf_t m,int n){assert(n>=0&&(size_t)n<=m->len);m->offset+=n;m->len-=n;m->pklen-=n;}
#define IEEE80211_F_RSNON 1
#define IEEE80211_FC0_TYPE_MASK 0x0c
#define IEEE80211_FC0_TYPE_DATA 0x08
#define IEEE80211_FC0_TYPE_MGT 0x00
#define IEEE80211_FC1_PROTECTED 0x40
#define IEEE80211_CIPHER_USEGROUP 0
#define IEEE80211_CIPHER_CCMP 4
#define IEEE80211_CIPHER_TKIP 2
#define IEEE80211_RXI_HWDEC_SAME_PN 4
#define IEEE80211_CCMP_HDRLEN 8
#define IEEE80211_TKIP_HDRLEN 8
#define IEEE80211_WEP_EXTIV 0x20
#define IEEE80211_QOS_TID 15
#define IEEE80211_MMIE_LEN 18
#define IEEE80211_ELEMID_MMIE 76
#define IEEE80211_IS_MULTICAST(p) ((p)[0]&1)
#define LE_READ_2(p) ((uint16_t)(p)[0]|((uint16_t)(p)[1]<<8))
struct ieee80211_key {unsigned k_cipher=0;uint64_t k_rsc[16]={},k_mgmt_rsc=0;};
struct ieee80211_node {unsigned ni_rsncipher=4;ieee80211_key ni_pairwise_key;};
struct ieee80211com {unsigned ic_flags=IEEE80211_F_RSNON;ieee80211_key ic_nw_keys[6];struct{unsigned is_ccmp_replays=0,is_tkip_replays=0;}ic_stats;};
struct ieee80211_rxinfo {unsigned rxi_flags=0;};
static bool ieee80211_has_qos(const ieee80211_frame*w){return (w->i_fc[0]&0x8c)==0x88;}
static unsigned ieee80211_get_hdrlen(const ieee80211_frame*w){return 24+(ieee80211_has_qos(w)?2:0);}
static unsigned ieee80211_get_qos(const ieee80211_frame*w){return ((const uint8_t*)w)[24];}
'''
main=r'''
static vector<uint8_t>frame(unsigned cipher,uint64_t pn,unsigned tid=3,bool protected_bit=true,unsigned ivlen=8,bool ext=true,bool qos=true){unsigned h=qos?26:24;vector<uint8_t>v(h+ivlen+10,0);v[0]=qos?0x88:0x08;v[1]=2|(protected_bit?0x40:0);v[4]=2;if(qos)v[24]=tid;auto*p=v.data()+h;if(ivlen>=8){p[3]=ext?0x20:0;if(cipher==4){p[0]=pn;p[1]=pn>>8;}else{p[2]=pn;p[0]=pn>>8;}for(unsigned i=2;i<6;i++)p[i+2]=pn>>(i*8);}for(unsigned i=0;i<10;i++)v[h+ivlen+i]=0xa0+i;return v;}
static void rejected(ieee80211com&ic,ieee80211_node&ni,ieee80211_rxinfo&rxi,vector<uint8_t>v){auto*m=packet(v);unsigned f=freed;assert(!ieee80211_input_hwdecrypt(&ic,&ni,m,&rxi));assert(live.empty()&&freed==f+1);}
int main(){
 for(unsigned cipher:{4u,2u}){
  ieee80211com ic;ieee80211_node ni;ni.ni_pairwise_key.k_cipher=cipher;ieee80211_rxinfo rx;
  // Valid 48-bit PN/TSC, preserve payload, remove exactly IV, clear Protected.
  uint64_t pn=0x060504030201ULL;auto v=frame(cipher,pn);auto*m=packet(v);auto*out=ieee80211_input_hwdecrypt(&ic,&ni,m,&rx);assert(out==m&&live.size()==1);assert(ni.ni_pairwise_key.k_rsc[3]==pn);assert(!(mtod(out,uint8_t*)[1]&0x40));assert(out->pklen==v.size()-8);assert(!memcmp(mtod(out,uint8_t*)+26,v.data()+34,10));mbuf_freem(out);
  // Same and smaller counters fail, consuming original packet exactly once.
  rejected(ic,ni,rx,frame(cipher,pn));rejected(ic,ni,rx,frame(cipher,pn-1));assert((cipher==4?ic.ic_stats.is_ccmp_replays:ic.ic_stats.is_tkip_replays)==2);
  // SAME_PN allows equality only, never a lower counter.
  rx.rxi_flags=IEEE80211_RXI_HWDEC_SAME_PN;m=packet(frame(cipher,pn));assert(ieee80211_input_hwdecrypt(&ic,&ni,m,&rx)==m);mbuf_freem(m);rejected(ic,ni,rx,frame(cipher,pn-1));rx.rxi_flags=0;
  // Missing ExtIV and IV shorter than eight bytes do not advance PN.
  rejected(ic,ni,rx,frame(cipher,pn+1,3,true,8,false));auto shortiv=frame(cipher,pn+1);shortiv.resize(26+7);rejected(ic,ni,rx,shortiv);assert(ni.ni_pairwise_key.k_rsc[3]==pn);
  // Exact header+IV boundary is valid and yields a header-only result.
  v=frame(cipher,pn+1);v.resize(34);m=packet(v);assert(ieee80211_input_hwdecrypt(&ic,&ni,m,&rx)==m);assert(m->pklen==26);mbuf_freem(m);
  // Unprotected hardware-stripped path preserves bytes and counter.
  v=frame(cipher,pn+9,3,false,0);m=packet(v);assert(ieee80211_input_hwdecrypt(&ic,&ni,m,&rx)==m);assert(m->pklen==v.size()&&ni.ni_pairwise_key.k_rsc[3]==pn+1);mbuf_freem(m);
  // Non-QoS uses TID0 and cannot perturb TID3.
  v=frame(cipher,9,0,true,8,true,false);m=packet(v);assert(ieee80211_input_hwdecrypt(&ic,&ni,m,&rx)==m);assert(ni.ni_pairwise_key.k_rsc[0]==9&&m->pklen==v.size()-8);mbuf_freem(m);
 }
 // Real get_rxkey NULL: group-data IV absent, invalid/short MMIE and invalid key id.
 {ieee80211com ic;ic.ic_flags=0;ieee80211_node ni;ieee80211_rxinfo rx;auto v=frame(4,1);v.resize(26+3);rejected(ic,ni,rx,v);v=vector<uint8_t>(24,0);v[4]=1;rejected(ic,ni,rx,v);v.resize(42,0);rejected(ic,ni,rx,v);v[24]=IEEE80211_ELEMID_MMIE;v[25]=16;v[26]=6;rejected(ic,ni,rx,v);}
 // Proper group key lookup still succeeds; unsupported cipher retains ownership.
 {ieee80211com ic;ic.ic_flags=0;ic.ic_nw_keys[2].k_cipher=4;ieee80211_node ni;ieee80211_rxinfo rx;auto v=frame(4,7);v[29]|=0x80;auto*m=packet(v);assert(ieee80211_input_hwdecrypt(&ic,&ni,m,&rx)==m);assert(ic.ic_nw_keys[2].k_rsc[3]==7);mbuf_freem(m);ni.ni_pairwise_key.k_cipher=99;ic.ic_flags=1;v=frame(4,1);m=packet(v);assert(ieee80211_input_hwdecrypt(&ic,&ni,m,&rx)==m&&m->pklen==v.size());mbuf_freem(m);}
 // Rejection consumes an entire payload chain; successful header/IV stays contiguous.
 {ieee80211com ic;ieee80211_node ni;ni.ni_pairwise_key.k_cipher=4;ni.ni_pairwise_key.k_rsc[3]=5;ieee80211_rxinfo rx;auto v=frame(4,5);auto*m=packet(vector<uint8_t>(v.begin(),v.begin()+34));m->next=packet(vector<uint8_t>(v.begin()+34,v.end()));m->pklen=v.size();unsigned f=freed;assert(!ieee80211_input_hwdecrypt(&ic,&ni,m,&rx));assert(live.empty()&&freed==f+2);}
 assert(live.empty());puts("PASS actual hwdecrypt/key lookup/CCMP/TKIP readers: success and exact 8-byte strip, replay/no-key/short-IV/ExtIV failures consume input, same-PN flag, TID/group lookup and chained rejection");
}
'''
code=pre+'\n'+function('ieee80211_crypto.c','ieee80211_get_rxkey')+'\n'+function('ieee80211_crypto_ccmp.c','ieee80211_ccmp_get_pn')+'\n'+function('ieee80211_crypto_tkip.c','ieee80211_tkip_get_tsc')+'\n'+function('ieee80211_input.c','ieee80211_input_hwdecrypt')+'\n'+main
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.cpp').write_text(code)
 subprocess.run(['clang++','-std=c++14','-fsanitize=undefined','-fno-sanitize-recover=all','-g',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
