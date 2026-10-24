#!/usr/bin/env python3
"""Actual A-MSDU functions with Apple's actual m_split0/KPI code, UBSan.
Packet storage, allocation and delivery use host shims; no kext is loaded.
"""
from pathlib import Path
import os, subprocess, tempfile
ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / 'mtk80211/openbsd/net80211/ieee80211_input.c').read_text()
def extract(text, name, rettype):
    start = text.index(rettype + '\n' + name + '(')
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]
functions = '\n'.join(extract(SRC, n, t) for n, t in [
    ('ieee80211_amsdu_decap_validate', 'int'), ('ieee80211_amsdu_decap', 'void')])
xnu = (Path(__file__).parent/'fixtures/apple-xnu-mbuf-split.inc').read_text()
pre = r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <deque>
#include <memory>
#include <unordered_set>
#include <vector>
#include <sys/types.h>
#include <arpa/inet.h>
using bytes=std::vector<uint8_t>;
#define M_PKTHDR 1
#define M_EXT 2
#define MHLEN 2048
#define MLEN 2048
#define MBUF_DONTWAIT 0
#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14
#define LLC_SNAPFRAMELEN 8
#define LLC_SNAP_LSAP 0xaa
#define LLC_UI 3
#define IEEE80211_M_STA 1
#define IEEE80211_M_HOSTAP 2
#define IEEE80211_IS_MULTICAST(p) ((p)[0]&1)
#define ETHER_IS_EQ(a,b) (!memcmp(a,b,6))
#define MBUF_LIST_INITIALIZER() {}
#define DPRINTF(x) ((void)0)
#define VERIFY(x) assert(x)
#define mtod(m,t) reinterpret_cast<t>((m)->m_data)
struct mbuf {
    unsigned m_len=0;
    int m_flags=M_PKTHDR,m_type=1;
    mbuf *m_next=nullptr;
    struct {void *rcvif=nullptr;unsigned len=0;}m_pkthdr;
    std::shared_ptr<bytes> m_ext;
    alignas(8) uint8_t internal[MLEN]={};
    uint8_t *m_data=internal;
};
using mbuf_t=mbuf*;using mbuf_how_t=int;using errno_t=int;
std::unordered_set<mbuf*>live;
int split_allocations=0,fail_split_allocation=0,pullup_calls=0,fail_pullup_call=0;
int delivered=0;
mbuf *allocate(){auto*m=new mbuf;assert(live.insert(m).second);return m;}
mbuf *split_allocate(){++split_allocations;return split_allocations==fail_split_allocation?nullptr:allocate();}
#define _MGETHDR(n,w,t) ((n)=split_allocate())
#define _MGET(n,w,t) ((n)=split_allocate())
#define MH_ALIGN(n,l) ((void)0)
#define M_ALIGN(n,l) ((void)0)
void m_incref(mbuf*){}
void *m_free(mbuf*m){assert(live.erase(m)==1);delete m;return nullptr;}
void mbuf_freem(mbuf*m){while(m){mbuf*n=m->m_next;m_free(m);m=n;}}
mbuf *m_split(mbuf*,int,int);
'''
postshim = r'''
struct __attribute__((packed)) ether_header {uint8_t ether_dhost[6],ether_shost[6];uint16_t ether_type;};
struct __attribute__((packed)) llc {uint8_t llc_dsap,llc_ssap,llc_control;struct __attribute__((packed)){uint8_t org_code[3];uint16_t ether_type;}llc_snap;};
struct ieee80211_frame {uint8_t fc[2],duration[2],i_addr1[6],remainder[14];};
struct ieee80211com {int ic_opmode=IEEE80211_M_STA;uint8_t ic_myaddr[6]={2,1,2,3,4,5};struct{unsigned is_rx_decap=0;}ic_stats;};
struct ieee80211_node {uint8_t ni_macaddr[6]={2,6,7,8,9,10};};
struct mbuf_list {std::deque<mbuf*>items;};
void ml_enqueue(mbuf_list*l,mbuf*m){assert(m&&live.count(m));l->items.push_back(m);}
mbuf *ml_dequeue(mbuf_list*l){if(l->items.empty())return nullptr;auto*m=l->items.front();l->items.pop_front();return m;}
void ml_purge(mbuf_list*l){while(auto*m=ml_dequeue(l))mbuf_freem(m);}
unsigned mbuf_pkthdr_len(mbuf*m){assert(m&&live.count(m));return m->m_pkthdr.len;}
bytes flatten(mbuf*m){bytes b;for(;m;m=m->m_next)b.insert(b.end(),m->m_data,m->m_data+m->m_len);return b;}
void mbuf_adj(mbuf*m,unsigned n){assert(m&&live.count(m));n=std::min(n,m->m_pkthdr.len);m->m_pkthdr.len-=n;for(;m&&n;m=m->m_next){auto k=std::min(n,m->m_len);m->m_data+=k;m->m_len-=k;n-=k;}}
mbuf *packet(const bytes &b){auto*m=allocate();m->m_ext=std::make_shared<bytes>(b);m->m_data=m->m_ext->data();m->m_flags|=M_EXT;m->m_len=m->m_pkthdr.len=b.size();return m;}
errno_t mbuf_pullup(mbuf_t *m,size_t n){++pullup_calls;if(pullup_calls==fail_pullup_call||mbuf_pkthdr_len(*m)<n){mbuf_freem(*m);*m=nullptr;return ENOMEM;}if((*m)->m_len>=n)return 0;auto b=flatten(*m);mbuf_freem(*m);*m=packet(b);return 0;}
void ieee80211_enqueue_data(ieee80211com*,mbuf*m,ieee80211_node*,int,mbuf_list*l){++delivered;ml_enqueue(l,m);}
'''
tests = r'''
void reset(){assert(live.empty());split_allocations=fail_split_allocation=pullup_calls=fail_pullup_call=delivered=0;}
bytes subframe(unsigned payload,bool snap=true,bool valid=true){bytes b(14+8+payload);uint8_t dst[]={2,1,2,3,4,5},src[]={2,6,7,8,9,10};memcpy(b.data(),dst,6);memcpy(b.data()+6,src,6);if(!valid)b[5]^=1;uint16_t len=htons(8+payload);memcpy(b.data()+12,&len,2);uint8_t ll[]={0xaa,0xaa,3,0,0,0,8,0};memcpy(b.data()+14,ll,8);if(!snap)b[14]=0x42;for(unsigned i=0;i<payload;i++)b[22+i]=uint8_t(0x40+i);return b;}
bytes aggregate(const std::vector<bytes>&s){bytes b(24);for(size_t i=0;i<s.size();i++){b.insert(b.end(),s[i].begin(),s[i].end());if(i+1<s.size())while((b.size()-24)&3)b.push_back(0);}return b;}
bytes output(const bytes&s,bool snap){bytes b=s;if(snap){b.erase(b.begin()+14,b.begin()+22);b[12]=8;b[13]=0;}return b;}
void run(const bytes&b,const std::vector<bytes>&want,bool failure=false,unsigned splitfail=0,unsigned pullfail=0,bool chain=false){
 reset();ieee80211com ic{};ieee80211_node ni{};mbuf_list out{};auto*m=packet(b);
 if(chain&&b.size()>25){auto*n=packet(bytes(b.begin()+25,b.end()));m->m_len=25;m->m_next=n;n->m_flags&=~M_PKTHDR;}
 fail_split_allocation=splitfail;fail_pullup_call=pullfail;
 ieee80211_amsdu_decap(&ic,m,&ni,24,&out);
 assert(ic.ic_stats.is_rx_decap==(failure?1u:0u));assert(out.items.size()==want.size());assert(delivered==int(want.size()));
 for(auto&w:want){auto*n=ml_dequeue(&out);if(flatten(n)!=w){auto actual=flatten(n);fprintf(stderr,"mismatch chain=%d input=%zu got=%zu want=%zu split=%d\n",chain,b.size(),actual.size(),w.size(),split_allocations);for(auto v:actual)fprintf(stderr,"%02x",v);fprintf(stderr,"\n");for(auto v:w)fprintf(stderr,"%02x",v);fprintf(stderr,"\n");abort();}mbuf_freem(n);}assert(live.empty());
}
int main(){
 // Apple's actual m_split0 and mbuf_split, including end-of-packet.
 reset();auto*m=packet(bytes(30,0x5a));mbuf*n=reinterpret_cast<mbuf*>(uintptr_t(1));
 assert(mbuf_split(m,30,0,&n)==0&&n&&n->m_pkthdr.len==0&&n->m_len==0);assert(m->m_pkthdr.len==30);mbuf_freem(n);mbuf_freem(m);
 reset();m=packet(bytes(30,0x5a));n=reinterpret_cast<mbuf*>(uintptr_t(1));fail_split_allocation=1;assert(mbuf_split(m,30,0,&n)==ENOMEM&&n==nullptr&&m->m_pkthdr.len==30);mbuf_freem(m);
 reset();m=packet(bytes(30,0x5a));n=nullptr;assert(mbuf_split(m,13,0,&n)==0&&n&&n->m_pkthdr.len==17&&m->m_pkthdr.len==13);mbuf_freem(n);mbuf_freem(m);
 for(unsigned payload=0;payload<64;payload++)for(bool snap:{false,true}){
  auto a=subframe(payload,snap),b=subframe(63-payload,snap),c=subframe(payload/2,snap);
  run(aggregate({a}),{output(a,snap)});assert(split_allocations==0);
  run(aggregate({a,b,c}),{output(a,snap),output(b,snap),output(c,snap)});assert(split_allocations==2);
  run(aggregate({a,b,c}),{output(a,snap),output(b,snap),output(c,snap)},false,0,0,true);
 }
 auto a=subframe(13),b=subframe(22),c=subframe(3);
 run(aggregate({a,b,c}),{},true,1);run(aggregate({a,b,c}),{},true,2);
 run(aggregate({a,subframe(22,true,false),c}),{},true);
 run(aggregate({a}),{output(a,true)},false,1);assert(split_allocations==0);
 run(aggregate({a,b,c}),{},true,0,1);run(aggregate({a,b,c}),{},true,0,2);
 auto bad=aggregate({a,b});for(unsigned cut=1;cut<unsigned(b.size());cut++)run(bytes(bad.begin(),bad.end()-cut),{},true);
 for(unsigned pad=1;pad<=3;pad++){auto x=aggregate({a});x.insert(x.end(),pad,0);run(x,{},true);}
 auto invalidlen=subframe(3);invalidlen[12]=0;invalidlen[13]=7;run(aggregate({a,invalidlen}),{},true);
 auto oversize=subframe(3);oversize[12]=0xff;oversize[13]=0xff;run(aggregate({oversize}),{},true);
 auto forged=subframe(3);uint8_t llmac[]={0xaa,0xaa,3,0,0,0};memcpy(forged.data(),llmac,6);run(aggregate({a,forged,c}),{},true);
 run(bytes(24),{},true);for(unsigned tail=1;tail<22;tail++){auto x=aggregate({a});while((x.size()-24)&3)x.push_back(0);x.insert(x.end(),tail,0);run(x,{},true);}
 puts("PASS actual A-MSDU decap/validation: XNU split exact-end success+ENOMEM, 0..63-byte payloads, all padding cases, SNAP/non-SNAP, chained input, final subframe without allocation, split/pullup fault injection, invalid-address tail ownership, truncation atomicity and forged LLC destination (UBSan).");
}
'''
with tempfile.TemporaryDirectory(prefix='mtk-amsdu-decap-') as tmp:
    cpp,binary=Path(tmp)/'test.cpp',Path(tmp)/'test'
    cpp.write_text(pre+xnu+postshim+functions+tests)
    subprocess.run(['clang++','-std=c++14','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all',str(cpp),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1:print_stacktrace=1'})
