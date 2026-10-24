#!/usr/bin/env python3
"""Run the production RX A-MSDU helper with chained mbufs and fault injection."""
from pathlib import Path
import subprocess, tempfile
root=Path(__file__).resolve().parents[2]
helper=(root/'SimpleMtkWlan/hal_mwx/RxAmsduReassembly.hpp').read_text()
pre=r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>
#include <set>
using namespace std;
struct ieee80211_rxinfo {uint32_t rxi_flags=0,rxi_tstamp=0;int rxi_rssi=0;uint8_t rxi_chan=0;};
struct Packet {vector<uint8_t> data;size_t off=0,len=0,pklen=0;Packet*next=nullptr,*nextpkt=nullptr;};
using mbuf_t=Packet*;
static set<mbuf_t> live;
static unsigned allocs=0,copies=0,fail_alloc=0,fail_copy=0;
static bool undersized=false,multichunk=false,fail_setdata=false;
#define MBUF_DONTWAIT 0
static mbuf_t makebuf(const vector<uint8_t>&v){auto*m=new Packet;m->data=v;m->len=m->pklen=v.size();assert(live.insert(m).second);return m;}
static int mbuf_allocpacket(int,size_t len,uint32_t *n,mbuf_t*out){assert(*n==1);++allocs;*out=nullptr;if(allocs==fail_alloc)return ENOMEM;*out=makebuf(vector<uint8_t>(undersized?len-1:len));if(multichunk)(*out)->next=makebuf({});return 0;}
static void mbuf_freem(mbuf_t m){while(m){assert(live.erase(m)==1);auto*n=m->next;delete m;m=n;}}
static mbuf_t mbuf_next(mbuf_t m){return m->next;}
static mbuf_t mbuf_nextpkt(mbuf_t m){return m->nextpkt;}
static void* mbuf_data(mbuf_t m){return m->data.data()+m->off;}
static size_t mbuf_maxlen(mbuf_t m){return m->data.size();}
static size_t mbuf_len(mbuf_t m){return m->len;}
static size_t mbuf_trailingspace(mbuf_t m){return m->data.size()-m->off-m->len;}
static int mbuf_setdata(mbuf_t m,void*p,size_t n){if(fail_setdata)return EINVAL;auto*d=(uint8_t*)p;auto*b=m->data.data();if(d<b||d>b+m->data.size()||n>m->data.size()-(d-b))return EINVAL;m->off=d-b;m->len=n;return 0;}
static size_t mbuf_pkthdr_len(mbuf_t m){return m->pklen;}
static void mbuf_setlen(mbuf_t m,size_t n){assert(n<=m->data.size()-m->off);m->len=n;}
static void mbuf_pkthdr_setlen(mbuf_t m,size_t n){m->pklen=n;}
static int mbuf_copydata(mbuf_t m,size_t off,size_t len,void*dst){if(++copies==fail_copy)return EINVAL;auto*d=(uint8_t*)dst;while(m&&off>=m->len){off-=m->len;m=m->next;}while(len&&m){auto n=min(len,m->len-off);memcpy(d,m->data.data()+m->off+off,n);d+=n;len-=n;off=0;m=m->next;}return len?EINVAL:0;}
'''
post=r'''
static MtkRxAmsduMeta meta(unsigned tid=0,unsigned fmt=3,unsigned seq=0){MtkRxAmsduMeta a{};a.epoch=1;a.wcid=1;a.seqctl=seq<<4;a.tid=tid;a.format=fmt;a.hdrlen=26;a.protected_frame=true;a.hwdec=true;a.cipher=4;a.pn_valid=true;a.pn[0]=42;a.rxi.rxi_rssi=-37;return a;}
static vector<uint8_t> bytes(MtkRxAmsduMeta a,size_t payload=8,unsigned id=1,unsigned terminal=0){vector<uint8_t>v(a.hdrlen+14+payload+terminal,0);v[0]=0x88;v[1]=2|(a.protected_frame?0x40:0)|(a.hdrlen==30?0x80:0);for(unsigned i=0;i<18;i++)v[4+i]=i+1;v[22]=a.seqctl&255;v[23]=a.seqctl>>8;v[24]=0x80|a.tid;memcpy(v.data()+a.hdrlen,v.data()+4,6);for(unsigned i=0;i<6;i++)v[a.hdrlen+6+i]=0x20+i;v[a.hdrlen+12]=payload>>8;v[a.hdrlen+13]=payload;for(unsigned i=0;i<payload;i++)v[a.hdrlen+14+i]=id;return v;}
static mbuf_t packet(const vector<uint8_t>&v,unsigned split=0){if(!split||split>=v.size())return makebuf(v);auto*m=makebuf(vector<uint8_t>(v.begin(),v.begin()+split));m->next=makebuf(vector<uint8_t>(v.begin()+split,v.end()));m->pklen=v.size();return m;}
static mbuf_t feed(MtkRxAmsduState&s,MtkRxAmsduMeta a,unsigned payload,unsigned id,uint64_t now,unsigned terminal=0,unsigned split=0,MtkRxAmsduMeta*out=nullptr){return mtkRxAmsduFeed(s,packet(bytes(a,payload,id,terminal),split),a,now,out);}
static void clean(MtkRxAmsduState&s){mtkRxAmsduPurge(s);assert(s.stats.pending==0);assert(live.empty());fail_alloc=fail_copy=0;undersized=multichunk=fail_setdata=false;}
static void verify(mbuf_t m,const vector<vector<uint8_t>>&parts,unsigned hdrlen){assert(m);assert(m->off==(((uint8_t*)mbuf_data(m))[1]&0x40?8u:0u));size_t off=hdrlen;for(unsigned i=0;i<parts.size();i++){if(i){unsigned pad=(4-(parts[i-1].size()&3))&3;for(unsigned p=0;p<pad;p++)assert(((uint8_t*)mbuf_data(m))[off++]==0);}assert(memcmp((uint8_t*)mbuf_data(m)+off,parts[i].data(),parts[i].size())==0);off+=parts[i].size();}assert(m->len==off&&m->pklen==off);mbuf_freem(m);}
static vector<uint8_t>body(MtkRxAmsduMeta a,unsigned payload,unsigned id){auto b=bytes(a,payload,id);return vector<uint8_t>(b.begin()+a.hdrlen,b.end());}
int main(){
 // Every inter-subframe padding, chain boundary, and retained first metadata.
 for(unsigned p=8;p<12;p++)for(unsigned split: {0u,1u,13u,25u,27u,39u}){
  MtkRxAmsduState s{};auto a=meta();MtkRxAmsduMeta first{};a.hdrlen=(split&1)?30:26;
  unsigned pad=(4-((14+p)&3))&3;assert(!feed(s,a,p,1,1,pad,split));assert(s.stats.pending==1);
  auto b=a;b.format=2;b.rxi.rxi_rssi=-90;auto v=bytes(b,11,2);v[2]=45;v[3]=9;v[1]^=8;
  assert(!mtkRxAmsduFeed(s,packet(v,split),b,2,&first));b.format=1;
  auto m=feed(s,b,12,3,3,0,split,&first);assert(first.rxi.rxi_rssi==-37);assert(first.format==3);assert(s.stats.pending==0);
  verify(m,{body(a,p,1),body(a,11,2),body(a,12,3)},a.hdrlen);assert(s.stats.completed==1&&s.stats.subframes==3);clean(s);
 }
 // Linux singleton-LAST behavior, including open network and optional tail pad.
 for(unsigned open=0;open<2;open++){MtkRxAmsduState s{};auto a=meta(0,1);if(open){a.protected_frame=a.hwdec=a.pn_valid=false;a.cipher=0;}auto m=feed(s,a,8,9,1,2,25);verify(m,{body(a,8,9)},26);assert(s.stats.singleton==1);clean(s);}
 // Every key field mismatch purges old and incoming groups, and blocks their tails.
 for(unsigned k=0;k<11;k++){MtkRxAmsduState s{};auto a=meta();assert(!feed(s,a,8,1,1));auto b=a;b.format=1;
  switch(k){case 0:b.epoch++;break;case 1:b.wcid++;break;case 2:b.seqctl+=16;break;case 3:b.queue++;break;case 4:b.key++;break;case 5:b.pn[0]++;break;case 6:b.pn[5]++;break;case 7:b.hdrlen=30;break;case 8:b.protected_frame=b.hwdec=b.pn_valid=false;b.cipher=0;break;case 9:b.cipher=3;break;case 10:b.pn_valid=false;break;}
  assert(!feed(s,b,8,2,2));assert(s.stats.pending==0&&s.stats.completed==0);a.format=1;assert(!feed(s,a,8,3,3));assert(!feed(s,b,8,4,4));clean(s);
 }
 // Header address/QoS invariants; duration and retry were explicitly allowed above.
 for(unsigned pos: {1u,4u,10u,16u,25u}){MtkRxAmsduState s{};auto a=meta();assert(!feed(s,a,8,1,0));a.format=1;auto v=bytes(a);v[pos]^=0x10;assert(!mtkRxAmsduFeed(s,packet(v),a,1,nullptr));assert(!s.stats.pending);clean(s);}
 // Orphan middle cannot be completed as a false singleton; timeout, purge and restart.
 {MtkRxAmsduState s{};auto a=meta(0,2);assert(!feed(s,a,8,1,0));a.format=1;assert(!feed(s,a,8,1,1));assert(s.stats.orphan==2);a.format=3;assert(!feed(s,a,8,1,2));a.format=1;verify(feed(s,a,8,2,3),{body(a,8,1),body(a,8,2)},26);clean(s);}
 {MtkRxAmsduState s{};auto a=meta();assert(!feed(s,a,8,1,10));mtkRxAmsduExpire(s,110);assert(s.stats.timeout==1&&!s.stats.pending);a.format=1;assert(!feed(s,a,8,2,111));a.format=3;assert(!feed(s,a,8,1,112));mtkRxAmsduPurge(s,0);a.format=1;assert(!feed(s,a,8,2,113));clean(s);}
 // Purge at a long-idle boundary still blocks a known tail on next activity.
 {MtkRxAmsduState s{};auto a=meta();assert(!feed(s,a,8,1,1));mtkRxAmsduPurge(s);a.format=1;assert(!feed(s,a,8,2,10000));assert(!s.stats.pending&&s.stats.orphan==1);clean(s);}
 // First replaces stale context, and repeating FIRST can restart the same key.
 {MtkRxAmsduState s{};auto a=meta();assert(!feed(s,a,8,1,0));assert(!feed(s,a,8,2,1));a.format=1;verify(feed(s,a,8,3,2),{body(a,8,2),body(a,8,3)},26);clean(s);}
 {MtkRxAmsduState s{};auto a=meta();assert(!feed(s,a,8,1,0));auto b=meta(0,3,1);assert(!feed(s,b,8,2,1));a.format=1;assert(!feed(s,a,8,1,2));b.format=1;verify(feed(s,b,8,3,3),{body(b,8,2),body(b,8,3)},26);clean(s);}
 // 16 interleaved TIDs; sequence wrap and queue isolation are explicit metadata.
 {MtkRxAmsduState s{};for(unsigned i=0;i<16;i++)assert(!feed(s,meta(i,3,4095),8,i,1));assert(s.stats.pending==16);for(unsigned i=0;i<16;i++)verify(feed(s,meta(i,1,4095),8,i,2),{body(meta(i),8,i),body(meta(i),8,i)},26);assert(s.stats.completed==16);for(unsigned i=0;i<16;i++)verify(feed(s,meta(i,1,0),8,i,3),{body(meta(i),8,i)},26);clean(s);}
 // Count and total-body bounds, exactly 3,839 bytes accepted, one more rejected.
 {MtkRxAmsduState s{};auto a=meta();for(unsigned i=0;i<64;i++){a.format=i?2:3;assert(!feed(s,a,8,i,i));}a.format=1;assert(!feed(s,a,8,1,64));assert(s.stats.invalid==1&&!s.stats.pending);clean(s);}
 {MtkRxAmsduState s{};auto a=meta();assert(!feed(s,a,1900,1,0));a.format=1;verify(feed(s,a,1909,2,1),{body(a,1900,1),body(a,1909,2)},26);clean(s);}
 {MtkRxAmsduState s{};auto a=meta();assert(!feed(s,a,1900,1,0));a.format=1;assert(!feed(s,a,1910,2,1));assert(s.stats.invalid==1);clean(s);}
 // Invalid length, truncation, forged LLC DA, short payload, extra tail, wrong seq/TID.
 for(unsigned k=0;k<11;k++){MtkRxAmsduState s{};auto a=meta(0,1);auto v=bytes(a);switch(k){case 0:v.resize(25);break;case 1:v.pop_back();break;case 2:v.insert(v.end(),4,0);break;case 3:v[26+12]=0xff;break;case 4:v[26+13]=7;break;case 5:v[24]=0;break;case 6:v[22]=1;break;case 7:v[24]^=1;break;case 8:for(unsigned j=0;j<6;j++)v[26+j]=v[4+j]=(uint8_t[]){0xaa,0xaa,3,0,0,0}[j];break;case 9:a.format=0;break;case 10:a.tid=16;break;}assert(!mtkRxAmsduFeed(s,packet(v),a,1,nullptr));assert(s.stats.invalid==1);clean(s);}
 // Allocation failure, unexpectedly short/noncontiguous output, metadata/body copy failures.
 for(unsigned k=0;k<3;k++){MtkRxAmsduState s{};auto a=meta();assert(!feed(s,a,8,1,0));a.format=1;if(k==0)fail_alloc=allocs+1;if(k==1)undersized=true;if(k==2)multichunk=true;assert(!feed(s,a,8,2,1));assert(s.stats.allocfail==1&&!s.stats.pending);clean(s);}
 for(unsigned k=1;k<=4;k++){MtkRxAmsduState s{};auto a=meta();assert(!feed(s,a,8,1,0));a.format=1;fail_copy=copies+k;assert(!feed(s,a,8,2,1));assert(s.stats.invalid==1&&!s.stats.pending);clean(s);}
 // Data-pointer adjustment failure must free both output and retained frames.
 {MtkRxAmsduState s{};auto a=meta();assert(!feed(s,a,8,1,0));a.format=1;fail_setdata=true;assert(!feed(s,a,8,2,1));assert(s.stats.allocfail==1&&!s.stats.pending);clean(s);}
 // Invalid header chains, end of epoch and teardown never leak ownership.
 {MtkRxAmsduState s{};auto a=meta();auto m=packet(bytes(a));m->pklen+=100;assert(!mtkRxAmsduFeed(s,m,a,0,nullptr));clean(s);}
 {MtkRxAmsduState s{};auto a=meta();assert(!feed(s,a,8,1,500));mtkRxAmsduExpire(s,499);assert(s.stats.timeout==1);clean(s);}
 assert(live.empty());puts("PASS production RX A-MSDU helper: padding/chains, ownership, 16 TIDs, boundaries, key/PN/header mismatches, timeout/tombstones, singleton and fault injection");
}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.cpp').write_text(pre+helper+post)
 subprocess.run(['clang++','-std=gnu++14','-fsanitize=undefined','-fno-sanitize-recover=all','-g',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
