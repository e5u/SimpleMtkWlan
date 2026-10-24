#!/usr/bin/env python3
"""Production metadata helpers, guard-page bounds and consuming mbuf fault tests."""
from pathlib import Path
import re, subprocess, tempfile
root = Path(__file__).resolve().parents[2]
header = root/'SimpleMtkWlan/hal_mwx/RxAmsduMetadata.hpp'
regs = (root/'SimpleMtkWlan/hal_mwx/if_mwxreg.h').read_text()
needed = sorted(set(re.findall(r'\bMT_RXD\w+', header.read_text())))
defs = []
for name in needed:
    found = re.search(r'^#define\s+'+name+r'\s+([^\n]+)', regs, re.M)
    assert found, name
    defs.append('#define '+name+' '+found.group(1))
pre = r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>
#include <sys/mman.h>
#include <unistd.h>
struct Packet {std::vector<uint8_t> storage;size_t off=0,len=0,pklen=0;bool shared=false;Packet* next=nullptr;uint8_t* guarded=nullptr;void* mapping=nullptr;};
using mbuf_t=Packet*;
static unsigned live=0,alloc_calls=0,copy_calls=0;
static int alloc_mode=0,fail_copy=0;
static bool fail_setdata=false;
constexpr int MBUF_DONTWAIT=0;
static mbuf_t packet(const std::vector<uint8_t>& data,size_t capacity=0){auto*m=new Packet;m->storage.resize(std::max(capacity,data.size()));std::copy(data.begin(),data.end(),m->storage.begin());m->len=m->pklen=data.size();++live;return m;}
static void mbuf_freem(mbuf_t m){while(m){auto*n=m->next;if(m->mapping)munmap(m->mapping,2*getpagesize());assert(live);--live;delete m;m=n;}}
static size_t mbuf_len(mbuf_t m){return m->len;}
static size_t mbuf_pkthdr_len(mbuf_t m){return m->pklen;}
static void* mbuf_data(mbuf_t m){return m->guarded?m->guarded+m->off:m->storage.data()+m->off;}
static mbuf_t mbuf_next(mbuf_t m){return m->next;}
static size_t mbuf_trailingspace(mbuf_t m){return m->storage.size()-m->off-m->len;}
static size_t mbuf_leadingspace(mbuf_t m){return m->off;}
static int mbuf_mclhasreference(mbuf_t m){return m->shared;}
static int mbuf_setdata(mbuf_t m,void*data,size_t len){if(fail_setdata)return EINVAL;auto*d=(uint8_t*)data;auto*base=m->storage.data();if(d<base||d>base+m->storage.size()||len>m->storage.size()-(d-base))return EINVAL;m->off=d-base;m->len=len;return 0;}
static void mbuf_adj(mbuf_t m,int n){assert(n>=0 && (size_t)n<=m->len);m->off+=n;m->len-=n;m->pklen-=n;}
static void mbuf_setlen(mbuf_t m,size_t n){assert(n<=m->storage.size()-m->off);m->len=n;}
static void mbuf_pkthdr_setlen(mbuf_t m,size_t n){m->pklen=n;}
static int mbuf_copydata(mbuf_t m,size_t off,size_t len,void* dest){if(++copy_calls==(unsigned)fail_copy)return EIO;uint8_t*d=(uint8_t*)dest;while(m&&off>=m->len){off-=m->len;m=m->next;}while(m&&len){size_t n=std::min(len,m->len-off);memcpy(d,(uint8_t*)mbuf_data(m)+off,n);d+=n;len-=n;off=0;m=m->next;}return len?EINVAL:0;}
static int mbuf_allocpacket(int,size_t n,unsigned int*chunks,mbuf_t*out){assert(*chunks==1);++alloc_calls;*out=nullptr;if(alloc_mode==1)return ENOMEM;*out=packet({},alloc_mode==3?n-1:n);if(alloc_mode==2)return ENOMEM;if(alloc_mode==4)(*out)->next=packet({0});return 0;}
static void put32(std::vector<uint8_t>& b,size_t o,uint32_t x){for(int i=0;i<4;++i)b[o+i]=(x>>(8*i))&255;}
static std::vector<uint8_t> frame(bool prot=true){std::vector<uint8_t> p(26+14+20);p[0]=0x88;p[1]=prot?0x42:2;for(int i=4;i<22;++i)p[i]=(uint8_t)i;p[22]=0x40;p[23]=0x12;p[24]=0x83;for(size_t i=26;i<p.size();++i)p[i]=(uint8_t)(i*3);return p;}
'''
main = r'''
static std::vector<uint8_t> descriptor(unsigned groups,unsigned pad=0,unsigned fmt=3,unsigned cipher=4){
 unsigned r1=7|(cipher<<16)|(2<<21);if(groups&1)r1|=MT_RXD1_NORMAL_GROUP_1;if(groups&2)r1|=MT_RXD1_NORMAL_GROUP_2;if(groups&4)r1|=MT_RXD1_NORMAL_GROUP_3;if(groups&8)r1|=MT_RXD1_NORMAL_GROUP_4;if(groups&16)r1|=MT_RXD1_NORMAL_GROUP_5;
 size_t off=24+((groups&8)?16:0),g1=off;off+=((groups&1)?16:0)+((groups&2)?8:0)+((groups&4)?8:0)+(((groups&20)==20)?72:0)+pad*2;
 auto p=frame(cipher!=0);std::vector<uint8_t>b(off+2+p.size());put32(b,4,r1);put32(b,8,pad<<14);put32(b,12,MT_RXD3_NORMAL_U2M);put32(b,16,fmt);if(groups&1)for(unsigned i=0;i<6;++i)b[g1+i]=(uint8_t)(i+1);std::copy(p.begin(),p.begin()+26,b.begin()+off);b[off+26]=0xcc;b[off+27]=0xdd;std::copy(p.begin()+26,p.end(),b.begin()+off+28);return b;
}
static mbuf_t guarded(const std::vector<uint8_t>& bytes,size_t n){auto*m=packet({});const size_t page=getpagesize();m->mapping=mmap(nullptr,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);assert(m->mapping!=MAP_FAILED);assert(mprotect((uint8_t*)m->mapping+page,page,PROT_NONE)==0);m->guarded=(uint8_t*)m->mapping+page-n;m->len=m->pklen=n;if(n)memcpy(m->guarded,bytes.data(),n);return m;}
int main(){
 MtkRxDescriptorMeta meta{};
 // Every optional-group combination and header-offset choice, every format.
 for(unsigned g=0;g<32;++g)for(unsigned p=0;p<4;++p)for(unsigned fmt=1;fmt<4;++fmt){
  auto b=descriptor(g,p,fmt);auto*m=packet(b);int rv=mtkRxAmsduReadDescriptor(m,meta);bool valid=(g&1)&&(!(g&16)||(g&4));assert(rv==(valid?1:-1));
  if(valid){assert(meta.wcid==7&&meta.key==2&&meta.cipher==4&&meta.format==fmt&&meta.hdrlen==26&&meta.seqctl==0x1240&&meta.tid==3&&meta.protected_frame&&meta.hwdec&&meta.pn_valid&&meta.unicast);for(int j=0;j<6;++j)assert(meta.pn[j]==j+1);}
  mbuf_freem(m);
 }
 // A guard page follows every available prefix; no descriptor/group/header OOB.
 for(unsigned g:{1u,9u,31u})for(unsigned p=0;p<4;++p){auto b=descriptor(g,p);for(size_t n=0;n<=b.size();++n){auto*m=guarded(b,n);int rv=mtkRxAmsduReadDescriptor(m,meta);if(n<b.size()-12)assert(rv<0);mbuf_freem(m);}}
 // Complete packet in a chain does not excuse an incomplete leading header.
 auto b=descriptor(31,3);auto*m=packet(b);assert(mtkRxAmsduReadDescriptor(m,meta)==1);auto good=meta;m->len=meta.hdr_gap+27;assert(mtkRxAmsduReadDescriptor(m,meta)<0);mbuf_freem(m);
 // Format zero does not impose A-MSDU security or optional group restrictions.
 b=descriptor(16,0,0,12);m=packet(b);assert(mtkRxAmsduReadDescriptor(m,meta)==0&&meta.format==0);mbuf_freem(m);
 // Errors, translated header, multicast and missing groups fail closed.
 for(unsigned word:{1u,2u,3u}){std::vector<uint32_t> bits;if(word==1)bits={MT_RXD1_NORMAL_BAND_IDX,MT_RXD1_NORMAL_ICV_ERR,MT_RXD1_NORMAL_FCS_ERR,MT_RXD1_NORMAL_TKIP_MIC_ERR,MT_RXD1_NORMAL_CM,MT_RXD1_NORMAL_CLM};if(word==2)bits={MT_RXD2_NORMAL_HDR_TRANS,MT_RXD2_NORMAL_AMSDU_ERR,MT_RXD2_NORMAL_MAX_LEN_ERROR,MT_RXD2_NORMAL_HDR_TRANS_ERROR,MT_RXD2_NORMAL_FRAG,MT_RXD2_NORMAL_NULL_FRAME,MT_RXD2_NORMAL_NDATA};if(word==3)bits={MT_RXD3_NORMAL_U2M};for(auto bit:bits){b=descriptor(1);auto v=mtkRxAmsduLe32(b.data()+word*4);put32(b,word*4,word==3?v&~bit:v|bit);m=packet(b);assert(mtkRxAmsduReadDescriptor(m,meta)<0);mbuf_freem(m);}}
 // QoS/FromDS/fragment/HT-Control/AMSDU flag checks.
 for(unsigned mode=0;mode<8;++mode){b=descriptor(1);const size_t o=40;switch(mode){case 0:b[o]=0x08;break;case 1:b[o]=0xc8;break;case 2:b[o+1]|=1;break;case 3:b[o+1]|=4;break;case 4:b[o+1]|=0x80;break;case 5:b[o+22]|=1;break;case 6:b[o+24]&=~0x80;break;case 7:b[o+4]|=1;break;}m=packet(b);assert(mtkRxAmsduReadDescriptor(m,meta)<0);mbuf_freem(m);}
 for(unsigned c=0;c<32;++c){b=descriptor(1,0,3,c);m=packet(b);assert(mtkRxAmsduReadDescriptor(m,meta)==((c==0||c==4)?1:-1));mbuf_freem(m);}
 b=descriptor(0,0,3,0);m=packet(b);assert(mtkRxAmsduReadDescriptor(m,meta)==1&&!meta.pn_valid&&!meta.hwdec);mbuf_freem(m);
 b=descriptor(1,0,3,0);m=packet(b);assert(mtkRxAmsduReadDescriptor(m,meta)==1&&!meta.pn_valid&&!meta.hwdec);mbuf_freem(m);
 b=descriptor(1);m=packet(b);assert(mtkRxAmsduReadDescriptor(m,meta)==1);good=meta;
 // Fill_rx has stripped RXD and may have cleared Protected; padding helper keeps it.
 mbuf_adj(m,meta.hdr_gap);((uint8_t*)mbuf_data(m))[1]&=~0x40;assert(mtkRxAmsduRemovePad(m,meta));auto expected=frame();expected[1]&=~0x40;assert(m->len==expected.size()&&!memcmp(mbuf_data(m),expected.data(),expected.size()));mbuf_freem(m);
 for(size_t n=0;n<50;++n){m=packet(std::vector<uint8_t>(n,0xaa));auto copy=m->storage;assert(!mtkRxAmsduRemovePad(m,good));assert(m->storage==copy&&m->len==n);mbuf_freem(m);}
 // Restore exactly one IV; body/tail bytes unchanged; both header states accepted.
 for(bool prot:{false,true}){auto f=frame(prot);m=packet(f);copy_calls=alloc_calls=0;auto*z=mtkRxAmsduRestoreCcmp(m,good);assert(z&&live==1&&alloc_calls==1);assert(z->len==f.size()+8&&z->pklen==z->len);auto*d=(uint8_t*)mbuf_data(z);assert(d[1]&0x40);uint8_t iv[]={1,2,0,0xa0,3,4,5,6};assert(!memcmp(d+26,iv,8));assert(!memcmp(d+34,f.data()+26,f.size()-26));mbuf_freem(z);}
 // Owned headroom restores IV in the same packet without copying payload.
 for(unsigned head:{8u,16u,32u})for(unsigned body:{20u,3817u}){
  auto f=frame(false);f.resize(26+14+body,0x5a);m=packet({},head+f.size());m->off=head;m->len=m->pklen=f.size();memcpy(mbuf_data(m),f.data(),f.size());auto*body_address=(uint8_t*)mbuf_data(m)+26;
  copy_calls=alloc_calls=0;auto*same=m;auto*z=mtkRxAmsduRestoreCcmp(m,good);assert(z==same&&live==1&&alloc_calls==0&&copy_calls==0);auto*d=(uint8_t*)mbuf_data(z);uint8_t iv[]={1,2,0,0xa0,3,4,5,6};assert(z->len==f.size()+8&&z->pklen==z->len&&!memcmp(d+26,iv,8));assert(d+34==body_address&&!memcmp(d+34,f.data()+26,f.size()-26));mbuf_freem(z);
 }
 // Shared clusters never take the mutating path, even with enough headroom.
 {auto f=frame(false);m=packet({},8+f.size());m->off=8;m->len=m->pklen=f.size();m->shared=true;memcpy(mbuf_data(m),f.data(),f.size());copy_calls=alloc_calls=0;auto*z=mtkRxAmsduRestoreCcmp(m,good);assert(z&&live==1&&alloc_calls==1&&copy_calls==2);mbuf_freem(z);}
 // A failed data-pointer adjustment preserves consuming ownership semantics.
 {auto f=frame(false);m=packet({},8+f.size());m->off=8;m->len=m->pklen=f.size();memcpy(mbuf_data(m),f.data(),f.size());fail_setdata=true;assert(!mtkRxAmsduRestoreCcmp(m,good)&&live==0);fail_setdata=false;}
 // Chained body accepted and copied in order.
 auto f=frame(false);m=packet(std::vector<uint8_t>(f.begin(),f.begin()+31));m->next=packet(std::vector<uint8_t>(f.begin()+31,f.end()));m->pklen=f.size();auto*z=mtkRxAmsduRestoreCcmp(m,good);assert(z&&live==1&&!memcmp((uint8_t*)mbuf_data(z)+34,f.data()+26,f.size()-26));mbuf_freem(z);
 // All allocation/copy failures consume both old and new buffers exactly once.
 for(int mode=1;mode<=4;++mode){alloc_mode=mode;m=packet(f);assert(!mtkRxAmsduRestoreCcmp(m,good)&&live==0);}alloc_mode=0;
 for(int mode=1;mode<=2;++mode){copy_calls=0;fail_copy=mode;m=packet(f);assert(!mtkRxAmsduRestoreCcmp(m,good)&&live==0);}fail_copy=0;
 for(unsigned mode=0;mode<7;++mode){auto md=good;if(mode==0)md.pn_valid=false;if(mode==1)md.hwdec=false;if(mode==2)md.cipher=2;if(mode==3)md.hdrlen=30;if(mode==4)md.key=4;if(mode==5)md.seqctl+=16;if(mode==6)md.tid=4;m=packet(f);assert(!mtkRxAmsduRestoreCcmp(m,md)&&live==0);}
 for(size_t n:{0u,25u,47u,3866u}){m=packet(std::vector<uint8_t>(n));assert(!mtkRxAmsduRestoreCcmp(m,good)&&live==0);}
 auto open=good;open.cipher=0;open.hwdec=false;open.protected_frame=false;open.pn_valid=false;m=packet(f);assert(mtkRxAmsduRestoreCcmp(m,open)==m);mbuf_freem(m);m=packet(frame(true));assert(!mtkRxAmsduRestoreCcmp(m,open)&&live==0);
 // Maximum supported complete body plus 8-byte IV remains bounded.
 f=frame(false);f.resize(26+3839,0x5a);m=packet(f);z=mtkRxAmsduRestoreCcmp(m,good);assert(z&&z->len==26+3839+8);mbuf_freem(z);
 assert(live==0);puts("PASS: descriptor group/guard-page bounds, all formats/ciphers, PN order, padding, IV restoration, chained input, allocation/copy failures and exact ownership");
}
'''
with tempfile.TemporaryDirectory() as d:
    p=Path(d);(p/'test.cpp').write_text(pre+'\n'+'\n'.join(defs)+'\n#include "'+str(header)+'"\n'+main)
    subprocess.run(['clang++','-std=c++14','-fsanitize=undefined','-fno-sanitize-recover=all','-g',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True)
