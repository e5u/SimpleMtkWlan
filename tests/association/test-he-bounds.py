#!/usr/bin/env python3
"""Actual HE parsers/builders: protected-page truncation and UBSan."""
from pathlib import Path
import os,re,subprocess,tempfile
root=Path(__file__).resolve().parents[2]; net=root/'mtk80211/openbsd/net80211'
h=(net/'ieee80211.h').read_text(); node=(net/'ieee80211_node.c').read_text()
out=(net/'ieee80211_output.c').read_text(); inp=(net/'ieee80211_input.c').read_text()
def fn(s,name,ret):
 m=re.search(r'(?m)^'+name+r'\([^;]*?\)\s*\n\{',s);assert m,name
 return ret+'\n'+s[m.start():s.index('\n}',m.end())+2]+'\n'
def struct(name):
 m=re.search(r'(?ms)^struct '+name+r' \{.*?^\} __packed;',h);assert m,name
 return m.group()+'\n'
names=['IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G','IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G','IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT','IEEE80211_PPE_THRES_NSS_POS','IEEE80211_PPE_THRES_NSS_MASK','IEEE80211_PPE_THRES_RU_INDEX_BITMASK_MASK','IEEE80211_PPE_THRES_INFO_PPET_SIZE','IEEE80211_HE_OPERATION_VHT_OPER_INFO','IEEE80211_HE_OPERATION_CO_HOSTED_BSS','IEEE80211_HE_OPERATION_6GHZ_OP_INFO']
defines='\n'.join(re.search(r'(?m)^#define\s+'+n+r'\s+[^\n]+',h).group() for n in names)
guards=re.findall(r'case IEEE80211_ELEMID_EXTENSION:\n(.*?)\s*switch \(frm\[2\]\)',inp,re.S)
assert len(guards)==2 and guards[0]==guards[1] and 'if (frm[1] < 1)' in guards[0]
pre=r'''
#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <strings.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>
#define __packed __attribute__((packed))
#ifndef __offsetof
#define __offsetof(t,f) offsetof(t,f)
#endif
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#ifndef le32toh
#define le32toh(x) uint32_t(x)
#define le16toh(x) uint16_t(x)
#endif
#define IEEE80211_ELEMID_EXTENSION 255
#define IEEE80211_ELEMID_EXT_HE_CAPABILITY 35
static unsigned hweight8(uint8_t x){return __builtin_popcount(unsigned(x));}
template<class A,class B> static size_t min(A a,B b){return size_t(a)<size_t(b)?size_t(a):size_t(b);}
'''
stubs=r'''
struct ieee80211_node {ieee80211_he_cap_elem ni_he_cap_elem;ieee80211_he_mcs_nss_supp ni_he_mcs_nss_supp;uint8_t ni_ppe_thres[25];uint32_t ni_he_oper_params;uint16_t ni_he_oper_nss_set;uint8_t ni_he_optional[8];};
struct ieee80211com {ieee80211_he_cap_elem ic_he_cap_elem;ieee80211_he_mcs_nss_supp ic_he_mcs_nss_supp;uint8_t ic_ppe_thres[25];struct{unsigned is_rx_elem_toosmall=0;}ic_stats;};
'''
helpers=''.join(fn(h,n,'static inline uint8_t') for n in ['ieee80211_he_mcs_nss_size','ieee80211_he_ppe_size','ieee80211_he_oper_size'])
functions=fn(node,'ieee80211_setup_hecaps','void')+fn(node,'ieee80211_setup_heop','int')+fn(out,'ieee80211_add_hecaps','uint8_t *')
proto=(net/'ieee80211_proto.c').read_text();neg=proto[proto.index('void\nieee80211_he_negotiate('):proto.index('\n\nvoid\n',proto.index('void\nieee80211_he_negotiate('))]
assert 'htole32(ni->ni_he_oper_params)' not in neg, 'HE operation VHT-info bit must stay host endian after setup_heop()'
extension='static void extension_guard(const uint8_t *frm,ieee80211com *ic,unsigned &seen){do{\n'+guards[0]+'\nseen=frm[2];\n}while(0);}\n'
post=r'''
struct Guard{uint8_t *base;size_t page;
 Guard(){page=size_t(sysconf(_SC_PAGESIZE));base=static_cast<uint8_t*>(mmap(nullptr,page*2,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0));assert(base!=MAP_FAILED);assert(mprotect(base+page,page,PROT_NONE)==0);}
 ~Guard(){assert(munmap(base,page*2)==0);}
 uint8_t *place(const std::vector<uint8_t>&v,size_t n){assert(n<=v.size());auto*p=base+page-n;if(n)memcpy(p,v.data(),n);return p;}};
static size_t cases;
static void cap_tests(Guard&g){
 static_assert(sizeof(ieee80211_he_cap_elem)==17,"HE fixed wire size");
 for(unsigned w=0;w<4;++w)for(unsigned present=0;present<2;++present)for(unsigned hdr=0;hdr<(present?256:1);++hdr){
  size_t mcs=4+((w&1)?4:0)+((w&2)?4:0);
  size_t ppe=present?(7+6*((hdr&7)+1)*__builtin_popcount(hdr&0x78)+7)/8:0,need=17+mcs+ppe;
  std::vector<uint8_t> v(need+2,0x59);v[6]=((w&1)?8:0)|((w&2)?16:0);v[12]=present?0x80:0;if(ppe)v[17+mcs]=hdr;
  for(size_t len=0;len<=v.size();++len){
   ieee80211_node n,before;memset(&n,0xa5,sizeof(n));before=n;
   ieee80211_setup_hecaps(&n,g.place(v,len),uint8_t(len));
   if(len<need)assert(memcmp(&n,&before,sizeof(n))==0);
   else{assert(memcmp(&n.ni_he_cap_elem,v.data(),17)==0);assert(memcmp(&n.ni_he_mcs_nss_supp,v.data()+17,mcs)==0);
    if(ppe)assert(memcmp(n.ni_ppe_thres,v.data()+17+mcs,ppe)==0);else assert(memcmp(n.ni_ppe_thres,before.ni_ppe_thres,25)==0);
    assert(n.ni_he_oper_params==before.ni_he_oper_params);}
   ++cases;}
  ieee80211com ic;memset(&ic,0x3a,sizeof(ic));memcpy(&ic.ic_he_cap_elem,v.data(),17);memcpy(&ic.ic_he_mcs_nss_supp,v.data()+17,mcs);if(ppe)memcpy(ic.ic_ppe_thres,v.data()+17+mcs,ppe);
  std::vector<uint8_t> z(need+3,0);auto*o=g.place(z,z.size());auto*end=ieee80211_add_hecaps(o,&ic);assert(end-o==ptrdiff_t(need+3));
  assert(o[0]==255&&o[1]==need+1&&o[2]==35);assert(memcmp(o+3,v.data(),17+mcs)==0);if(ppe)assert(memcmp(o+3+17+mcs,v.data()+17+mcs,ppe)==0);++cases;
 }}
static void operation_tests(Guard&g){
 static_assert(sizeof(ieee80211_he_operation)==6,"HE operation fixed wire size");
 for(unsigned f=0;f<8;++f){uint32_t params=((f&1)?0x4000:0)|((f&2)?0x8000:0)|((f&4)?0x20000:0);
  size_t need=6+((f&1)?3:0)+((f&2)?1:0)+((f&4)?5:0);std::vector<uint8_t>v(need+2,0x73);memcpy(v.data(),&params,4);v[4]=0xfa;v[5]=0xff;
  for(size_t len=0;len<=v.size();++len){ieee80211_node n,before;memset(&n,0xa5,sizeof(n));before=n;
   int rv=ieee80211_setup_heop(&n,g.place(v,len),uint8_t(len));
   if(len<need){assert(rv==0);assert(memcmp(&n,&before,sizeof(n))==0);}
   else{assert(rv==1&&n.ni_he_oper_params==params&&n.ni_he_oper_nss_set==0xfffa);size_t copied=min(size_t(8),len-6);assert(memcmp(n.ni_he_optional,v.data()+6,copied)==0);for(size_t i=copied;i<8;++i)assert(n.ni_he_optional[i]==0);assert(memcmp(&n.ni_he_cap_elem,&before.ni_he_cap_elem,17)==0);}++cases;
  }}
}
int main(){const uint16_t little=1;assert(*reinterpret_cast<const uint8_t*>(&little)==1);Guard g;cap_tests(g);operation_tests(g);
 for(unsigned len=0;len<2;++len){std::vector<uint8_t>v={255,uint8_t(len),35};ieee80211com ic{};unsigned seen=999;extension_guard(g.place(v,2+len),&ic,seen);assert(ic.ic_stats.is_rx_elem_toosmall==(len==0));assert(seen==(len?35:999));++cases;}
 printf("PASS actual HE parsers/builders: %zu protected-page cases; all width/MCS and 256 PPE headers, every truncation, optional operation lengths, both empty extension guards, present/absent PPE output length; UBSan. HE remains disabled.\n",cases);}
'''
source=pre+defines+'\n'+''.join(struct(n) for n in ['ieee80211_he_cap_elem','ieee80211_he_mcs_nss_supp','ieee80211_he_operation','ieee80211_he_6ghz_oper'])+stubs+helpers+functions+extension+post
with tempfile.TemporaryDirectory(prefix='mtk-he-bounds-') as td:
 p=Path(td);cpp=p/'test.cpp';cpp.write_text(source)
 subprocess.run(['clang++','-std=gnu++14','-fsanitize=undefined','-fno-sanitize-recover=all','-g',str(cpp),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1:print_stacktrace=1'})
