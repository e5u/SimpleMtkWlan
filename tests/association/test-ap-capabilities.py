#!/usr/bin/env python3
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[2]
source=r'''
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>
#include <sys/mman.h>
#include <unistd.h>
#include "ApCapabilitySummary.hpp"
int main(){
 const uint8_t golden[]={191,12,0x34,0x71,0x80,0x31,0xfa,0xff,0,0,0xfa,0xff,0,0,192,5,1,42,50,0xfa,0xff};
 MtkApCapabilitySummary s{};
 assert(mtkParseApCapabilities(golden,sizeof(golden),s));
 assert(s.vhtCaps==0x31807134 && s.vht && s.operation && s.width==1 && s.center0==42 && s.center1==50 && !s.heCapabilityBytes);
 const size_t page=sysconf(_SC_PAGESIZE);
 auto*p=(uint8_t*)mmap(nullptr,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);assert(p!=MAP_FAILED);assert(!mprotect(p+page,page,PROT_NONE));
 for(size_t n=0;n<=sizeof(golden);++n){
  auto*q=p+page-n;memcpy(q,golden,n);bool ok=mtkParseApCapabilities(q,n,s);
  assert(ok==(n==14 || n==sizeof(golden)));
  if(!ok)assert(!s.vht&&!s.operation&&!s.vhtCaps&&!s.heCapabilityBytes);
 }
 for(unsigned n=0;n<=255;++n){
  std::vector<uint8_t>a(n+2,0);a[0]=191;a[1]=n;assert(mtkParseApCapabilities(a.data(),a.size(),s)==(n==12));
  a[0]=192;assert(mtkParseApCapabilities(a.data(),a.size(),s)==(n==5));
  a[0]=255;if(n)a[2]=35;assert(mtkParseApCapabilities(a.data(),a.size(),s)==(n>=22));
 }
 std::vector<uint8_t>d(golden,golden+sizeof(golden));d.insert(d.end(),golden,golden+14);assert(!mtkParseApCapabilities(d.data(),d.size(),s));
 uint8_t absent[]={0,0,1,1,0x82};assert(mtkParseApCapabilities(absent,sizeof(absent),s)&&!s.vht&&!s.operation&&!s.heCapabilityBytes);
 assert(!mtkParseApCapabilities(nullptr,21,s));assert(!mtkParseApCapabilities(golden,1025,s));
 munmap(p,page*2);puts("PASS raw AP IE summary: independent VHT/centers, protected-page truncation, all byte lengths, duplicates, empty cache; diagnostic only.");
}
'''
with tempfile.TemporaryDirectory(prefix='mtk-ap-cap-') as tmp:
 p=Path(tmp);(p/'test.cpp').write_text(source)
 subprocess.run(['clang++','-std=c++14','-fsanitize=undefined','-fno-sanitize-recover=all','-I',str(root/'SimpleMtkWlan/hal_mwx'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
