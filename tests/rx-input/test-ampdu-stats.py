#!/usr/bin/env python3
"""UBSan test of timestamp grouping, interval carry-over and unknown RX groups."""
from pathlib import Path
import subprocess, tempfile
root=Path(__file__).resolve().parents[2]
main=r'''
#include <cassert>
#include <cstdio>
#include "RxAmpduStats.hpp"
int main() {
 MtkRxAmpduStats s={};
 // TSF zero is valid; a timestamp change, not its numeric value, closes a group.
 mtkRxAmpduObserve(s,true,0,false,false);
 mtkRxAmpduObserve(s,true,0,false,false);
 assert(s.groups==0 && s.pending==2);
 mtkRxAmpduResetInterval(s);
 assert(s.active && s.pending==2);
 mtkRxAmpduObserve(s,true,0,false,false);
 mtkRxAmpduObserve(s,true,0xffffffff,false,false);
 assert(s.groups==1 && s.mpdus==3 && s.bins[1]==1 && s.pending==1);
 mtkRxAmpduObserve(s,true,0,false,false);
 assert(s.groups==2 && s.bins[0]==1); // timestamp wrap is just a change
 mtkRxAmpduObserve(s,false,0,false,false);
 assert(s.missingGroup2==1 && s.uncertainGroups==1 && !s.active);
 mtkRxAmpduObserve(s,true,1,false,false);
 mtkRxAmpduObserve(s,true,1,false,true);
 assert(s.deaggregated==1 && s.uncertainGroups==2 && !s.active);
 mtkRxAmpduObserve(s,true,2,true,false);
 assert(s.nonAmpdu==1 && !s.active);
 s={};
 unsigned sizes[]={1,2,3,4,7,8,15,16,31,32,64};
 for(unsigned g=0;g<11;++g) {
  for(unsigned n=0;n<sizes[g];++n) mtkRxAmpduObserve(s,true,g,false,false);
 }
 // A non-A-MPDU terminates the last pending aggregate without adding a member.
 mtkRxAmpduObserve(s,true,20,true,false);
 assert(s.groups==11 && s.mpdus==183 && s.maximum==64 && s.pending==0);
 assert(s.bins[0]==1);
 for(unsigned i=1;i<6;++i)assert(s.bins[i]==2);
 mtkRxAmpduResetInterval(s);
 assert(s.groups==0 && s.maximum==0 && !s.active && s.nonAmpdu==0);
 puts("PASS: timestamp grouping, zero/wrap, exact histogram, cross-interval carry, missing metadata and deaggregation exclusions");
}
'''
with tempfile.TemporaryDirectory(prefix='mtk-ampdu-stats-') as d:
 p=Path(d);(p/'test.cpp').write_text(main)
 subprocess.run(['clang++','-std=c++14','-fsanitize=undefined','-fno-sanitize-recover=all','-g','-I',str(root/'SimpleMtkWlan/hal_mwx'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
