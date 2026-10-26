#!/usr/bin/env python3
"""Run the real MAC-address restart and deferred WCL join lifecycle."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
WCL = ROOT / "AirportMtkWlan/WCL"


def function(path, name, pattern=r"(?:IOReturn|void)"):
    # Balance braces from the active production branch, not the excluded
    # legacy adapter branch inside the same function.
    lines, active = [], [True]
    for line in path.read_text().splitlines(keepends=True):
        directive = line.strip()
        if directive in ("#ifdef AIRPORT_WCL", "#ifndef AIRPORT_WCL"):
            active.append(directive.startswith("#ifdef"))
            continue
        if directive == "#else" and len(active) > 1:
            active[-1] = not active[-1]
            continue
        if directive == "#endif" and len(active) > 1:
            active.pop()
            continue
        if all(active):
            lines.append(line)
    text = "".join(lines)
    match = re.search(r"(?m)^" + pattern + r" " + name + r"\([^;]*?\)\n\{", text)
    assert match, name
    start = text.index("{", match.start())
    depth, end = 1, start + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[match.start():end]


STUB = r'''
#define AIRPORT_WCL 1
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include "WCL.hpp"
using IOReturn=int;using UInt32=uint32_t;using UInt8=uint8_t;using errno_t=int;
constexpr int kIOReturnSuccess=0,kIOReturnError=5,kIOReturnBadArgument=6,kIOReturnNotReady=7;
#define XYLog(...) ((void)0)
#define explicit_bzero(p,n) memset(p,0,n)
#define AIRPORT_WCL_EVENT(code,data) handleEvent(code,data)
#define IFF_UP 1
#define IFF_RUNNING 2
#define IEEE80211_S_RUN 4
#define IEEE80211_ADDR_LEN 6
#define IEEE80211_EVT_DRIVER_READY 6
#define IEEE80211_EVT_DRIVER_STOPPED 7
struct _ifnet{int if_flags=IFF_UP|IFF_RUNNING;};
struct arpcom{_ifnet ac_if;uint8_t ac_enaddr[6]={2,0,0,0,0,1};};
struct ieee80211com{arpcom ic_ac;_ifnet&ic_if;uint8_t ic_myaddr[6]={2,0,0,0,0,1};
 uint8_t ic_wcl_mac_reconfig=AirportWCL::MacRestartNone;ieee80211com():ic_if(ic_ac.ac_if){}};
using ifnet_t=void*;
static const char*ether_sprintf(const uint8_t*){return "mac";}
static int ifnet_set_lladdr(ifnet_t,const void*,UInt32 n){assert(n==6);return 0;}
static int if_setlladdr(_ifnet*ifp,const UInt8*a){memcpy(((arpcom*)ifp)->ac_enaddr,a,6);return 0;}
static const char kIOMACAddress[]="IOMACAddress";
struct BSD{ifnet_t getIfnet(){return (ifnet_t)1;}void setProperty(const char*,UInt8*,UInt32 n){assert(n==6);}};
class AirportItlwm;
class Hal{public:AirportItlwm*owner=nullptr;ieee80211com ic;int disableResult=0,enableResult=0,disableCalls=0,enableCalls=0;
 bool async=false,stopped=false;
 ieee80211com*get80211Controller(){return &ic;}
 IOReturn disable(BSD*);
 IOReturn enable(BSD*);
};
class AirportItlwm{public:AirportItlwm(){hal.owner=this;}
 Hal hal;Hal*fHalService=&hal;BSD bsdStorage;BSD*bsdInterface=&bsdStorage;
 bool fNetIf=true;int events=0,readyEvents=0,failedEvents=0,deferredJoins=0;
 void handleEvent(int code,void*){
  ++events;bool ready=code==IEEE80211_EVT_DRIVER_READY;
  auto result=AirportWCL::advanceMacRestart(hal.ic.ic_wcl_mac_reconfig,ready);
  if(result==AirportWCL::MacRestartResult::Waiting){assert(!ready);return;}
  if(result==AirportWCL::MacRestartResult::Complete){++readyEvents;assert(ready);assert(deferredJoins);}
  if(result==AirportWCL::MacRestartResult::Failed){++failedEvents;assert(!ready);deferredJoins=0;}
 }
 IOReturn setHardwareAddress(const void*,UInt32);
};

IOReturn Hal::disable(BSD *interface)
{
    ++disableCalls;bool running=ic.ic_if.if_flags&IFF_RUNNING;ic.ic_if.if_flags&=~(IFF_UP|IFF_RUNNING);
    if(async&&running){stopped=true;owner->AIRPORT_WCL_EVENT(IEEE80211_EVT_DRIVER_STOPPED,nullptr);}
    return disableResult;
}

IOReturn Hal::enable(BSD *interface)
{
    ++enableCalls;ic.ic_if.if_flags|=IFF_UP;AirportWCL::beginMacRestartInit(ic.ic_wcl_mac_reconfig);
    assert(memcmp(ic.ic_myaddr,ic.ic_ac.ac_enaddr,6)!=0);
    memcpy(ic.ic_myaddr,ic.ic_ac.ac_enaddr,6);ic.ic_if.if_flags|=IFF_RUNNING;
    if(!async)AirportWCL::advanceMacRestart(ic.ic_wcl_mac_reconfig,enableResult==0);
    else owner->AIRPORT_WCL_EVENT(enableResult?IEEE80211_EVT_DRIVER_STOPPED:IEEE80211_EVT_DRIVER_READY,nullptr);
    return enableResult;
}
'''

MAIN = r'''
static uint8_t address[6]={2,0,0,0,0,2};
int main(){
 for(int flags:{IFF_UP|IFF_RUNNING,IFF_UP,0}){
  AirportItlwm f;f.hal.ic.ic_if.if_flags=flags;
  if(flags==IFF_UP)f.deferredJoins=1;
  assert(f.setHardwareAddress(address,6)==0);
  assert(!memcmp(f.hal.ic.ic_ac.ac_enaddr,address,6));
  if(flags&IFF_UP)assert(!memcmp(f.hal.ic.ic_myaddr,address,6));
  assert(f.hal.disableCalls==(flags&IFF_UP?1:0)&&f.hal.enableCalls==(flags&IFF_UP?1:0));
  assert(!f.hal.ic.ic_wcl_mac_reconfig);
 }
 {
  AirportItlwm f;f.hal.async=true;f.hal.ic.ic_if.if_flags=IFF_UP|IFF_RUNNING;f.deferredJoins=1;
  assert(f.setHardwareAddress(address,6)==0&&f.deferredJoins==1&&f.readyEvents==1);
  assert(f.hal.stopped&&f.hal.ic.ic_wcl_mac_reconfig==AirportWCL::MacRestartNone);
 }
 {
  AirportItlwm f;f.deferredJoins=1;f.hal.enableResult=kIOReturnError;
  assert(f.setHardwareAddress(address,6)==kIOReturnError);
  assert(!f.hal.ic.ic_wcl_mac_reconfig&&f.deferredJoins==1);
  // A later, unrelated event must not consume the join that WCL can retry.
  f.AIRPORT_WCL_EVENT(IEEE80211_EVT_DRIVER_STOPPED,nullptr);assert(f.deferredJoins==1&&!f.failedEvents);
 }
 {
  AirportItlwm f;f.deferredJoins=1;f.hal.ic.ic_wcl_mac_reconfig=AirportWCL::MacRestartStarting;
  f.AIRPORT_WCL_EVENT(IEEE80211_EVT_DRIVER_STOPPED,nullptr);
  assert(f.failedEvents==1&&f.deferredJoins==0&&!f.hal.ic.ic_wcl_mac_reconfig);
 }
 {
  AirportItlwm f;uint8_t same[6];memcpy(same,f.hal.ic.ic_myaddr,6);
  assert(f.setHardwareAddress(same,6)==0&&f.hal.disableCalls==0&&f.events==0);
  uint8_t bad[6]={1,0,0,0,0,2};assert(f.setHardwareAddress(bad,6)==kIOReturnBadArgument);
  assert(f.setHardwareAddress(address,5)==kIOReturnBadArgument);
 }
 puts("PASS MAC address: prejoin restart, address propagation, deferred join retention and failure reporting.");
}
'''

with tempfile.TemporaryDirectory(prefix="mtk-mac-restart-") as directory:
    source = Path(directory) / "test.cpp"
    source.write_text(STUB + function(ROOT / "AirportMtkWlan/AirportItlwmV2.cpp",
                                      "AirportItlwm::setHardwareAddress") + MAIN)
    binary = source.with_suffix("")
    subprocess.run(["clang++", "-std=c++14", "-I", str(WCL),
                    "-fsanitize=" + os.environ.get("MTK_TEST_SANITIZERS", "address,undefined"),
                    "-fno-sanitize-recover=all", str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
