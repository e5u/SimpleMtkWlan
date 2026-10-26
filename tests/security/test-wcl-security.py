#!/usr/bin/env python3
"""Execute native WCL join credential selection and lifecycle with real code."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
WCL = ROOT / "AirportMtkWlan/WCL"


def method(name):
    text = (WCL / "WCL.cpp").read_text()
    match = re.search(r"(?m)^(?:IOReturn|void) AirportItlwmSkywalkInterface::" + name + r"\([^;]*?\)\n\{", text)
    assert match, name
    start = text.index("{", match.start())
    depth, end = 1, start + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[match.start():end]


STUB = r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "WCL.hpp"
using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnUnsupported=2,kIOReturnBusy=3,kIOReturnNoMemory=4,kIOReturnError=5;
#define XYLog(...) ((void)0)
#define explicit_bzero(p,n) memset(p,0,n)
#define IEEE80211_PMK_LEN 32
#define IEEE80211_ELEMID_RSN 48
#define IEEE80211_F_PSK 1
#define IEEE80211_F_RSNON 2
#define IEEE80211_F_AUTO_JOIN 4
#define IEEE80211_F_MFPR 8
#define IEEE80211_F_DESBSSID 16
#define IEEE80211_F_WPA3 1
#define IEEE80211_C_MFP 1
#define IEEE80211_C_RSN 2
#define IFF_UP 1
#define IFF_RUNNING 2
#define IEEE80211_S_SCAN 1
#define IEEE80211_S_AUTH 2
#define IEEE80211_S_ASSOC 3
#define IEEE80211_S_RUN 4
#define IEEE80211_WPA_PROTO_WPA1 1
#define IEEE80211_WPA_PROTO_WPA2 2
#define IEEE80211_WPA_AKM_8021X 1
#define IEEE80211_WPA_AKM_PSK 2
#define IEEE80211_WPA_AKM_SHA256_8021X 4
#define IEEE80211_WPA_AKM_SHA256_PSK 8
#define IEEE80211_WPA_AKM_SAE 16
#define IEEE80211_PROTO_WPA 1
#define IEEE80211_PROTO_RSN 2
#define IEEE80211_AKM_PSK 2
#define IEEE80211_AKM_SHA256_PSK 8
#define IEEE80211_AKM_SAE 16
#define IEEE80211_WPA_CIPHER_WEP40 1
#define IEEE80211_WPA_CIPHER_WEP104 8
#define IEEE80211_WPA_CIPHER_USEGROUP 0x100
#define IEEE80211_WPA_CIPHER_CCMP 4
enum ieee80211_cipher {IEEE80211_CIPHER_NONE=0,IEEE80211_CIPHER_USEGROUP=0x100,
 IEEE80211_CIPHER_WEP40=1,IEEE80211_CIPHER_TKIP=2,IEEE80211_CIPHER_CCMP=4,IEEE80211_CIPHER_WEP104=8};
using u_int32_t=uint32_t;
#define IEEE80211_WPA_CIPHER_TKIP 2
#define IEEE80211_AKM_8021X 1
#define IEEE80211_AKM_SHA256_8021X 4
#define IEEE80211_NWKEY_WEP 1
#define APPLE80211_AUTHTYPE_WPA (1u<<0)
#define APPLE80211_AUTHTYPE_WPA_PSK (1u<<1)
#define APPLE80211_AUTHTYPE_WPA2 (1u<<2)
#define APPLE80211_AUTHTYPE_WPA2_PSK (1u<<3)
#define APPLE80211_AUTHTYPE_SHA256_PSK (1u<<10)
#define APPLE80211_AUTHTYPE_SHA256_8021X (1u<<11)
#define APPLE80211_AUTHTYPE_WPA3_SAE (1u<<12)
struct ieee80211_wpaparams {int i_enabled,i_protos,i_akms,i_ciphers,i_groupcipher;};
struct ieee80211_nwkey {int i_wepon,i_defkid;struct {int i_keylen;uint8_t*i_keydat;}i_key[4];};
struct _ifnet {int if_flags=IFF_UP|IFF_RUNNING;};
struct ieee80211com {
 _ifnet ic_if;int ic_userflags=0,ic_flags=0,ic_caps=IEEE80211_C_RSN,ic_state=0;
 int ic_rsnprotos=0,ic_rsnakms=0,ic_rsnciphers=0;ieee80211_cipher ic_rsngroupcipher=IEEE80211_CIPHER_NONE;
 bool ic_wcl_mac_reconfig=false,ic_wcl_enterprise=false,ic_wcl_join_requested=false,ic_wcl_scan_requested=false,ic_wcl_scan_idle=false;
 uint8_t ic_psk[32]={},ic_sae[128]={},ic_sae_password[255]={};
 uint8_t ic_sae_password_len=0,ic_sae_pmk_valid=0,ic_sae_confirm_sent=0,ic_sae_confirm_ready=0;
 unsigned ic_des_esslen=0;uint8_t ic_des_essid[32]={},ic_des_bssid[6]={};
 int(*ic_newstate)(ieee80211com*,int,int)=nullptr;
};
static ieee80211_wpaparams last_wpa;static int pbkdf_calls=0,newstate_error=0;
static void ieee80211_sae_clear(void*s){memset(s,0,128);}
static void ieee80211_disable_rsn(ieee80211com*ic){ic->ic_flags&=~(IEEE80211_F_PSK|IEEE80211_F_RSNON);}
static void ieee80211_disable_wep(ieee80211com*){}
int actual_setwpaparms(ieee80211com*,const ieee80211_wpaparams*);
static int ieee80211_ioctl_setwpaparms(ieee80211com*ic,const ieee80211_wpaparams*w){last_wpa=*w;return actual_setwpaparms(ic,w);}
static int ieee80211_ioctl_setnwkeys(ieee80211com*,const ieee80211_nwkey*){return ENETRESET;}
static void*ieee80211_pmksa_add(ieee80211com*,int,const uint8_t*,const uint8_t*,int){return (void*)1;}
static void ieee80211_next_scan(_ifnet*){}
// This test checks whether both credential paths are invoked. PBKDF correctness
// is independently covered by the crypto tests; never replace real join code.
static void pbkdf2_sha1(const char*p,const uint8_t*ssid,unsigned n,unsigned count,uint8_t*out,size_t len){
 assert(strlen(p)==8&&memcmp(p,"password",8)==0&&n==4&&!memcmp(ssid,"test",4)&&count==4096&&len==32);
 ++pbkdf_calls;memset(out,0x6d,len);
}
static int change_state(ieee80211com*ic,int s,int){ic->ic_state=s;return newstate_error;}
struct Hal {ieee80211com ic;ieee80211com*get80211Controller(){return &ic;}};
struct Timer {int timeout=0;void setTimeoutMS(int n){timeout=n;}void cancelTimeout(){timeout=0;}};
class AirportItlwmSkywalkInterface {
public:
 Hal hal;Hal*fHalService=&hal;Timer timer;Timer*joinTimer=&timer;
 AirportWCL::JoinRequest deferredJoin{};uint8_t joinBSSID[6]={},wclBeaconInfo[64]={};
 bool joinPending=false,joinDeferred=false,scanPending=false,wclBssValid=false,assocNotified=false,firstBeaconNotified=false,portAuthorized=false,disassocIsVoluntary=false;
 unsigned current_authtype_lower=0,current_authtype_upper=0,wclAssociatedBeacons=0;int cache_clears=0;
 IOReturn startWCLJoin(AirportWCL::JoinRequest&);
 bool wclScanWantsSAE(const AirportWCL::JoinRequest&)const{return false;}
 void clearWCLSae();
 void clearWCLPMKSA(){++cache_clears;}
 IOReturn leaveWCLNetwork(){hal.ic.ic_state=IEEE80211_S_SCAN;return 0;}
 AirportItlwmSkywalkInterface(){hal.ic.ic_newstate=change_state;}
};
'''

MAIN = r'''
static AirportWCL::JoinRequest request(uint32_t upper,bool pmk=false,unsigned length=8){
 AirportWCL::JoinRequest j{};j.lowerAuth=1;j.upperAuth=upper;j.ssidLength=4;memcpy(j.ssid,"test",4);j.bssid[0]=2;
 j.keyLength=pmk?32:length;j.keyCipher=pmk?6:0;
 if(pmk)memset(j.key,0x2a,32);else memcpy(j.key,"password",length>8?8:length);return j;
}
static void saeOnlyRSN(AirportWCL::JoinRequest&j){
 static const uint8_t ie[]={48,20,1,0,0,0x0f,0xac,4,1,0,0,0x0f,0xac,4,
  1,0,0,0x0f,0xac,8,0xc0,0};
 j.rsnLength=sizeof(ie);memcpy(j.rsn,ie,sizeof(ie));
}
static bool zero(const void*p,size_t n){auto*b=(const uint8_t*)p;for(size_t i=0;i<n;++i)if(b[i])return false;return true;}
int main(){
 const uint32_t transition=APPLE80211_AUTHTYPE_WPA2_PSK|APPLE80211_AUTHTYPE_WPA3_SAE;
 {
  uint8_t frame[96]={};frame[0]=0x80;for(unsigned i=0;i<6;++i)frame[16+i]=uint8_t(0x10+i);
  size_t off=36;frame[off++]=0;frame[off++]=4;memcpy(frame+off,"test",4);off+=4;
  static const uint8_t ie[]={48,20,1,0,0,0x0f,0xac,4,1,0,0,0x0f,0xac,4,
   1,0,0,0x0f,0xac,8,0xc0,0};
  memcpy(frame+off,ie,sizeof(ie));off+=sizeof(ie);
  AirportWCL::ScannedNetwork parsed{};
  assert(AirportWCL::parseScannedNetwork(frame,off,parsed));
  assert(parsed.ssidLength==4&&!memcmp(parsed.ssid,"test",4)&&parsed.saeOnly);
  assert(parsed.bssid[0]==0x10&&parsed.bssid[5]==0x15);
  assert(parsed.rsnAKMCount==1&&parsed.rsnAKMs[0]==8&&parsed.hasSAE&&!parsed.hasPSK);
  frame[0]=0x50;
  assert(AirportWCL::parseScannedNetwork(frame,off,parsed)&&parsed.saeOnly);
 }
 {
  AirportItlwmSkywalkInterface f;f.hal.ic.ic_userflags=IEEE80211_F_WPA3;auto j=request(transition);
  assert(f.startWCLJoin(j)==0&&zero(&j,sizeof(j))&&f.joinPending);
  assert(last_wpa.i_akms==(IEEE80211_WPA_AKM_PSK|IEEE80211_WPA_AKM_SAE));
  assert(f.hal.ic.ic_rsnakms==(IEEE80211_AKM_PSK|IEEE80211_AKM_SAE));
  assert(pbkdf_calls==1&&f.hal.ic.ic_psk[0]==0x6d&&f.hal.ic.ic_sae_password_len==8);
  assert(!memcmp(f.hal.ic.ic_sae_password,"password",8)&&(f.hal.ic.ic_flags&IEEE80211_F_PSK));
  assert((f.hal.ic.ic_flags&IEEE80211_F_MFPR)&&(f.hal.ic.ic_caps&IEEE80211_C_MFP));
 }
 {
  AirportItlwmSkywalkInterface f;auto j=request(transition);
  assert(f.startWCLJoin(j)==0&&last_wpa.i_akms==IEEE80211_WPA_AKM_PSK&&pbkdf_calls==2);
  assert(!f.hal.ic.ic_sae_password_len&&!(f.hal.ic.ic_caps&IEEE80211_C_MFP));
 }
 {
  AirportItlwmSkywalkInterface f;f.hal.ic.ic_userflags=IEEE80211_F_WPA3;auto j=request(transition,true);
  assert(f.startWCLJoin(j)==0&&last_wpa.i_akms==IEEE80211_WPA_AKM_PSK&&pbkdf_calls==2);
  assert(f.hal.ic.ic_psk[0]==0x2a&&!f.hal.ic.ic_sae_password_len);
 }
 {
  // Tahoe can supply a PMK and a separate SAE password in the same request.
  AirportItlwmSkywalkInterface f;f.hal.ic.ic_userflags=IEEE80211_F_WPA3;auto j=request(transition,true);
  j.extendedPasswordLength=8;memcpy(j.extendedPassword,"password",8);
  assert(AirportWCL::isSAEPassword(j));
  assert(f.startWCLJoin(j)==0&&last_wpa.i_akms==(IEEE80211_WPA_AKM_PSK|IEEE80211_WPA_AKM_SAE));
  assert(f.hal.ic.ic_sae_password_len==8&&!memcmp(f.hal.ic.ic_sae_password,"password",8));
  assert(f.hal.ic.ic_psk[0]==0x2a&&pbkdf_calls==2);
 }
 {
  AirportItlwmSkywalkInterface f;f.hal.ic.ic_userflags=IEEE80211_F_WPA3;auto j=request(APPLE80211_AUTHTYPE_WPA3_SAE);
  assert(f.startWCLJoin(j)==0&&last_wpa.i_akms==IEEE80211_WPA_AKM_SAE&&last_wpa.i_protos==IEEE80211_WPA_PROTO_WPA2);
  assert(last_wpa.i_ciphers==IEEE80211_WPA_CIPHER_CCMP&&pbkdf_calls==2);
  assert(!(f.hal.ic.ic_flags&IEEE80211_F_PSK)&&(f.hal.ic.ic_flags&IEEE80211_F_MFPR)&&zero(f.hal.ic.ic_psk,32));
 }
 {
  // Tahoe's CoreWLAN may submit upper=WPA2_PSK for a WPA3-only BSS. The
  // SAE-only RSN IE must override that stale auth hint without PSK fallback.
  AirportItlwmSkywalkInterface f;f.hal.ic.ic_userflags=IEEE80211_F_WPA3;
  auto j=request(APPLE80211_AUTHTYPE_WPA2_PSK);saeOnlyRSN(j);
  assert(AirportWCL::rsnForcesSAE(j));
  assert(f.startWCLJoin(j)==0&&last_wpa.i_akms==IEEE80211_WPA_AKM_SAE);
  assert(last_wpa.i_ciphers==IEEE80211_WPA_CIPHER_CCMP&&pbkdf_calls==2);
  assert(!(f.hal.ic.ic_flags&IEEE80211_F_PSK)&&(f.hal.ic.ic_flags&IEEE80211_F_MFPR));
  assert(f.hal.ic.ic_sae_password_len==8&&!memcmp(f.hal.ic.ic_sae_password,"password",8));
 }
 for(bool enabled:{false,true}) {
  AirportItlwmSkywalkInterface f;f.hal.ic.ic_userflags=enabled?IEEE80211_F_WPA3:0;
  auto j=request(APPLE80211_AUTHTYPE_WPA3_SAE,true);
  assert(f.startWCLJoin(j)==kIOReturnUnsupported&&zero(&j,sizeof(j))&&!f.joinPending);
 }
 {
  AirportItlwmSkywalkInterface f;f.hal.ic.ic_userflags=IEEE80211_F_WPA3;
  auto j=request(APPLE80211_AUTHTYPE_WPA2_PSK,true);saeOnlyRSN(j);
  assert(AirportWCL::classifyLegacyAuth(j,true)==AirportWCL::LegacyAuth::Invalid);
  assert(!AirportWCL::personalSecurity(j,true,true).psk);
 }
 {
  AirportItlwmSkywalkInterface f;auto j=request(APPLE80211_AUTHTYPE_WPA3_SAE);
  assert(f.startWCLJoin(j)==kIOReturnUnsupported&&!f.joinPending);
 }
 {
  AirportItlwmSkywalkInterface f;f.hal.ic.ic_userflags=IEEE80211_F_WPA3;auto j=request(APPLE80211_AUTHTYPE_WPA3_SAE,false,1);
  assert(f.startWCLJoin(j)==0&&f.hal.ic.ic_sae_password_len==1&&!(f.hal.ic.ic_flags&IEEE80211_F_PSK));
 }
 {
  auto j=request(APPLE80211_AUTHTYPE_WPA3_SAE|APPLE80211_AUTHTYPE_WPA2);
  assert(AirportWCL::classifyLegacyAuth(j)==AirportWCL::LegacyAuth::Invalid);
  j=request(APPLE80211_AUTHTYPE_WPA3_SAE,false,33);
  assert(AirportWCL::classifyLegacyAuth(j)==AirportWCL::LegacyAuth::Invalid);
 }
 {
  AirportItlwmSkywalkInterface f;f.hal.ic.ic_userflags=IEEE80211_F_WPA3;f.hal.ic.ic_wcl_mac_reconfig=true;
  auto j=request(transition);assert(f.startWCLJoin(j)==0&&f.joinDeferred&&f.joinPending&&zero(&j,sizeof(j)));
  assert(f.deferredJoin.keyLength==8&&!memcmp(f.deferredJoin.key,"password",8));
 }
 {
  AirportItlwmSkywalkInterface f;f.hal.ic.ic_userflags=IEEE80211_F_WPA3;newstate_error=1;auto j=request(transition);
  assert(f.startWCLJoin(j)==kIOReturnError&&!f.joinPending&&!f.hal.ic.ic_wcl_join_requested);
  assert(zero(f.hal.ic.ic_psk,32)&&zero(f.hal.ic.ic_sae_password,255)&&!f.hal.ic.ic_sae_password_len);
  newstate_error=0;
 }
 {
  AirportItlwmSkywalkInterface f;memset(f.hal.ic.ic_sae,0xaa,128);memset(f.hal.ic.ic_sae_password,0xaa,255);
  f.hal.ic.ic_sae_password_len=f.hal.ic.ic_sae_pmk_valid=f.hal.ic.ic_sae_confirm_ready=f.hal.ic.ic_sae_confirm_sent=1;
  f.clearWCLSae();assert(zero(f.hal.ic.ic_sae,128)&&zero(f.hal.ic.ic_sae_password,255));
  assert(!f.hal.ic.ic_sae_password_len&&!f.hal.ic.ic_sae_pmk_valid&&!f.hal.ic.ic_sae_confirm_ready&&!f.hal.ic.ic_sae_confirm_sent);
 }
 {
  ieee80211com ic;ieee80211_wpaparams w{};w.i_enabled=1;w.i_akms=IEEE80211_WPA_AKM_SAE;
  ic.ic_rsnakms=IEEE80211_AKM_PSK;
  assert(actual_setwpaparms(&ic,&w)==EINVAL&&ic.ic_rsnakms==IEEE80211_AKM_PSK);
  w.i_akms=0x80000000;assert(actual_setwpaparms(&ic,&w)==EINVAL);
  w.i_akms=0;assert(actual_setwpaparms(&ic,&w)==ENETRESET&&ic.ic_rsnakms==IEEE80211_AKM_PSK);
 }
 // The native key starts at0x50; byte33 is a distinct ABI field, not a password continuation.
 uint8_t raw[0x2cc]={};raw[0x10]=1;raw[0x1c]=4;memcpy(raw+0x20,"test",4);raw[0x44]=33;raw[0x214]=1;raw[0x21c]=2;
 AirportWCL::JoinRequest decoded{};assert(!AirportWCL::decodeJoin(raw,sizeof(raw),decoded));raw[0x44]=32;
 assert(AirportWCL::decodeJoin(raw,sizeof(raw),decoded)&&decoded.keyLength==32);
 uint8_t sae_raw[0x3e0]={};memcpy(sae_raw,raw,sizeof(raw));
 sae_raw[0x48]=10;sae_raw[0x15]=0x10;
 sae_raw[0x18]=0x78;sae_raw[0x19]=0x56;sae_raw[0x1a]=0x34;sae_raw[0x1b]=0x12;
 sae_raw[0x1e0]=0x21;sae_raw[0x1e1]=0x43;sae_raw[0x1e4]=0x12;sae_raw[0x1e8]=0x1f;
 sae_raw[0x1ec]=8;memcpy(sae_raw+0x1f0,"password",8);
 assert(AirportWCL::decodeJoin(sae_raw,sizeof(sae_raw),decoded));
 assert(decoded.keyCipher==10&&decoded.upperAuth==0x1000&&decoded.extendedAuth==0x12345678);
 assert(decoded.joinFlags==0x4321&&decoded.securityFlags==0x12&&decoded.keyFlags==0x1f);
 assert(decoded.extendedPasswordLength==8&&!memcmp(decoded.extendedPassword,"password",8));
 assert(AirportWCL::isSAEPassword(decoded));
 sae_raw[0x1ec]=33;assert(!AirportWCL::decodeJoin(sae_raw,sizeof(sae_raw),decoded));
 puts("PASS real WCL joins: SAE-only auth/RSN inference, dual credentials, PSK fallback, native ABI bounds and secret cleanup.");
}
'''

ioctl_source = (ROOT / "mtk80211/openbsd/net80211/ieee80211_ioctl.c").read_text()
start = ioctl_source.index("int\nieee80211_ioctl_setwpaparms(")
end = ioctl_source.index("\nint\nieee80211_ioctl_getwpaparms", start)
actual_setwpaparms = ioctl_source[start:end].replace("ieee80211_ioctl_setwpaparms", "actual_setwpaparms")

with tempfile.TemporaryDirectory(prefix="mtk-wcl-security-") as directory:
    source = Path(directory) / "test.cpp"
    source.write_text(STUB.replace('#include <cassert>', '#include <cassert>\n#include <initializer_list>') + actual_setwpaparms + method("clearWCLSae") + method("startWCLJoin") + MAIN)
    binary = source.with_suffix("")
    subprocess.run(["clang++", "-std=c++14", "-I", str(WCL), "-fsanitize=" + os.environ.get("MTK_TEST_SANITIZERS", "address,undefined"),
                    "-fno-sanitize-recover=all", str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
