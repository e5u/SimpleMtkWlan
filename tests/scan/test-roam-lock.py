"""UBSan tests of the real WCL lock setter and net80211 roam/cache paths."""
from pathlib import Path
import subprocess
import tempfile
root=Path(__file__).resolve().parents[2]
def function(path, signature):
    text=(root/path).read_text(); start=text.index(signature); brace=text.index('{',start)
    depth=1; end=brace+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}'); end+=1
    return text[start:end]
wcl='AirportMtkWlan/WCL/WCL.cpp'
node='mtk80211/openbsd/net80211/ieee80211_node.c'
core='mtk80211/openbsd/net80211/ieee80211.c'
functions=[function(wcl,'IOReturn AirportItlwmSkywalkInterface::setWCL_SET_ROAM_LOCK('),
           function(wcl,'IOReturn AirportItlwmSkywalkInterface::applyWCLRoamLock('),
           function(core,'void\nieee80211_begin_bgscan('),
           function(core,'void\nieee80211_begin_cache_bgscan('),
           function(node,'void\nieee80211_node_switch_bss(')]
pre=r'''
#include <cstdint>
#include <cassert>
#include <cstdlib>
#define AIRPORT_WCL 1
#define IEEE80211_S_RUN 4
#define IEEE80211_S_SCAN 1
#define IEEE80211_F_RSNON 1
#define IEEE80211_F_BGSCAN 2
#define IEEE80211_F_DISABLE_BG_AUTO_CONNECT 4
#define IEEE80211_F_TX_MGMT_ONLY 8
#define IFF_DEBUG 1
#define IPL_NET 0
#define IEEE80211_STA_CACHE 0
#define XYLog(...) ((void)0)
#define DPRINTF(...) ((void)0)
#define splassert(...) ((void)0)
struct _ifnet {unsigned if_flags; const char *if_xname;};
struct ieee80211_node {void *ni_unref_arg; int ni_port_valid; int ni_chan; uint8_t ni_macaddr[6];};
struct ieee80211_node_switch_bss_arg {uint8_t sel_macaddr[6],cur_macaddr[6];};
struct ieee80211com { _ifnet ic_if; int ic_state,ic_mgt_timer; unsigned ic_flags,ic_xflags;
 bool ic_wcl_roam_locked; ieee80211_node *ic_bss; int (*ic_bgscan_start)(ieee80211com*);
 long ic_last_cache_scan_ts;};

static int scans,frees,joins,lookups,states;
static int start_scan(ieee80211com*) {++scans;return 0;}
static void ieee80211_free_allnodes(ieee80211com*,int) {++frees;}
static void microtime(timeval *tv) {tv->tv_sec=1000;}
static ieee80211_node candidate={};
static ieee80211_node *ieee80211_find_node(ieee80211com*,uint8_t*) {++lookups;return &candidate;}
static void ieee80211_new_state(ieee80211com*,int,int) {++states;}
static int ieee80211_chan2ieee(ieee80211com*,int) {return 1;}
static const char *ether_sprintf(uint8_t*) {return "";}
static void ieee80211_node_newstate(ieee80211_node*,int) {}
static void ieee80211_node_join_bss(ieee80211com*,ieee80211_node*) {++joins;}
using IOReturn=int; static const int kIOReturnBadArgument=1,kIOReturnNotReady=2,kIOReturnSuccess=0;
struct apple80211_set_roam_lock {uint8_t locked;};
struct Hal {ieee80211com ic; ieee80211com *get80211Controller(){return &ic;}};
struct AirportItlwmSkywalkInterface;
struct Gate {int calls=0; IOReturn runAction(int,AirportItlwmSkywalkInterface*,void*,void*);};
static Gate *_fCommandGate;
struct AirportItlwmSkywalkInterface {Hal *fHalService; bool wclStopping=false;
 static const int wclCommand=0;
 IOReturn setWCL_SET_ROAM_LOCK(apple80211_set_roam_lock*);
 IOReturn applyWCLRoamLock(void*);};
IOReturn Gate::runAction(int,AirportItlwmSkywalkInterface *self,void *command,void *data) {
 ++calls; assert(uintptr_t(command)==16);
 return self->wclStopping ? kIOReturnNotReady : self->applyWCLRoamLock(data);
}
'''
post=r'''
int main(){
 Hal hal={}; AirportItlwmSkywalkInterface interface{&hal}; Gate gate; _fCommandGate=&gate;
 apple80211_set_roam_lock locked={0xff}, unlocked={0};
 assert(interface.setWCL_SET_ROAM_LOCK(nullptr)==kIOReturnBadArgument);
 _fCommandGate=nullptr; assert(interface.setWCL_SET_ROAM_LOCK(&locked)==kIOReturnNotReady);
 _fCommandGate=&gate; assert(interface.setWCL_SET_ROAM_LOCK(&locked)==0);
 assert(gate.calls==1 && hal.ic.ic_wcl_roam_locked);
 assert(interface.applyWCLRoamLock(nullptr)==kIOReturnBadArgument);
 ieee80211_node current={}; current.ni_port_valid=1;
 auto &ic=hal.ic; ic.ic_state=IEEE80211_S_RUN; ic.ic_bss=&current;ic.ic_bgscan_start=start_scan;
 // Locked automatic roaming neither submits a scan nor upgrades cache scans.
 ieee80211_begin_bgscan(&ic.ic_if); assert(scans==0);
 ic.ic_flags=IEEE80211_F_BGSCAN|IEEE80211_F_DISABLE_BG_AUTO_CONNECT;
 ieee80211_begin_bgscan(&ic.ic_if);
 assert(ic.ic_flags&IEEE80211_F_DISABLE_BG_AUTO_CONNECT);
 // Cache scans remain available, and their one-shot flag cannot erase the lock.
 ic.ic_flags=0;ieee80211_begin_cache_bgscan(&ic.ic_if);
 assert(scans==1 && (ic.ic_flags&IEEE80211_F_BGSCAN) && ic.ic_wcl_roam_locked);
 ic.ic_flags=0;ieee80211_begin_cache_bgscan(&ic.ic_if);
 assert(scans==2 && ic.ic_wcl_roam_locked);
 // Locking after an automatic switch was queued prevents looking up/joining APs.
 current.ni_unref_arg=std::calloc(1,sizeof(ieee80211_node_switch_bss_arg));
 ic.ic_flags=IEEE80211_F_BGSCAN;ic.ic_xflags=IEEE80211_F_TX_MGMT_ONLY;
 ieee80211_node_switch_bss(&ic,&current);current.ni_unref_arg=nullptr;
 assert(lookups==0 && joins==0 && states==0 && ic.ic_flags==0 && ic.ic_xflags==0);
 assert(interface.setWCL_SET_ROAM_LOCK(&unlocked)==0 && !ic.ic_wcl_roam_locked);
 ieee80211_begin_bgscan(&ic.ic_if); assert(scans==3);
 current.ni_unref_arg=std::calloc(1,sizeof(ieee80211_node_switch_bss_arg));
 ieee80211_node_switch_bss(&ic,&current);
 assert(lookups==2 && joins==1);std::free(current.ni_unref_arg);
 // Shutdown rejection is enforced by the dispatcher, and explicit join has no lock guard.
 interface.wclStopping=true;
 assert(interface.setWCL_SET_ROAM_LOCK(&locked)==kIOReturnNotReady && !ic.ic_wcl_roam_locked);
}
'''
with tempfile.TemporaryDirectory(prefix='mtk-roam-lock-') as tmp:
    path=Path(tmp)/'test.cpp';path.write_text(pre+'\n'.join(functions)+post)
    binary=Path(tmp)/'test'
    subprocess.run(['clang++','-std=c++14','-fsanitize=undefined',str(path),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
# End-scan derives roam/cache behavior from the persistent lock, while explicit
# association never consults it. Assert integration in addition to the execution tests.
end_scan=function(node,'void\nieee80211_end_scan(')
assert 'roamscan = roamscan && !ic->ic_wcl_roam_locked;' in end_scan
assert 'ic_wcl_roam_locked' not in function(wcl,'IOReturn AirportItlwmSkywalkInterface::startWCLJoin(')
assert 'case 16: return self->applyWCLRoamLock(a2);' in (root/wcl).read_text()
print('PASS real WCL lock setter, automatic/cache scans, queued BSS switch, unlock and explicit-join isolation')
hal_pre=r'''
#include <cstdint>
#include <cstddef>
#include <cassert>
#include <cstdlib>
#include <cerrno>
#define AIRPORT_WCL 1
#define IEEE80211_S_RUN 4
#define IEEE80211_F_BGSCAN 2
#define IEEE80211_F_TX_MGMT_ONLY 8
#define IEEE80211_F_RSNON 16
#define IEEE80211_CIPHER_NONE 0
#define IEEE80211_CIPHER_CCMP 1
#define IEEE80211_KEY_GROUP 2
#define IEEE80211_KEY_IGTK 4
#define IEEE80211_NODE_TXRXPROT 1
#define IEEE80211_NODE_TXMGMTPROT 2
#define IEEE80211_NODE_RXMGMTPROT 4
#define IEEE80211_NODE_MFP 8
#define RSNA_SUPP_INITIALIZE 0
#define M_DEVBUF 0
struct ieee80211com;
struct ieee80211_key {int k_cipher,k_flags;};
struct ieee80211_node {
 ieee80211_key ni_pairwise_key;int ni_port_valid,ni_flags,ni_rsn_supp_state;
 void *ni_unref_arg;size_t ni_unref_arg_size;
 void (*ni_unref_cb)(ieee80211com*,ieee80211_node*);
};
struct ieee80211com {
 int ic_state;unsigned ic_flags,ic_xflags;bool ic_wcl_roam_locked;
 ieee80211_node *ic_bss;int ic_if,ic_def_txkey,ic_igtk_kid;
 ieee80211_key ic_nw_keys[6];
 void (*ic_delete_key)(ieee80211com*,ieee80211_node*,ieee80211_key*);
};
struct mwx_softc {ieee80211com sc_ic;void *sc_bgscan_arg;size_t sc_bgscan_arg_size;};
static int starts,delays,switches,key_deletes,releases;
static int splnet(){return 0;}static void splx(int){}
static void mwx_start(int*) {++starts;}static void delay(int){++delays;}
static void ieee80211_node_switch_bss(ieee80211com*,ieee80211_node*) {++switches;}
static void delete_key(ieee80211com*,ieee80211_node*,ieee80211_key*){++key_deletes;}
static void release_arg(void *arg,int,size_t){++releases;std::free(arg);}
#define free(arg,type,size) release_arg(arg,type,size)
'''
hal_post=r'''
#undef free
int main(){
 mwx_softc sc={};ieee80211_node ni={};auto &ic=sc.sc_ic;
 ic.ic_bss=&ni;ic.ic_state=IEEE80211_S_RUN;
 ic.ic_flags=IEEE80211_F_BGSCAN|IEEE80211_F_RSNON;
 ic.ic_xflags=IEEE80211_F_TX_MGMT_ONLY;ic.ic_wcl_roam_locked=true;
 ic.ic_delete_key=delete_key;ni.ni_port_valid=1;ni.ni_pairwise_key.k_cipher=IEEE80211_CIPHER_CCMP;
 sc.sc_bgscan_arg=std::malloc(12);sc.sc_bgscan_arg_size=12;
 mwx_bgscan_done_task(&sc);
 assert(releases==1 && sc.sc_bgscan_arg==nullptr && sc.sc_bgscan_arg_size==0);
 assert(starts==0 && delays==0 && switches==0 && key_deletes==0);
 assert(ni.ni_port_valid==1 && ni.ni_unref_cb==nullptr);
 assert(!(ic.ic_flags&IEEE80211_F_BGSCAN) && ic.ic_xflags==0);
 // Unlock preserves the existing queued-roam execution path.
 ic.ic_wcl_roam_locked=false;ic.ic_flags|=IEEE80211_F_BGSCAN;
 sc.sc_bgscan_arg=std::malloc(12);sc.sc_bgscan_arg_size=12;
 mwx_bgscan_done_task(&sc);
 assert(starts==1 && delays==1 && key_deletes==1 && ni.ni_port_valid==0);
 assert(ni.ni_unref_cb && ni.ni_unref_arg && sc.sc_bgscan_arg==nullptr);
 std::free(ni.ni_unref_arg);
}
'''
with tempfile.TemporaryDirectory(prefix='mtk-queued-roam-') as tmp:
    path=Path(tmp)/'test.cpp'
    path.write_text(hal_pre+function('SimpleMtkWlan/hal_mwx/MtkMwx.cpp','void\nmwx_bgscan_done_task(')+hal_post)
    binary=Path(tmp)/'test'
    subprocess.run(['clang++','-std=c++14','-fsanitize=undefined',str(path),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
print('PASS real HAL queued roam lock prevents deauth flush/key deletion and releases pending switch')
