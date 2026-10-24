"""Extract the production detach body; mock resources and verify ordering."""
from pathlib import Path
import subprocess
import tempfile

b = Path(__file__).resolve().parents[2]
src = (b/'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text()
body = src.split('MtkMwx::detach(IOPCIDevice *device)\n{', 1)[1].split('\n}\n', 1)[0]
pre = r'''
#include <cassert>
#include <vector>
#include <algorithm>
#include <cstdio>
#define MWX_LOG(...) ((void)0)
#define IFF_RUNNING 1
#define MT_WFDMA0_HOST_INT_ENA 0
#define IEEE80211_S_INIT 0
struct IOPCIDevice {};
struct Soft;
struct ifnet { int if_flags=0; Soft *owner=nullptr; };
struct IC { ifnet ic_if; Soft *owner=nullptr; };
struct IOLock { Soft *owner=nullptr; bool held=false; };
struct Soft {
 IC sc_ic;
 bool sc_detaching=false,sc_net_attached=false;
 bool sc_rx_amsdu_teardown=false,sc_rx_amsdu_irq_quiesced=false;
 void *sc_reset_to=nullptr,*sc_nswq=nullptr,*sc_ih=nullptr;
 void *initial_irq=nullptr;
 int sc_memh=0,sc_st=0,sc_mems=0;
 int (*sc_newstate)(IC*,int,int)=nullptr;
 IOLock mutex; IOLock *sc_rx_amsdu_lock=&mutex;
 Soft(){sc_ic.owner=this;sc_ic.ic_if.owner=this;mutex.owner=this;}
};
struct PCI { int pa_pc=0; };
std::vector<int> events;
void *systq=(void*)1;
Soft *active=nullptr;
int index(int n){auto it=std::find(events.begin(),events.end(),n);return it==events.end()?-1:it-events.begin();}
unsigned count(int n){return std::count(events.begin(),events.end(),n);}
void taskq_destroy(void *q) { if(q) events.push_back(8); }
void taskq_quiesce(void *q) { if(q){assert(active->sc_rx_amsdu_teardown);events.push_back(2);} }
void timeout_del(void**) {assert(active->sc_rx_amsdu_teardown);events.push_back(1);}
void timeout_free(void**) {events.push_back(4);}
void mwx_rx_amsdu_begin_teardown(Soft *sc) {
 assert(sc==active&&sc->sc_detaching&&!sc->sc_rx_amsdu_teardown);
 assert(sc->sc_ih==sc->initial_irq);sc->sc_rx_amsdu_teardown=true;events.push_back(13);
}
void mwx_stop_internal(ifnet *ifp,bool bypass) {
 Soft *sc=ifp->owner;
 assert(bypass&&sc->sc_detaching&&sc->sc_rx_amsdu_teardown);
 assert(index(2)>=0&&index(5)==-1&&index(17)==-1);
 assert(sc->sc_ih==sc->initial_irq&&!sc->sc_rx_amsdu_irq_quiesced);
 events.push_back(3);
}
void pci_intr_disestablish(int,void *irq) {
 assert(active->sc_ih==irq&&irq&&active->sc_rx_amsdu_teardown);
 assert(index(2)>=0&&index(4)>=0&&index(17)==-1);events.push_back(5);
}
void IOLockLock(IOLock *lock) {
 assert(lock&&!lock->held&&lock->owner==active);
 assert(!active->sc_ih&&active->sc_rx_amsdu_teardown);
 lock->held=true;events.push_back(14);
}
void IOLockUnlock(IOLock *lock) {
 assert(lock&&lock->held&&lock->owner->sc_rx_amsdu_irq_quiesced);
 lock->held=false;events.push_back(15);
}
void mwx_rx_amsdu_purge(Soft *sc) {
 assert(!sc->sc_ih&&sc->sc_rx_amsdu_teardown);
 assert(!sc->sc_rx_amsdu_lock||(!sc->sc_rx_amsdu_lock->held&&sc->sc_rx_amsdu_irq_quiesced));
 events.push_back(16);
}
int newstate(IC *ic,int state,int arg) {
 Soft *sc=ic->owner;
 assert(state==IEEE80211_S_INIT&&arg==-1);
 assert(sc->sc_net_attached&&sc->sc_rx_amsdu_teardown);
 assert(!sc->sc_ih&&sc->sc_rx_amsdu_irq_quiesced&&!sc->mutex.held);
 assert(index(16)>=0&&index(7)==-1&&count(17)==0);events.push_back(17);return 0;
}
void mwx_write(Soft*,int,int) {events.push_back(6);}
void mwx_dma_disable(Soft*,int) {events.push_back(6);}
void ieee80211_ifdetach(ifnet *ifp) {
 Soft *sc=ifp->owner;
 assert(!sc->sc_ih&&sc->sc_rx_amsdu_irq_quiesced&&!sc->mutex.held);
 assert(index(16)>=0&&(!sc->sc_newstate||count(17)==1));events.push_back(7);
}
void mwx_txwi_free(Soft*) {events.push_back(9);}
void mwx_dma_free(Soft*) {events.push_back(10);}
void bus_space_unmap(int,int,int) {events.push_back(11);}
class MtkMwx {public: Soft *com=nullptr; PCI *pci=nullptr; bool taskQueueOwned=false;
void releaseAll(){assert(!com||!com->mutex.held);events.push_back(12);delete com;com=nullptr;delete pci;pci=nullptr;active=nullptr;}
void detach(IOPCIDevice*);
};
'''
post = r'''
int main(){
 for(int mask=0;mask<16;mask++) {
  events.clear();MtkMwx h;h.com=new Soft;h.pci=new PCI;h.taskQueueOwned=true;active=h.com;
  h.com->sc_memh=(mask&1)?1:0;h.com->sc_ih=(mask&2)?(void*)2:nullptr;h.com->initial_irq=h.com->sc_ih;
  h.com->sc_net_attached=mask&4;h.com->sc_nswq=(void*)3;h.com->sc_newstate=newstate;
  h.com->sc_ic.ic_if.if_flags=(mask&8)?IFF_RUNNING:0;
  h.detach(nullptr); assert(!h.com&&!h.pci&&!h.taskQueueOwned);
  assert(count(13)==1&&index(13)<index(1)&&index(13)<index(2));
  assert(index(2)<index(9)&&index(4)<index(9)&&index(8)<index(9)&&index(10)<index(12));
  assert(count(14)==1&&count(15)==1&&count(16)==1);
  assert(index(4)<index(14)&&index(14)<index(15)&&index(15)<index(16)&&index(16)<index(9));
  if(mask&1){assert(index(6)<index(9)&&index(10)<index(11));}else assert(index(11)==-1);
  if(mask&2)assert(index(5)<index(14));else assert(index(5)==-1);
  assert((index(7)>=0)==bool(mask&4));assert((index(17)>=0)==bool(mask&4));
  if(mask&4)assert(index(16)<index(17)&&index(17)<index(7));
  assert((index(3)>=0)==bool(mask&8));
  if(mask&8)assert(index(2)<index(3)&&index(3)<index(4));
  events.clear();h.detach(nullptr);assert(events.size()==1&&events[0]==12);
 }
 // A partial attach can have no RX mutex, IRQ, net80211 or state callback.
 {events.clear();MtkMwx h;h.com=new Soft;h.pci=new PCI;active=h.com;h.com->sc_rx_amsdu_lock=nullptr;
  h.detach(nullptr);assert(index(13)>=0&&index(16)>=0&&index(14)==-1&&index(15)==-1&&index(17)==-1&&index(7)==-1);}
 // The callback itself can be absent even if net80211 was attached.
 {events.clear();MtkMwx h;h.com=new Soft;h.pci=new PCI;active=h.com;h.com->sc_net_attached=true;
  h.detach(nullptr);assert(index(17)==-1&&index(16)<index(7));}
 MtkMwx h;h.taskQueueOwned=true;events.clear();h.detach(nullptr);assert(!h.taskQueueOwned&&events[0]==8);
 puts("PASS actual HAL detach body (UBSan): 16 partial/full combinations and repeated detach; cancel before quiesce, bypass stop before IRQ removal, locked irq_quiesced publication, purge then INIT before ifdetach, null mutex/callback partial attach, timer/queue-before-buffer order. Mocks do not prove kernel scheduling.");
}
'''
with tempfile.TemporaryDirectory() as d:
    out = Path(d)
    f = out/'test-detach.cpp'
    f.write_text(pre+'void MtkMwx::detach(IOPCIDevice *device)\n{'+body+'\n}\n'+post)
    subprocess.run(['clang++', '-std=c++14', '-fsanitize=undefined',
                    '-fno-sanitize-recover=all', '-g', str(f), '-o', str(out/'test-detach')], check=True)
    subprocess.run([str(out/'test-detach')], check=True, timeout=15)
