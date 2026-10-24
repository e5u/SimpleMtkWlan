#!/usr/bin/env python3
"""Extract actual transition helpers and exercise locking/lifetime with UBSan.

The reassembly implementation is production code. Fake IOKit gates model the
public documented recursive gate/attemptAction API; this is not a kernel race
proof or a replacement for sleep/wake and rekey hardware validation.
"""
from pathlib import Path
import ast
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
production = root / 'SimpleMtkWlan/hal_mwx/MtkMwx.cpp'
source = production.read_text()
start = source.index('static bool\nmwx_rx_amsdu_tearing_down(')
end = source.index('\n\nconst uint8_t mwx_channels_2ghz[]', start)
helpers = source[start:end]
metadata_fixture = ast.parse((root / 'tests/rx-input/test-rx-amsdu-metadata.py').read_text())
pre = next(ast.literal_eval(n.value) for n in metadata_fixture.body
           if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'pre' for t in n.targets))
pre = pre.replace('#include <cassert>', '#include <cassert>\n#include <atomic>\n#include <chrono>\n#include <mutex>\n#include <thread>')
pre = pre.replace('static unsigned live=0,alloc_calls=0,copy_calls=0;',
                  'static std::atomic<unsigned> live{0},alloc_calls{0},copy_calls{0};')
pre = pre.replace('Packet', 'mbuf')
pre += r'''
static size_t mbuf_maxlen(mbuf_t m){return m->storage.size();}
static mbuf_t mbuf_nextpkt(mbuf_t){return nullptr;}
struct ieee80211_rxinfo {int flags=0;};
'''
shim = r'''
using IOReturn=int;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnCannotLock=1,kIOReturnNotPermitted=2;
struct OSObject {};
struct IOLock {std::mutex mutex;};
static thread_local IOLock* held_mutex=nullptr;
static thread_local unsigned gate_depth=0;
static thread_local bool barrier_purge=false;
static std::atomic<unsigned> mutex_locks{0},mutex_unlocks{0},purges{0},feeds{0},sleeps{0};
static void IOLockLock(IOLock*l){assert(l&&!held_mutex);l->mutex.lock();held_mutex=l;++mutex_locks;}
static void IOLockUnlock(IOLock*l){assert(l==held_mutex);held_mutex=nullptr;++mutex_unlocks;l->mutex.unlock();}
static void IOSleep(unsigned ms){assert(!held_mutex);++sleeps;std::this_thread::sleep_for(std::chrono::milliseconds(ms));}
struct IOWorkLoop {
 using Action=IOReturn(*)(OSObject*,void*,void*,void*,void*);
 std::recursive_mutex gate;
 std::atomic<unsigned> actions{0},active{0};
 IOReturn runAction(Action action,OSObject*target,void*a=nullptr,void*b=nullptr,void*c=nullptr,void*d=nullptr){
  assert(!held_mutex);std::lock_guard<std::recursive_mutex> lock(gate);++gate_depth;++actions;++active;
  IOReturn rv=action(target,a,b,c,d);--active;--gate_depth;return rv;
 }
};
struct IOCommandGate {
 IOWorkLoop*loop;std::atomic<bool>enabled{true};std::atomic<unsigned>attempts{0};
 explicit IOCommandGate(IOWorkLoop*l):loop(l){}
 IOWorkLoop*getWorkLoop(){return loop;}
 IOReturn attemptAction(IOWorkLoop::Action action,void*a=nullptr,void*b=nullptr,void*c=nullptr,void*d=nullptr){
  assert(!held_mutex);++attempts;std::unique_lock<std::recursive_mutex> lock(loop->gate,std::try_to_lock);
  if(!lock.owns_lock())return kIOReturnCannotLock;
  if(!enabled)return kIOReturnNotPermitted;
  ++gate_depth;bool old=barrier_purge;barrier_purge=true;
  IOReturn rv=action(nullptr,a,b,c,d);barrier_purge=old;--gate_depth;return rv;
 }
};
static void mtkRxAmsduPurge(MtkRxAmsduState&s,int tid=-1){assert(held_mutex);if(barrier_purge)assert(gate_depth);++purges;mtkRxAmsduPurgeImpl(s,tid);}
static void mtkRxAmsduExpire(MtkRxAmsduState&s,uint64_t t){assert(held_mutex);mtkRxAmsduExpireImpl(s,t);}
static mbuf_t mtkRxAmsduFeed(MtkRxAmsduState&s,mbuf_t m,const MtkRxAmsduMeta&md,uint64_t t,MtkRxAmsduMeta*first){assert(held_mutex);++feeds;return mtkRxAmsduFeedImpl(s,m,md,t,first);}
struct mwx_softc {
 IOLock*sc_rx_amsdu_lock=nullptr;IOCommandGate*sc_rx_amsdu_gate=nullptr;
 uint32_t sc_rx_amsdu_transition_depth=0;bool sc_rx_amsdu_teardown=false,sc_rx_amsdu_irq_quiesced=false;
 MtkRxAmsduState sc_rx_amsdu_state{};uint32_t sc_rx_amsdu_epoch=1;bool sc_rx_amsdu_enabled=true;
};
'''
main = r'''
struct Fixture {
 IOLock mutex;IOWorkLoop loop;IOCommandGate gate{&loop};mwx_softc sc;
 Fixture(){sc.sc_rx_amsdu_lock=&mutex;sc.sc_rx_amsdu_gate=&gate;assert(!held_mutex&&!gate_depth&&live==0);}
 ~Fixture(){mwx_rx_amsdu_purge(&sc);assert(live==0&&!held_mutex&&!gate_depth);}
};
static void wait_true(std::atomic<bool>&flag){auto limit=std::chrono::steady_clock::now()+std::chrono::seconds(2);while(!flag.load()){assert(std::chrono::steady_clock::now()<limit);std::this_thread::yield();}}
static void wait_attempt(IOCommandGate&gate,unsigned count){auto limit=std::chrono::steady_clock::now()+std::chrono::seconds(2);while(gate.attempts.load()<=count){assert(std::chrono::steady_clock::now()<limit);std::this_thread::yield();}}
static MtkRxAmsduMeta meta(mwx_softc*sc,unsigned fmt=3){MtkRxAmsduMeta md{};md.epoch=mwx_rx_amsdu_epoch(sc);md.format=fmt;md.hdrlen=26;md.tid=3;md.seqctl=0x1240;md.wcid=7;return md;}
static mbuf_t input(){auto h=frame(false);std::vector<uint8_t>b(26+14+8);memcpy(b.data(),h.data(),26);memcpy(b.data()+26,h.data()+4,6);memcpy(b.data()+32,h.data()+16,6);b[39]=8;return packet(b);}
static void seed(mwx_softc*sc){auto md=meta(sc);assert(!mwx_rx_amsdu_feed(sc,input(),md,1,nullptr));assert(mwx_rx_amsdu_stats(sc).pending==1);}
static bool key_operation(mwx_softc*sc,unsigned&calls,bool early=false){MwxRxAmsduTransition transition(sc);if(!transition.ok())return false;assert(!held_mutex);if(early)return true;++calls;return true;}
static IOReturn recursive_action(OSObject*,void*arg,void*,void*,void*){
 auto*sc=(mwx_softc*)arg;unsigned initial=gate_depth;assert(initial==1);{
  MwxRxAmsduTransition a(sc);assert(a.ok()&&gate_depth==initial);{
   MwxRxAmsduTransition b(sc);assert(b.ok()&&sc->sc_rx_amsdu_transition_depth==2&&gate_depth==initial);
  }assert(sc->sc_rx_amsdu_transition_depth==1);
 }assert(!sc->sc_rx_amsdu_transition_depth&&gate_depth==initial);return 0;
}
struct Hold {std::atomic<bool>entered{false},release{false};};
static IOReturn hold_action(OSObject*,void*arg,void*,void*,void*){auto*h=(Hold*)arg;h->entered=true;wait_true(h->release);return 0;}
struct ActiveRx:Hold {mwx_softc*sc;bool completed=false;};
static IOReturn active_rx_action(OSObject*,void*arg,void*,void*,void*){
 auto*h=(ActiveRx*)arg;auto md=meta(h->sc,1);auto*out=mwx_rx_amsdu_feed(h->sc,input(),md,1,nullptr);assert(out);h->entered=true;wait_true(h->release);
 // A teardown cannot purge/change epoch until this already-running RX leaves
 // its gate. No key mutation or final ifdetach can run in this window.
 assert(md.epoch==mwx_rx_amsdu_epoch(h->sc));assert(!held_mutex);mbuf_freem(out);h->completed=true;return 0;
}
static void test_nested_and_feed(){Fixture f;uint32_t epoch=0;assert(mwx_rx_amsdu_snapshot(&f.sc,&epoch)&&epoch==1);seed(&f.sc);unsigned p=purges;{
 MwxRxAmsduTransition a(&f.sc);assert(a.ok()&&f.sc.sc_rx_amsdu_transition_depth==1&&f.sc.sc_rx_amsdu_epoch==2);assert(purges==p+1&&live==0);assert(!mwx_rx_amsdu_snapshot(&f.sc,&epoch)&&epoch==2);
 auto md=meta(&f.sc);unsigned n=feeds;assert(!mwx_rx_amsdu_feed(&f.sc,input(),md,2,nullptr)&&live==0&&feeds==n);
 {MwxRxAmsduTransition b(&f.sc);assert(b.ok()&&f.sc.sc_rx_amsdu_transition_depth==2&&f.sc.sc_rx_amsdu_epoch==3);}assert(f.sc.sc_rx_amsdu_transition_depth==1);
 unsigned ops=0;assert(key_operation(&f.sc,ops,true)&&ops==0&&f.sc.sc_rx_amsdu_transition_depth==1);
 }assert(mwx_rx_amsdu_snapshot(&f.sc,&epoch)&&epoch==4&&f.sc.sc_rx_amsdu_transition_depth==0);
 auto stale=meta(&f.sc);--stale.epoch;assert(!mwx_rx_amsdu_feed(&f.sc,input(),stale,3,nullptr)&&live==0);seed(&f.sc);
 auto md=meta(&f.sc,1);auto*out=mwx_rx_amsdu_feed(&f.sc,input(),md,4,nullptr);assert(out&&live==1&&mwx_rx_amsdu_stats(&f.sc).pending==0);mbuf_freem(out);
 assert(!mwx_rx_amsdu_barrier(&f.sc,0));f.sc.sc_rx_amsdu_transition_depth=UINT32_MAX;unsigned before=f.sc.sc_rx_amsdu_epoch;{MwxRxAmsduTransition guard(&f.sc);assert(!guard.ok());}assert(f.sc.sc_rx_amsdu_epoch==before);f.sc.sc_rx_amsdu_transition_depth=0;
}
static void test_recursive_and_partial(){Fixture f;assert(f.loop.runAction(recursive_action,nullptr,&f.sc)==0);assert(f.sc.sc_rx_amsdu_epoch==3);
 unsigned calls=0;f.sc.sc_rx_amsdu_enabled=false;assert(key_operation(&f.sc,calls)&&calls==1&&f.sc.sc_rx_amsdu_epoch==3);mwx_rx_amsdu_begin_teardown(&f.sc);assert(!key_operation(&f.sc,calls)&&calls==1);
 mwx_softc partial;assert(!mwx_rx_amsdu_tearing_down(&partial));mwx_rx_amsdu_purge(&partial);mwx_rx_amsdu_begin_teardown(&partial);assert(!mwx_rx_amsdu_key_cleanup_only(&partial));{MwxRxAmsduTransition guard(&partial);assert(!guard.ok());}
 partial.sc_rx_amsdu_enabled=false;{MwxRxAmsduTransition guard(&partial);assert(guard.ok());}
}
static void test_disabled_gate(){Fixture f;seed(&f.sc);f.gate.enabled=false;unsigned calls=0;assert(!key_operation(&f.sc,calls)&&calls==0&&f.sc.sc_rx_amsdu_epoch==1&&mwx_rx_amsdu_stats(&f.sc).pending==1);
 mwx_rx_amsdu_begin_teardown(&f.sc);assert(f.sc.sc_rx_amsdu_teardown&&f.sc.sc_rx_amsdu_epoch==2&&live==0&&f.loop.actions==1);assert(!mwx_rx_amsdu_key_cleanup_only(&f.sc));
 IOLockLock(&f.mutex);f.sc.sc_rx_amsdu_irq_quiesced=true;IOLockUnlock(&f.mutex);assert(mwx_rx_amsdu_key_cleanup_only(&f.sc));assert(!key_operation(&f.sc,calls)&&calls==0);
 {MwxRxAmsduTransition owner(&f.sc,true);assert(owner.ok());}assert(f.sc.sc_rx_amsdu_epoch==2);
}
static void test_cancellation_while_owner_holds_gate(){Fixture f;Hold h;std::atomic<bool>worker_done{false};unsigned operations=0;unsigned attempts=f.gate.attempts;
 std::thread owner([&]{std::lock_guard<std::recursive_mutex> lock(f.loop.gate);++gate_depth;h.entered=true;wait_true(h.release);mwx_rx_amsdu_begin_teardown(&f.sc);wait_true(worker_done);--gate_depth;});wait_true(h.entered);
 std::thread worker([&]{assert(!key_operation(&f.sc,operations));worker_done=true;});wait_attempt(f.gate,attempts);h.release=true;wait_true(worker_done);worker.join();owner.join();assert(operations==0&&f.sc.sc_rx_amsdu_teardown&&f.sc.sc_rx_amsdu_epoch==2);
}
static void test_teardown_waits_active_rx(){Fixture f;ActiveRx rx;rx.sc=&f.sc;std::atomic<bool>done{false};unsigned p=purges;
 std::thread receive([&]{f.loop.runAction(active_rx_action,nullptr,&rx);});wait_true(rx.entered);
 std::thread detach([&]{mwx_rx_amsdu_begin_teardown(&f.sc);done=true;});auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);while(!mwx_rx_amsdu_tearing_down(&f.sc)){assert(std::chrono::steady_clock::now()<deadline);std::this_thread::yield();}
 assert(!done&&purges==p);uint32_t epoch=0;assert(!mwx_rx_amsdu_snapshot(&f.sc,&epoch)&&epoch==1);rx.release=true;receive.join();detach.join();assert(rx.completed&&done&&purges==p+1&&f.sc.sc_rx_amsdu_epoch==2&&live==0);
}
static void test_disabled_end_stays_blocked(){Fixture f;{MwxRxAmsduTransition guard(&f.sc);assert(guard.ok());f.gate.enabled=false;}uint32_t epoch;assert(!mwx_rx_amsdu_snapshot(&f.sc,&epoch)&&f.sc.sc_rx_amsdu_transition_depth==1);mwx_rx_amsdu_begin_teardown(&f.sc);assert(f.sc.sc_rx_amsdu_transition_depth==0&&f.sc.sc_rx_amsdu_teardown);}
int main(){test_nested_and_feed();test_recursive_and_partial();test_disabled_gate();test_cancellation_while_owner_holds_gate();test_teardown_waits_active_rx();test_disabled_end_stays_blocked();assert(live==0&&mutex_locks==mutex_unlocks);puts("PASS: actual transition wrappers/RAII + production reassembly; nested epochs, blocked feed, stale epoch, early return, recursive gate, disabled fail-closed/fallback, cancellable wait, active RX drain, partial attach, final key cleanup condition, exact ownership and lock ordering");}
'''
# Match lifecycle placement in the real callers; these complement runtime helper
# tests, which deliberately do not pretend to execute firmware or ifdetach.
def body(name):
    marker = source.index(name + '(')
    # Definitions use a preceding newline; skip forward declarations.
    match = re.search(r'\n' + re.escape(name) + r'\([^;]*?\)\n\{', source)
    assert match, name
    first = source.index('{', match.start()); depth = 1; end = first + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}'); end += 1
    return source[first:end]
stop = body('mwx_stop_internal')
assert 'if (!teardown_owner)\n\t\tsc->sc_newstate(ic, IEEE80211_S_INIT, -1);' in stop
assert source.count('mwx_stop_internal(ifp, true)') == 1
for name in ['mwx_newstate_task', 'mwx_setkey_task', 'mwx_delete_key', 'MtkMwx::suspend']:
    assert 'MwxRxAmsduTransition transition(sc);' in body(name), name
detach = body('MtkMwx::detach')
steps = ['mwx_rx_amsdu_begin_teardown(com)', 'taskq_quiesce(com->sc_nswq)',
         'mwx_stop_internal(ifp, true)', 'pci_intr_disestablish',
         'com->sc_rx_amsdu_irq_quiesced = true',
         'com->sc_newstate(&com->sc_ic, IEEE80211_S_INIT, -1)', 'ieee80211_ifdetach(ifp)']
positions = [detach.index(step) for step in steps]
assert positions == sorted(positions)
assert 'aggregate != 0 && !mwx_rx_amsdu_snapshot(sc, &rx_epoch)' in body('mwx_rx')
# Epoch must only change in the gated barrier, never in generic purge wrappers.
assert len(re.findall(r'\+\+sc->sc_rx_amsdu_epoch', source)) == 2
assert source.count('sc_rx_amsdu_gate = getMainCommandGate()') == 1
assembly = str(root / 'SimpleMtkWlan/hal_mwx/RxAmsduReassembly.hpp')
cpp = pre + '\n#define mtkRxAmsduPurge mtkRxAmsduPurgeImpl\n#define mtkRxAmsduFeed mtkRxAmsduFeedImpl\n#define mtkRxAmsduExpire mtkRxAmsduExpireImpl\n#include "' + assembly + '"\n#undef mtkRxAmsduPurge\n#undef mtkRxAmsduFeed\n#undef mtkRxAmsduExpire\n' + shim + helpers + main
with tempfile.TemporaryDirectory() as d:
    path = Path(d)
    (path / 'test.cpp').write_text(cpp)
    subprocess.run(['clang++', '-std=c++14', '-pthread', '-fsanitize=undefined',
                    '-fno-sanitize-recover=all', '-g', str(path / 'test.cpp'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True, timeout=15)
print('PASS: production lifecycle ordering, ordinary RX exemption, sole gated epoch increments')
