#!/usr/bin/env python3
"""Actual mwx_rx and crypto helpers; bounded fill_rx hardware-removal stub."""
from pathlib import Path
import ast,re,subprocess,tempfile
root=Path(__file__).resolve().parents[2]
fixture=ast.parse((root/'tests/rx-input/test-rx-amsdu-metadata.py').read_text())
pre=next(ast.literal_eval(n.value) for n in fixture.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='pre' for t in n.targets))
pre=pre.replace('#include <cassert>', '#include <cassert>\n#include <atomic>\n#include <mutex>\n#include <thread>')
pre=pre.replace('static unsigned live=0,alloc_calls=0,copy_calls=0;', 'static std::atomic<unsigned> live{0},alloc_calls{0},copy_calls{0};')
pre=pre.replace('Packet','mbuf').replace('static int alloc_mode=0,fail_copy=0;','static int alloc_mode=0,fail_copy=0;\nstatic unsigned fail_alloc_at=0;')
pre=pre.replace('if(alloc_mode==1)return ENOMEM;', 'if(alloc_mode==1||alloc_calls==fail_alloc_at)return ENOMEM;')
def extract(path,name):
 s=path.read_text();m=re.search(r'(?m)^(?:static\s+)?(?:void|mbuf_t|int|bool|IOReturn|uint32_t|MtkRxAmsduStats|struct mbuf \*)\n'+name+r'\(',s);assert m,name
 a=s.index('{',m.start());pos=a+1;depth=1
 while depth:
  depth+=(s[pos]=='{')-(s[pos]=='}');pos+=1
 return s[m.start():pos]
metadata=root/'SimpleMtkWlan/hal_mwx/RxAmsduMetadata.hpp';assembler=root/'SimpleMtkWlan/hal_mwx/RxAmsduReassembly.hpp'
regs=(root/'SimpleMtkWlan/hal_mwx/if_mwxreg.h').read_text();defs=[]
for name in sorted(set(re.findall(r'\bMT_RXD\w+',metadata.read_text()))):
 m=re.search(r'^#define\s+'+name+r'\s+([^\n]+)',regs,re.M);assert m,name;defs.append('#define '+name+' '+m.group(1))
before=r'''
using u_int8_t=uint8_t;using u_int64_t=uint64_t;using caddr_t=char*;
#define mtod(m,t) ((t)mbuf_data(m))
#define m_freem mbuf_freem
#define MWX_DEV_LOG(...) ((void)0)
#define NBPFILTER 0
#define IEEE80211_FC1_PROTECTED 0x40
#define IEEE80211_FC0_TYPE_MASK 0x0c
#define IEEE80211_FC0_SUBTYPE_MASK 0xf0
#define IEEE80211_FC0_TYPE_DATA 0x08
#define IEEE80211_FC0_TYPE_CTL 0x04
#define IEEE80211_FC0_SUBTYPE_BAR 0x80
#define IEEE80211_S_RUN 4
#define IEEE80211_RXI_HWDEC 1
#define IEEE80211_RXI_HWDEC_SAME_PN 2
#define IEEE80211_CIPHER_CCMP 3
#define IEEE80211_CIPHER_TKIP 2
#define IEEE80211_CCMP_HDRLEN 8
#define IEEE80211_TKIP_HDRLEN 8
#define IEEE80211_WEP_EXTIV 0x20
#define IEEE80211_QOS_TID 0x0f
struct ieee80211_rxinfo {int rxi_flags=0,rxi_chan=0,rxi_rssi=0;};
struct ieee80211_frame {uint8_t i_fc[2],duration[2],i_addr1[6],i_addr2[6],i_addr3[6],seqctl[2];};
struct ieee80211_node{};struct mbuf_list{};
struct ifnet{unsigned if_ierrors=0;};
struct ieee80211com {ifnet ic_if;int ic_state=4,ic_max_rssi=0;struct{unsigned is_ccmp_replays=0,is_tkip_replays=0;}ic_stats;};
struct ieee80211_key{int k_cipher=IEEE80211_CIPHER_CCMP;uint64_t k_rsc[16]={},k_mgmt_rsc=0;};
static ieee80211_key key;static ieee80211_node node;
static ieee80211_key*ieee80211_get_rxkey(ieee80211com*,mbuf_t,ieee80211_node*){return &key;}
static int ieee80211_get_hdrlen(ieee80211_frame*){return 26;}
static bool ieee80211_has_qos(ieee80211_frame*wh){return (wh->i_fc[0]&0x80)!=0;}
static uint8_t ieee80211_get_qos(ieee80211_frame*wh){return ((uint8_t*)wh)[24];}
static int ieee80211_tkip_get_tsc(uint64_t*,uint64_t**,mbuf_t,ieee80211_key*){assert(false);return EINVAL;}
static size_t mbuf_maxlen(mbuf_t m){return m->storage.size();}
static mbuf_t mbuf_nextpkt(mbuf_t){return nullptr;}
'''
after=r'''
struct IOLock {std::mutex mutex;};
static IOLock test_lock;static thread_local IOLock* held_lock=nullptr;
static std::atomic<unsigned> lock_calls{0},unlock_calls{0},helper_calls{0};
static void IOLockLock(IOLock*l){assert(l&&held_lock==nullptr);l->mutex.lock();held_lock=l;++lock_calls;}
static void IOLockUnlock(IOLock*l){assert(l&&held_lock==l);held_lock=nullptr;++unlock_calls;l->mutex.unlock();}
static void mtkRxAmsduPurge(MtkRxAmsduState&s,int tid=-1){assert(held_lock);++helper_calls;mtkRxAmsduPurgeImpl(s,tid);}
static void mtkRxAmsduExpire(MtkRxAmsduState&s,uint64_t t){assert(held_lock);++helper_calls;mtkRxAmsduExpireImpl(s,t);}
static mbuf_t mtkRxAmsduFeed(MtkRxAmsduState&s,mbuf_t m,const MtkRxAmsduMeta&md,uint64_t t,MtkRxAmsduMeta*first){assert(held_lock);++helper_calls;return mtkRxAmsduFeedImpl(s,m,md,t,first);}
struct mwx_softc {bool sc_rx_amsdu_teardown=false;uint32_t sc_rx_amsdu_transition_depth=0;IOLock*sc_rx_amsdu_lock=&test_lock;ieee80211com sc_ic;bool sc_rx_amsdu_enabled=true;uint32_t sc_rx_amsdu_epoch=1;MtkRxAmsduState sc_rx_amsdu_state{};unsigned sc_rx_fill_fail=0,sc_rx_delivered=0;};
using IOReturn=int;struct OSObject{};constexpr int kIOReturnSuccess=0;
struct MwxRxAmsduBarrier {mwx_softc*sc;int operation;bool finished,accepted;};
static std::recursive_mutex main_gate;static thread_local unsigned gate_depth=0;
struct TestGateScope {TestGateScope(){assert(!held_lock);main_gate.lock();++gate_depth;}~TestGateScope(){assert(gate_depth&&!held_lock);--gate_depth;main_gate.unlock();}};
static unsigned mwx_rx_ctl_cnt=0,mwx_rx_bar_cnt=0,mwx_rx_hwdec_cnt=0,mwx_rx_swdec_cnt=0,fill_calls=0,refs=0;
static std::atomic<uint64_t> now_ms{1};
static uint64_t mach_absolute_time(){return now_ms.load()*1000000;}
static void absolutetime_to_nanoseconds(uint64_t t,uint64_t*p){*p=t;}
static int mwx_dbm_to_rssi(int r){return r+100;}
static ieee80211_node*ieee80211_find_rxnode(ieee80211com*,ieee80211_frame*){assert(!held_lock);++refs;return &node;}
static void ieee80211_release_node(ieee80211com*,ieee80211_node*){assert(!held_lock&&refs);--refs;}
struct Delivery{mbuf_t packet;ieee80211_rxinfo rxi;};static std::vector<Delivery> deliveries;
static void ieee80211_inputm(ifnet*,mbuf_t m,ieee80211_node*,ieee80211_rxinfo*rxi,mbuf_list*){assert(!held_lock&&gate_depth);deliveries.push_back({m,*rxi});}
static int fill_mode=0,fill_rssi=-33;
static void(*fill_hook)(mwx_softc*)=nullptr;
// This bounded stub models only the unchanged hardware descriptor removal and
// Protected clearing of mt7921_mac_fill_rx. Actual integrated mwx_rx is below.
static int mt7921_mac_fill_rx(mwx_softc*sc,mbuf_t m,ieee80211_rxinfo*rxi){
 assert(!held_lock);++fill_calls;if(fill_hook){auto hook=fill_hook;fill_hook=nullptr;hook(sc);}if(fill_mode==1)return -1;auto*p=(uint8_t*)mbuf_data(m);if(m->len<24)return -1;
 uint32_t d1=mtkRxAmsduLe32(p+4),d2=mtkRxAmsduLe32(p+8);size_t gap=24;
 if(d1&MT_RXD1_NORMAL_GROUP_4)gap+=16;if(d1&MT_RXD1_NORMAL_GROUP_1)gap+=16;if(d1&MT_RXD1_NORMAL_GROUP_2)gap+=8;if(d1&MT_RXD1_NORMAL_GROUP_3){gap+=8;if(d1&MT_RXD1_NORMAL_GROUP_5)gap+=72;}gap+=2*((d2>>14)&3);
 if(m->len<gap+26)return -1;mbuf_adj(m,gap);auto*h=(uint8_t*)mbuf_data(m);bool hw=((d1>>16)&31)!=0&&!(d1&(MT_RXD1_NORMAL_CM|MT_RXD1_NORMAL_CLM));rxi->rxi_flags=hw?IEEE80211_RXI_HWDEC:0;rxi->rxi_chan=40;rxi->rxi_rssi=fill_rssi;if(hw)h[1]&=~0x40;
 if(fill_mode==2){m->len=27;m->pklen=27;}return 0;
}
static std::vector<uint8_t> subframe(unsigned payload,unsigned marker){
 auto h=frame();std::vector<uint8_t>s(14+payload);memcpy(s.data(),h.data()+4,6);memcpy(s.data()+6,h.data()+16,6);s[12]=payload>>8;s[13]=payload;for(unsigned i=14;i<s.size();++i)s[i]=(marker+i)&255;return s;
}
static std::vector<uint8_t> raw(unsigned fmt,unsigned payload=17,unsigned marker=0,unsigned cipher=4,bool group1=true,uint64_t pn=0x060504030201ULL){
 const size_t gap=24+(group1?16:0);auto h=frame(cipher!=0);auto body=subframe(payload,marker);std::vector<uint8_t>b(gap+26+(fmt?2:0)+body.size());put32(b,4,7|(cipher<<16)|(2<<21)|(group1?MT_RXD1_NORMAL_GROUP_1:0));put32(b,12,MT_RXD3_NORMAL_U2M);put32(b,16,fmt);if(group1)for(unsigned i=0;i<6;++i)b[24+i]=pn>>(8*i);memcpy(b.data()+gap,h.data(),26);memcpy(b.data()+gap+26+(fmt?2:0),body.data(),body.size());return b;
}
static std::vector<uint8_t> body_expected(){auto a=subframe(17,0),b=subframe(18,1),c=subframe(19,2);std::vector<uint8_t>x=a;x.resize((x.size()+3)&~3,0);x.insert(x.end(),b.begin(),b.end());x.resize((x.size()+3)&~3,0);x.insert(x.end(),c.begin(),c.end());return x;}
static void reset(mwx_softc&sc){for(auto d:deliveries)mbuf_freem(d.packet);deliveries.clear();IOLockLock(sc.sc_rx_amsdu_lock);mtkRxAmsduPurge(sc.sc_rx_amsdu_state);IOLockUnlock(sc.sc_rx_amsdu_lock);assert(live==0&&refs==0);sc={};key={};now_ms=1;fill_mode=0;fill_rssi=-33;fill_hook=nullptr;fill_calls=0;alloc_calls=0;alloc_mode=0;copy_calls=0;fail_copy=0;fail_alloc_at=0;}
'''
main=r'''
static void gated_rx(mwx_softc*sc,mbuf_t m,mbuf_list*ml,uint8_t q){TestGateScope gate;mwx_rx(sc,m,ml,q);}
static void test_transition(mwx_softc*sc,int operation){TestGateScope gate;MwxRxAmsduBarrier b{sc,operation,false,false};assert(mwx_rx_amsdu_barrier_gated(nullptr,&b,nullptr,nullptr,nullptr)==0);assert(b.finished&&b.accepted);}
static void change_epoch_and_seed(mwx_softc*sc){
 test_transition(sc,1);test_transition(sc,0);
 auto b=raw(3,17,0,4,true,0x090807060504ULL);auto*m=packet(b);MtkRxDescriptorMeta md;assert(mtkRxAmsduReadDescriptor(m,md)==1);ieee80211_rxinfo ri;assert(mt7921_mac_fill_rx(sc,m,&ri)==0);assert(mtkRxAmsduRemovePad(m,md));((uint8_t*)mbuf_data(m))[1]|=0x40;
 MtkRxAmsduMeta meta{},first{};meta.epoch=mwx_rx_amsdu_epoch(sc);meta.queue=0;meta.wcid=md.wcid;meta.seqctl=md.seqctl;meta.tid=md.tid;meta.cipher=md.cipher;meta.key=md.key;meta.format=md.format;meta.hdrlen=md.hdrlen;meta.protected_frame=md.protected_frame;meta.hwdec=md.hwdec;meta.pn_valid=md.pn_valid;memcpy(meta.pn,md.pn,6);meta.rxi=ri;
 assert(!mwx_rx_amsdu_feed(sc,m,meta,now_ms,&first));assert(mwx_rx_amsdu_stats(sc).pending==1);
}
int main(){mwx_softc sc{};mbuf_list ml;
 // Three hardware fragments go through the real driver function but enter
 // net80211 only once, with first-frame metadata and one reconstructed IV.
 gated_rx(&sc,packet(raw(3,17,0)),&ml,0);assert(deliveries.empty()&&sc.sc_rx_amsdu_state.stats.pending==1);
 fill_rssi=-60;gated_rx(&sc,packet(raw(2,18,1)),&ml,0);assert(deliveries.empty());
 fill_rssi=-70;gated_rx(&sc,packet(raw(1,19,2)),&ml,0);assert(deliveries.size()==1&&live==1&&refs==0&&sc.sc_rx_delivered==1&&sc.sc_rx_amsdu_state.stats.pending==0);
 auto d=deliveries[0];auto*p=(uint8_t*)mbuf_data(d.packet);auto expected=body_expected();assert(d.rxi.rxi_rssi==-33&&d.rxi.rxi_chan==40&&d.rxi.rxi_flags==IEEE80211_RXI_HWDEC);assert(d.packet->pklen==26+8+expected.size());uint8_t iv[]={1,2,0,0xa0,3,4,5,6};assert((p[1]&0x40)&&!memcmp(p+26,iv,8)&&!memcmp(p+34,expected.data(),expected.size()));
 // The production key/PN functions operate at the existing post-reorder
 // boundary: a new PN passes, removes exactly 8 bytes, preserves the body.
 auto original=std::vector<uint8_t>(p,p+d.packet->pklen);assert(ieee80211_input_hwdecrypt(&sc.sc_ic,&node,d.packet,&d.rxi)==d.packet);assert(key.k_rsc[3]==0x060504030201ULL&&key.k_rsc[0]==0);p=(uint8_t*)mbuf_data(d.packet);assert(!(p[1]&0x40)&&d.packet->pklen==26+expected.size()&&!memcmp(p+26,expected.data(),expected.size()));
 auto replay=packet(original);auto ri=d.rxi;assert(!ieee80211_input_hwdecrypt(&sc.sc_ic,&node,replay,&ri));assert(sc.sc_ic.ic_stats.is_ccmp_replays==1&&live==1); /* failure consumed replay */
 auto newer=original;newer[26]++;auto n=packet(newer);assert(ieee80211_input_hwdecrypt(&sc.sc_ic,&node,n,&ri)==n);assert(key.k_rsc[3]==0x060504030202ULL);mbuf_freem(n);reset(sc);
 // Ordinary frame is passed once with only normal descriptor removal.
 auto normal=raw(0);gated_rx(&sc,packet(normal),&ml,0);assert(deliveries.size()==1&&deliveries[0].packet->pklen==normal.size()-40&&sc.sc_rx_amsdu_state.stats.started==0);assert(!(((uint8_t*)mbuf_data(deliveries[0].packet))[1]&0x40));reset(sc);
 // Opt-in off leaves the old path unchanged even for aggregate-shaped input.
 sc.sc_rx_amsdu_enabled=false;normal=raw(3);gated_rx(&sc,packet(normal),&ml,0);assert(deliveries.size()==1&&deliveries[0].packet->pklen==normal.size()-40&&sc.sc_rx_amsdu_state.stats.started==0);reset(sc);
 // Invalid metadata purges earlier held fragments before returning.
 gated_rx(&sc,packet(raw(3)),&ml,0);auto bad=raw(2);put32(bad,8,MT_RXD2_NORMAL_HDR_TRANS);gated_rx(&sc,packet(bad),&ml,0);assert(deliveries.empty()&&live==0&&sc.sc_rx_amsdu_state.stats.pending==0&&sc.sc_ic.ic_if.if_ierrors==1);reset(sc);
 // fill failure and post-fill short pad both purge state and consume inputs.
 for(int mode:{1,2}){gated_rx(&sc,packet(raw(3)),&ml,0);fill_mode=mode;gated_rx(&sc,packet(raw(1)),&ml,0);assert(deliveries.empty()&&live==0&&sc.sc_rx_amsdu_state.stats.pending==0&&sc.sc_ic.ic_if.if_ierrors==1);reset(sc);}
 // Protected aggregate uses one allocation; a hypothetical second failure
 // must not affect delivery because IV restoration reuses the owned buffer.
 fail_alloc_at=2;gated_rx(&sc,packet(raw(3)),&ml,0);gated_rx(&sc,packet(raw(1)),&ml,0);assert(deliveries.size()==1&&live==1&&alloc_calls==1&&sc.sc_ic.ic_if.if_ierrors==0);reset(sc);
 // Assembly allocation failure still consumes all retained and incoming data.
 fail_alloc_at=1;gated_rx(&sc,packet(raw(3)),&ml,0);gated_rx(&sc,packet(raw(1)),&ml,0);assert(deliveries.empty()&&live==0&&alloc_calls==1&&sc.sc_rx_amsdu_state.stats.allocfail==1);reset(sc);
 // Queue or association changes must never join unrelated subframes.
 gated_rx(&sc,packet(raw(3)),&ml,0);gated_rx(&sc,packet(raw(1)),&ml,1);assert(deliveries.empty()&&live==0&&sc.sc_rx_amsdu_state.stats.mismatch==1);reset(sc);
 gated_rx(&sc,packet(raw(3)),&ml,0);test_transition(&sc,1);assert(mwx_rx_amsdu_stats(&sc).pending==0&&live==0);gated_rx(&sc,packet(raw(1)),&ml,0);assert(deliveries.empty()&&live==0);test_transition(&sc,0);reset(sc);
 // Open-network frames do not receive a CCMP header.
 gated_rx(&sc,packet(raw(3,17,0,0,false)),&ml,0);gated_rx(&sc,packet(raw(1,18,1,0,false)),&ml,0);assert(deliveries.size()==1&&alloc_calls==1&&deliveries[0].rxi.rxi_flags==0);reset(sc);
 // Receive entry snapshot must reject a stale old-epoch fragment even if
 // fill_rx interleaves a key/association change and a new valid pending group.
 gated_rx(&sc,packet(raw(3)),&ml,0);fill_hook=change_epoch_and_seed;
 gated_rx(&sc,packet(raw(1)),&ml,0);assert(deliveries.empty()&&mwx_rx_amsdu_stats(&sc).pending==1&&sc.sc_rx_amsdu_epoch==2);
 gated_rx(&sc,packet(raw(1,18,1,4,true,0x090807060504ULL)),&ml,0);assert(deliveries.size()==1&&mwx_rx_amsdu_stats(&sc).pending==0);reset(sc);
 // GROUP1 may be present without encryption; it must not become valid PN.
 gated_rx(&sc,packet(raw(3,17,0,0,true)),&ml,0);gated_rx(&sc,packet(raw(1,18,1,0,true)),&ml,0);assert(deliveries.size()==1&&alloc_calls==1&&deliveries[0].rxi.rxi_flags==0);reset(sc);
 // New aggregate input is refused during transition and teardown.
 test_transition(&sc,1);gated_rx(&sc,packet(raw(3)),&ml,0);assert(deliveries.empty()&&live==0&&fill_calls==0);test_transition(&sc,0);reset(sc);
 IOLockLock(sc.sc_rx_amsdu_lock);sc.sc_rx_amsdu_teardown=true;IOLockUnlock(sc.sc_rx_amsdu_lock);gated_rx(&sc,packet(raw(3)),&ml,0);assert(deliveries.empty()&&live==0&&fill_calls==0);reset(sc);
 // Concurrent RX and thread_call-style lifecycle work share actual wrappers.
 // Fixtures use atomic ownership/clock counters, deliveries are RX-thread-only.
 std::atomic<bool>go{false};
 std::thread rx([&]{while(!go.load())std::this_thread::yield();for(unsigned i=0;i<100;++i){now_ms=10+i;auto a=raw(3,17,0,4,true,1000+i),z=raw(1,18,1,4,true,1000+i);gated_rx(&sc,packet(a),&ml,0);std::this_thread::yield();gated_rx(&sc,packet(z),&ml,0);}});
 std::thread teardown([&]{go=true;for(unsigned i=0;i<100;++i){test_transition(&sc,1);std::this_thread::yield();test_transition(&sc,0);mwx_rx_amsdu_expire(&sc,10000+i);auto stats=mwx_rx_amsdu_stats(&sc);assert(stats.pending<=16);mwx_rx_amsdu_invalid(&sc);std::this_thread::yield();}});
 rx.join();teardown.join();assert(!held_lock);mwx_rx_amsdu_purge(&sc);auto stats=mwx_rx_amsdu_stats(&sc);assert(stats.pending==0&&sc.sc_rx_amsdu_epoch==101);assert(lock_calls==unlock_calls&&helper_calls>200);reset(sc);
 puts("PASS: locked actual mwx_rx with both production helpers; first/middle/last exactly-once handoff, first RX metadata, CCMP PN and production replay/8B strip, ordinary/off paths, invalid/fill/pad/restore failures, queue/epoch isolation, open+GROUP1, 100 gate-serialized concurrent RX/transition/expire rounds and ownership");
}
'''
src=pre+'\n'+'\n'.join(defs)+'\n'+before+'\n#include "'+str(metadata)+'"\n#define mtkRxAmsduFeed mtkRxAmsduFeedImpl\n#define mtkRxAmsduPurge mtkRxAmsduPurgeImpl\n#define mtkRxAmsduExpire mtkRxAmsduExpireImpl\n#include "'+str(assembler)+'"\n#undef mtkRxAmsduFeed\n#undef mtkRxAmsduPurge\n#undef mtkRxAmsduExpire\n'+after
for name in ['mwx_rx_amsdu_barrier_gated','mwx_rx_amsdu_purge','mwx_rx_amsdu_invalid','mwx_rx_amsdu_epoch','mwx_rx_amsdu_snapshot','mwx_rx_amsdu_feed','mwx_rx_amsdu_expire','mwx_rx_amsdu_stats']:
 src+='\n'+extract(root/'SimpleMtkWlan/hal_mwx/MtkMwx.cpp',name)
src+='\n'+extract(root/'mtk80211/openbsd/net80211/ieee80211_crypto_ccmp.c','ieee80211_ccmp_get_pn')+'\n'+extract(root/'mtk80211/openbsd/net80211/ieee80211_input.c','ieee80211_input_hwdecrypt')+'\n'+extract(root/'SimpleMtkWlan/hal_mwx/MtkMwx.cpp','mwx_rx')+'\n'+main
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.cpp').write_text(src)
 subprocess.run(['clang++','-std=c++14','-fsanitize=undefined','-fno-sanitize-recover=all','-g',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
