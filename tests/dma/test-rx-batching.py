"""Extract real IRQ/process/completion; test batching and exactly-once ownership."""
from pathlib import Path
import re
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / 'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text()
def fn(name):
    m = re.search(r'(?m)^(?:int|void|bool)\n' + name + r'\([^;]+?\)\s*\{', SRC)
    assert m, name
    pos = SRC.index('{', m.start()) + 1
    depth = 1
    while depth:
        depth += (SRC[pos] == '{') - (SRC[pos] == '}')
        pos += 1
    return SRC[m.start():pos]
PRE = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>
#include <string>
using u_int = unsigned;
#define MBUF_LIST_INITIALIZER() {}
#define MWX_DEV_LOG(...) ((void)0)
#define DEVNAME(x) "test"
#define printf(...) ((void)0)
#define le32toh(x) (x)
#define mtod(m,t) ((t)&(m)->word)
#define MT_WFDMA0_HOST_INT_ENA 1
#define MT_WFDMA0_HOST_INT_STA 2
#define MT_MCU_CMD 3
#define MT_MCU_CMD_WAKE_RX_PCIE 0x100
#define MT_INT_TX_DONE_ALL 1
#define MT_INT_RX_DONE_WM 2
#define MT_INT_RX_DONE_WM2 4
#define MT_INT_RX_DONE_DATA 8
#define MT_INT_MCU_CMD 16
#define MT_RXD0_PKT_TYPE_GET(x) ((x)&15U)
#define MT_RXD0_PKT_FLAG_MASK 0xf00U
#define MT_RXD0_PKT_FLAG_SHIFT 8
#define PKT_TYPE_RX_EVENT 1
#define PKT_TYPE_TXRX_NOTIFY 2
#define PKT_TYPE_TXS 3
#define PKT_TYPE_NORMAL_MCU 4
#define PKT_TYPE_NORMAL 5
struct mbuf { uint32_t word; unsigned id; bool drop=false,management=false; unsigned freeCount=0,delivered=0; };
struct mbuf_list { std::vector<mbuf*> entries; };
static bool ml_empty(mbuf_list *l) { return l->entries.empty(); }
static unsigned ml_len(mbuf_list *l) { return l->entries.size(); }
static void ml_enqueue(mbuf_list *l,mbuf *m) { assert(!m->freeCount&&!m->delivered);l->entries.push_back(m); }
static mbuf *ml_dequeue(mbuf_list *l) {if(ml_empty(l))return nullptr;auto*m=l->entries.front();l->entries.erase(l->entries.begin());assert(!m->freeCount&&!m->delivered);return m;}
static void m_freem(mbuf *m) { assert(!m->freeCount&&!m->delivered);++m->freeCount; }
struct mwx_queue { unsigned mq_cons=0; bool mq_refill_pending=false; std::vector<std::vector<mbuf*>> batches; unsigned fills=0; };
struct ifnet {};
struct mwx_softc {
 bool sc_suspended=false;uint32_t sc_intr_mask=31;
 struct {ifnet ic_if;} sc_ic;
 mwx_queue sc_rxfwdlq,sc_rxmcuq,sc_rxq;
 uint64_t sc_rx_input_batches=0,sc_rx_input_packets=0;
 uint32_t sc_rx_input_max_batch=0,sc_rx_process_events=0;
 uint32_t sc_rx_pkt_event=0,sc_rx_pkt_txrx_notify=0,sc_rx_pkt_normal_mcu=0,sc_rx_pkt_normal=0,sc_rx_pkt_unknown=0;
 void *sc_pc=nullptr,*sc_ih=nullptr;
 std::vector<uint32_t> status;unsigned statusRead=0,pass=0,txDone=0;
 uint32_t mcuStatus=0;std::vector<uint32_t> enables;
};
static unsigned mwx_intr_calls=0,flushes=0,reschedules=0;
static std::vector<unsigned> deliveredIds,events;
static uint32_t mwx_read(mwx_softc *s,uint32_t reg) {
 if(reg==MT_MCU_CMD)return s->mcuStatus;
 assert(reg==MT_WFDMA0_HOST_INT_STA);
 s->pass=s->statusRead++;return s->pass<s->status.size()?s->status[s->pass]:0;
}
static void mwx_write(mwx_softc*s,uint32_t reg,uint32_t value) {if(reg==MT_WFDMA0_HOST_INT_ENA)s->enables.push_back(value);}
static void mwx_dma_tx_done(mwx_softc*s){++s->txDone;}
static bool mwx_dma_rx_dequeue(mwx_softc*s,mwx_queue*q,mbuf_list*l){
 if(s->pass>=q->batches.size())return false;
 auto &batch=q->batches[s->pass];unsigned quota=std::min<unsigned>(64,batch.size());
 for(unsigned i=0;i<quota;++i){ml_enqueue(l,batch[i]);++q->mq_cons;}
 batch.erase(batch.begin(),batch.begin()+quota);return !batch.empty();
}
static int mwx_queue_fill(mwx_softc*,mwx_queue*q){++q->fills;q->mq_refill_pending=false;return 0;}
static void mwx_mcu_rx_event(mwx_softc*,mbuf*m){events.push_back(m->id);m_freem(m);}
static void mwx_mac_tx_free(mwx_softc*,mbuf*m){events.push_back(m->id);m_freem(m);}
static void pci_intr_reschedule(void*,void*){++reschedules;}
static void mwx_rx(mwx_softc*,mbuf*m,mbuf_list*l,uint8_t){
 if(m->drop){m_freem(m);return;}
 if(m->management){events.push_back(m->id);m_freem(m);return;}
 ml_enqueue(l,m);
}
static int if_input(ifnet*,mbuf_list*l){
 assert(!ml_empty(l));++flushes;events.push_back(999);
 while(auto*m=ml_dequeue(l)){++m->delivered;deliveredIds.push_back(m->id);}
 return 0;
}
struct Fixture {
 mwx_softc sc;std::vector<mbuf*> owned;
 Fixture(){flushes=0;deliveredIds.clear();events.clear();reschedules=0;}
 mbuf* packet(unsigned id,unsigned type=PKT_TYPE_NORMAL,bool drop=false,bool management=false){auto*m=new mbuf{type,id,drop,management};owned.push_back(m);return m;}
 ~Fixture(){for(auto*m:owned){assert(m->freeCount+m->delivered==1);delete m;}}
};
'''
POST = r'''
int main(){
 // Two drain passes and all three queues share one output list. Management,
 // MCU events and TX completion are processed before the final data handoff.
 {Fixture f;auto&s=f.sc;s.status={31,14,0};
  s.sc_rxfwdlq.batches={{f.packet(1,PKT_TYPE_RX_EVENT),f.packet(2)}, {f.packet(7)}};
  s.sc_rxmcuq.batches={{f.packet(3,PKT_TYPE_TXRX_NOTIFY),f.packet(4,PKT_TYPE_NORMAL_MCU)}, {f.packet(8,PKT_TYPE_NORMAL_MCU)}};
  s.sc_rxq.batches={{f.packet(5,PKT_TYPE_NORMAL,false,true),f.packet(6)}, {f.packet(9,PKT_TYPE_NORMAL,true),f.packet(10)}};
  assert(mwx_intr(&s)==1);assert(deliveredIds==std::vector<unsigned>({2,4,6,7,8,10}));assert(reschedules==0);
  assert(events==std::vector<unsigned>({1,3,5,999}));assert(flushes==1&&s.txDone==1);
  assert(s.sc_rx_input_batches==1&&s.sc_rx_input_packets==6&&s.sc_rx_input_max_batch==6);
  assert(s.sc_rxfwdlq.fills==2&&s.sc_rxmcuq.fills==2&&s.sc_rxq.fills==2);
  assert(s.sc_rx_pkt_event==1&&s.sc_rx_pkt_txrx_notify==1&&s.sc_rx_pkt_normal_mcu==2&&s.sc_rx_pkt_normal==6);
  assert(s.enables==std::vector<uint32_t>({0,31}));
 }
 // MCU-only, TX-status and unknown events never enter an empty input gate.
 {Fixture f;auto&s=f.sc;s.status={6,0};
  s.sc_rxfwdlq.batches={{f.packet(1,PKT_TYPE_RX_EVENT),f.packet(2,PKT_TYPE_TXS)}};
  s.sc_rxmcuq.batches={{f.packet(3,PKT_TYPE_TXRX_NOTIFY),f.packet(4,15)}};
  assert(mwx_intr(&s)==1&&flushes==0&&s.sc_rx_input_batches==0&&s.sc_rx_input_packets==0);
  assert(events==std::vector<unsigned>({1,3}));assert(s.sc_rx_pkt_unknown==1);
 }
 // All data rejected by 802.11 parsing leaves no flush and no stale packets.
 {Fixture f;auto&s=f.sc;s.status={8,0};s.sc_rxq.batches={{f.packet(1,PKT_TYPE_NORMAL,true),f.packet(2,PKT_TYPE_NORMAL,true)}};
  assert(mwx_intr(&s)==1&&flushes==0&&s.sc_rxq.fills==1&&s.sc_rx_input_packets==0);
 }
 // MCU wake injects data service; RX_EVENT flag 1 is dispatched as NORMAL_MCU.
 {Fixture f;auto&s=f.sc;s.status={16,0};s.mcuStatus=MT_MCU_CMD_WAKE_RX_PCIE;
  s.sc_rxq.batches={{f.packet(1,PKT_TYPE_RX_EVENT|0x100)}};
  assert(mwx_intr(&s)==1&&flushes==1&&s.sc_rx_pkt_normal_mcu==1&&s.sc_rx_pkt_event==0);
 }
 // The existing nine-pass bound still delivers its complete batch exactly once.
 {Fixture f;auto&s=f.sc;s.status=std::vector<uint32_t>(10,8);
  for(unsigned i=0;i<9;++i)s.sc_rxq.batches.push_back({f.packet(i+1)});
  assert(mwx_intr(&s)==1&&s.statusRead==9&&flushes==1&&deliveredIds.size()==9);
  for(unsigned i=0;i<9;++i)assert(deliveredIds[i]==i+1);
 }
 // More than one RX quota schedules another work-loop item instead of
 // monopolising the shared gate, and the retained batch resumes exactly once.
 {Fixture f;auto&s=f.sc;s.status={8};s.sc_rxq.batches={std::vector<mbuf*>{}};
  for(unsigned i=0;i<65;++i)s.sc_rxq.batches[0].push_back(f.packet(i+1));
  assert(mwx_intr(&s)==1);assert(deliveredIds.size()==64&&reschedules==1&&s.sc_rxq.batches[0].size()==1);
  s.statusRead=0;s.status={8};
  assert(mwx_intr(&s)==1);assert(deliveredIds.size()==65&&reschedules==1&&s.sc_rxq.batches[0].empty());
 }
 // A second IRQ gets a fresh list; counters accumulate and maximum is preserved.
 {Fixture f;auto&s=f.sc;s.status={8,0};s.sc_rxq.batches={{f.packet(1),f.packet(2)}};
  assert(mwx_intr(&s)==1);s.statusRead=0;s.sc_rxq.batches={{f.packet(3)}};
  assert(mwx_intr(&s)==1&&flushes==2&&s.sc_rx_input_batches==2&&s.sc_rx_input_packets==3&&s.sc_rx_input_max_batch==2);
  assert(deliveredIds==std::vector<unsigned>({1,2,3}));
 }
 for(uint32_t status:{0U,0xffffffffU}){Fixture f;f.sc.status={status};assert(mwx_intr(&f.sc)==0&&flushes==0);}
 {Fixture f;f.sc.sc_suspended=true;assert(mwx_intr(&f.sc)==0&&f.sc.statusRead==0&&flushes==0);}
 puts("PASS actual RX interrupt/process/completion: multiple queues/passes, immediate MCU/management, MCU-only, all rejected, order, exactly-once ownership, wake, quota/reschedule, nine-pass bound, fresh lists/counters and early exits (UBSan).");
}
'''
with tempfile.TemporaryDirectory(prefix='rx-batching-') as tmp:
    p=Path(tmp)
    (p/'test.cpp').write_text(PRE+'\n'+fn('mwx_dma_rx_process')+'\n'+fn('mwx_dma_rx_done')+'\n'+fn('mwx_intr')+POST)
    subprocess.run(['clang++','-std=c++14','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True)
