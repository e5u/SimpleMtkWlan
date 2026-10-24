"""Execute production DMA chain/reset/free paths with exact ownership checks."""
from pathlib import Path
import runpy
support=runpy.run_path(str(Path(__file__).with_name('test-rx-copy.py')))
# Queue free can be exercised on a partial allocation with no mapped ring;
# those APIs are stubbed but its production chain-release code is unmodified.
EXTRA=r'''
#define M_DEVBUF 0
using caddr_t=char*;
static void bus_dmamap_destroy(void*,map_t*){}
static void bus_dmamem_unmap(void*,caddr_t,size_t){}
static void bus_dmamem_free(void*,segment*,int){}
static void free_stub(void*,int,size_t){}
#define free(...) free_stub(__VA_ARGS__)
'''
POST=r'''
static void consume(mbuf_list&ml){for(auto*m:ml.entries)m_freem(m);ml.entries.clear();}
static void check_chain(mbuf*m,unsigned bytes,unsigned parts){
 assert(m&&(m->flags&MBUF_PKTHDR)&&m->pklen==bytes);unsigned n=0,total=0;
 for(auto*p=m;p;p=p->next){if(n)assert(!(p->flags&MBUF_PKTHDR));++n;total+=p->len;}
 assert(n==parts&&total==bytes);
}
int main(){
 // Retain ownership across empty calls and append at wrap, with one delivery.
 {Fixture f;auto&q=f.sc.sc_rxq;q.mq_cons=7;f.packet(7,2048,false);q.dma=0;mbuf_list ml;
  mwx_dma_rx_dequeue(&f.sc,&q,&ml);auto*first=q.mq_rx_head;assert(first&&first==q.mq_rx_tail&&live==1&&ml.entries.empty());
  for(unsigned i=0;i<4;++i)mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(q.mq_rx_head==first&&f.sc.sc_rx_dma_chain_resumed==0);
  f.packet(0,2048,false);q.dma=1;mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(q.mq_rx_head==first&&q.mq_rx_bytes==4096&&q.mq_rx_segments==2);
  f.packet(1,13);q.dma=2;mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(ml.entries.size()==1&&ml.entries[0]==first);check_chain(first,4109,3);
  assert(!q.mq_rx_head&&!q.mq_rx_tail&&!q.mq_rx_bytes&&!q.mq_rx_segments&&!q.mq_rx_discard);
  assert(f.sc.sc_rx_dma_chain_completed==1&&f.sc.sc_rx_dma_chain_resumed==2);consume(ml);
  mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(ml.entries.empty()&&live==0);
 }
 // First normal descriptor needs 24 contiguous bytes; MCU/event/notify retain
 // their own variable-size parser checks. Header validation occurs after sync.
 for(unsigned type:{2U,8U})for(unsigned len:{4U,23U,24U}){
  Fixture f;auto&q=f.sc.sc_rxq;f.packet(0,len);uint32_t word=type<<27;std::memcpy(f.maps[0][0].payload,&word,4);q.dma=1;mbuf_list ml;
  mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(ml.entries.size()==unsigned(len>=24));assert(f.sc.sc_rx_dma_bad_len==unsigned(len<24));consume(ml);
 }
 // A bad continuation poisons the whole chain, including across batches.
 {Fixture f;auto&q=f.sc.sc_rxq;f.packet(0,2048,false);q.dma=1;mbuf_list ml;mwx_dma_rx_dequeue(&f.sc,&q,&ml);
  f.packet(1,0,false);q.dma=2;mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(!q.mq_rx_head&&q.mq_rx_discard&&live==0);
  f.packet(2,17,false);f.packet(3,1);f.packet(4,81);q.dma=5;mwx_dma_rx_dequeue(&f.sc,&q,&ml);
  assert(ml.entries.size()==1&&ml.entries[0]->pklen==81&&!q.mq_rx_discard);assert(copies==std::vector<size_t>({2048,81}));consume(ml);
 }
 // Maximum bytes accommodates the 16-bit MCU length plus RXD, but rejects
 // excess before bounce copy. Exercise the exact limit and one byte over.
 for(bool excess:{false,true}){
  Fixture f;auto&q=f.sc.sc_rxq;mbuf_list ml;unsigned idx=0;
  for(unsigned i=0;i<32;++i){f.packet(idx,2048,false);q.dma=(idx+1)%8;mwx_dma_rx_dequeue(&f.sc,&q,&ml);idx=q.dma;assert(ml.entries.empty());}
  assert(q.mq_rx_bytes==65536&&q.mq_rx_segments==32);
  f.packet(idx,excess?32:31);q.dma=(idx+1)%8;mwx_dma_rx_dequeue(&f.sc,&q,&ml);
  assert(ml.entries.size()==unsigned(!excess));assert(!q.mq_rx_head&&!q.mq_rx_discard);
  if(!excess)check_chain(ml.entries[0],65567,33);else assert(f.sc.sc_rx_dma_bad_len==1&&f.sc.sc_rx_dma_chain_dropped==1);
  assert(copies.size()==(excess?32U:33U));consume(ml);
 }
 // Tiny segments also have a hard segment-count bound, independent of bytes.
 for(bool excess:{false,true}){
  Fixture f;auto&q=f.sc.sc_rxq;mbuf_list ml;unsigned idx=0;
  for(unsigned i=0;i<64;++i){f.packet(idx,i==0?64:1,!excess&&i==63);q.dma=(idx+1)%8;mwx_dma_rx_dequeue(&f.sc,&q,&ml);idx=q.dma;}
  if(excess){assert(q.mq_rx_segments==64);f.packet(idx,1);q.dma=(idx+1)%8;mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(ml.entries.empty()&&f.sc.sc_rx_dma_bad_len==1);}
  else {assert(ml.entries.size()==1);check_chain(ml.entries[0],127,64);consume(ml);}
  assert(!q.mq_rx_head&&!q.mq_rx_discard&&live==0);
 }
 // Failure to demote a continuation cannot leak either fragment.
 {Fixture f;auto&q=f.sc.sc_rxq;f.packet(0,64,false);q.dma=1;mbuf_list ml;mwx_dma_rx_dequeue(&f.sc,&q,&ml);
  f.packet(1,21);fail_flag=flagcalls+1;q.dma=2;mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(ml.entries.empty()&&!q.mq_rx_head&&!q.mq_rx_discard&&live==0);}
 // Reset owns both detached prefix and the still-posted buffers, exactly once.
 {Fixture f;auto&q=f.sc.sc_rxq;f.packet(0,64,false);f.packet(1,64);q.dma=1;mbuf_list ml;mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(live==2);
  mwx_queue_reset(&f.sc,&q);assert(live==0&&!q.mq_rx_head&&!q.mq_rx_tail&&!q.mq_rx_bytes&&!q.mq_rx_segments&&!q.mq_rx_discard);
  mwx_queue_reset(&f.sc,&q);assert(live==0);
 }
 // Missing descriptor aborts a held prefix immediately before reset scheduling.
 {Fixture f;auto&q=f.sc.sc_rxq;f.packet(0,64,false);q.dma=1;mbuf_list ml;mwx_dma_rx_dequeue(&f.sc,&q,&ml);q.dma=2;
  unsigned old=resets;mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(resets==old+1&&!q.mq_rx_head&&live==0&&q.mq_rx_discard);}
 // Free on a partially constructed queue still releases detached buffers.
 {mwx_softc sc;mwx_queue q;q.mq_seg.ds_len=0;q.mq_rx_head=MCLGETL(nullptr,0,2048);q.mq_rx_tail=q.mq_rx_head;
  q.mq_rx_head->next=MCLGETL(nullptr,0,2048);q.mq_rx_tail=q.mq_rx_head->next;q.mq_rx_bytes=4096;q.mq_rx_segments=2;
  mwx_queue_free(&sc,&q);assert(live==0&&!q.mq_rx_head&&!q.mq_rx_tail&&!q.mq_rx_bytes&&!q.mq_rx_segments);mwx_queue_free(&sc,&q);}
 // Refill OOM does not discard a partial frame. The next batch completes it
 // while independent replacement slots recover under the existing retry path.
 {Fixture f;auto&q=f.sc.sc_rxq;f.packet(0,2048,false);q.mq_prod=7;q.dma=1;fail_alloc=allocs+1;
  mwx_dma_rx_done(&f.sc,&q,&f.output);assert(q.mq_rx_head&&q.mq_refill_pending&&live==1);
  fail_alloc=0;mwx_rx_refill_retry(&f.sc);assert(q.mq_rx_head&&!q.mq_refill_pending&&q.mq_prod==0);
  f.packet(1,10);q.dma=2;mwx_dma_rx_done(&f.sc,&q,&f.output);assert(!q.mq_rx_head&&delivered.size()==1);check_chain(delivered[0],2058,2);
 }
 puts("PASS production DMA cross-batch chains: empty polls, wrap, byte/segment limits, first-RXD bounds, poison-through-LAST, packet-header ownership, reset/free, missing slot, refill OOM and exact-once delivery (UBSan).");
}
'''
if __name__=='__main__':
 support['compile_run'].__globals__['PRE']+=EXTRA
 support['compile_run'](['mwx_queue_free','mwx_queue_reset','mwx_buf_fill','mwx_queue_fill','mwx_rx_refill_retry','mwx_dma_rx_dequeue','mwx_dma_rx_done'],POST)
