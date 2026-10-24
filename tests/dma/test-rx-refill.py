"""Actual refill/RX completion/retry functions with allocation-failure injection."""
from pathlib import Path
import runpy
support=runpy.run_path(str(Path(__file__).with_name('test-rx-copy.py')))
POST=r'''
int main(){
 // Fail the first/middle/last allocation/map; publish exactly the good prefix.
 for(unsigned fail:{1U,3U,7U})for(bool mapfail:{false,true}){
  Fixture f;auto&q=f.sc.sc_rxq;unsigned first=mapfail?loads:allocs;
  if(mapfail)fail_load=first+fail;else fail_alloc=first+fail;
  assert(mwx_queue_fill(&f.sc,&q)==ENOMEM);assert(q.mq_prod==fail-1);
  assert(q.cpu==fail-1&&q.mq_refill_pending&&live==fail-1);
  assert(q.writes==unsigned(fail!=1));assert(f.sc.sc_rx_refill_fail==1);
  std::vector<unsigned>ids;for(unsigned i=0;i<fail-1;++i)ids.push_back(q.mq_data[i].md_mbuf->id);
  fail_alloc=fail_load=0;mwx_rx_refill_retry(&f.sc);
  assert(q.mq_prod==7&&q.cpu==7&&!q.mq_refill_pending&&live==7);
  for(unsigned i=0;i<ids.size();++i)assert(q.mq_data[i].md_mbuf->id==ids[i]);
  assert(f.sc.sc_rx_refill_recover==1);unsigned before=allocs;mwx_rx_refill_retry(&f.sc);assert(allocs==before);
 }
 // Ring wrap: slots 6,7 succeed, slot 0 fails, then retry 0,1,2 only.
 {Fixture f;auto&q=f.sc.sc_rxq;q.mq_prod=6;q.mq_cons=4;fail_alloc=allocs+3;assert(mwx_queue_fill(&f.sc,&q)==ENOMEM);assert(q.mq_prod==0&&q.cpu==0&&q.writes==1&&live==2);auto*a=q.mq_data[6].md_mbuf;auto*b=q.mq_data[7].md_mbuf;fail_alloc=0;mwx_rx_refill_retry(&f.sc);assert(q.mq_prod==3&&q.cpu==3&&live==5);assert(a==q.mq_data[6].md_mbuf&&b==q.mq_data[7].md_mbuf);}
 // Bad ownership: refuse to overwrite any existing slot or allocate a replacement.
 {Fixture f;auto&q=f.sc.sc_rxq;f.packet(0,12);auto*owned=q.mq_data[0].md_mbuf;unsigned before=allocs;assert(mwx_queue_fill(&f.sc,&q)==EBUSY);assert(allocs==before&&q.mq_data[0].md_mbuf==owned&&live==1&&q.writes==0);}
 // Each failed periodic retry attempts each pending ring just once; no busy loop.
 {Fixture f;auto&q=f.sc.sc_rxq;q.mq_refill_pending=true;fail_alloc=allocs+1;unsigned before=allocs;mwx_rx_refill_retry(&f.sc);assert(allocs==before+1&&q.mq_refill_pending&&q.writes==0);}
 for(unsigned reason=0;reason<5;++reason){Fixture f;auto&q=f.sc.sc_rxq;q.mq_refill_pending=true;if(reason==0)f.sc.sc_fw_loaded=false;if(reason==1)f.sc.sc_detaching=true;if(reason==2)f.sc.sc_resetting=true;if(reason==3)f.sc.sc_suspended=true;if(reason==4)f.sc.sc_ic.ic_if.if_flags=0;unsigned before=allocs;mwx_rx_refill_retry(&f.sc);assert(before==allocs&&q.writes==0);}
 // All three pending RX rings are retried; fully idle rings never touched.
 {Fixture f;f.sc.sc_rxq.mq_refill_pending=true;f.sc.sc_rxmcuq.mq_refill_pending=true;f.sc.sc_rxfwdlq.mq_refill_pending=true;mwx_rx_refill_retry(&f.sc);assert(live==21&&f.sc.sc_rx_refill_recover==3);}
 // Reset clears retry and partial-chain discard and frees any successful prefix.
 {Fixture f;auto&q=f.sc.sc_rxq;fail_alloc=allocs+3;assert(mwx_queue_fill(&f.sc,&q)==ENOMEM);q.mq_rx_discard=true;mwx_queue_reset(&f.sc,&q);assert(q.mq_cons==0&&q.mq_prod==0&&!q.mq_refill_pending&&!q.mq_rx_discard&&live==0);}
 // Zero/oversized/incomplete descriptors consume slots but no output: refill still runs.
 for(unsigned len:{0U,1U,2049U,100U}){Fixture f;auto&q=f.sc.sc_rxq;f.packet(0,len,len!=100);q.mq_prod=7;q.dma=1;unsigned before=processes;mwx_dma_rx_done(&f.sc,&q,&f.output);assert(q.mq_cons==1&&q.mq_prod==0&&q.cpu==0&&q.mq_data[7].md_mbuf&&processes==before&&live==(len==100?2U:1U));}
 // Empty dequeue with earlier refill failure: completion also attempts recovery.
 {Fixture f;auto&q=f.sc.sc_rxq;q.mq_refill_pending=true;mwx_dma_rx_done(&f.sc,&q,&f.output);assert(q.mq_prod==7&&live==7&&!q.mq_refill_pending);}
 // Valid data retains delivery even when refill fails, then poll restores missing slot.
 {Fixture f;auto&q=f.sc.sc_rxq;f.packet(0,88);q.mq_prod=7;q.dma=1;fail_alloc=allocs+1;unsigned before=processes;mwx_dma_rx_done(&f.sc,&q,&f.output);assert(processes==before+1&&delivered.size()==1&&delivered[0]->pklen==88);assert(q.mq_prod==7&&q.mq_refill_pending);fail_alloc=0;mwx_rx_refill_retry(&f.sc);assert(q.mq_prod==0&&!q.mq_refill_pending&&q.cpu==0);}
 puts("PASS actual RX refill/completion/retry/reset: first/middle/last alloc/map failures, independent ownership/live counts, partial publish, wrap, zero progress, bounded/offline retry, empty output refill and valid delivery during failure (UBSan).");
}
'''
if __name__=='__main__':
 support['compile_run'](['mwx_buf_fill','mwx_queue_fill','mwx_rx_refill_retry','mwx_queue_reset','mwx_dma_rx_dequeue','mwx_dma_rx_done'],POST)
