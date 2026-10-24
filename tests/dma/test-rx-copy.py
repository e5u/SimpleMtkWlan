"""Execute actual DMA dequeue with guarded payload bounds and UBSan."""
from pathlib import Path
import re, subprocess, tempfile
ROOT=Path(__file__).resolve().parents[2]
SRC=(ROOT/'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text()
def fn(name):
 m=re.search(r'(?m)^(?:static\s+)?(?:int|void|bool)\n'+name+r'\([^;]+?\)\s*\{',SRC);assert m,name
 pos=SRC.index('{',m.start())+1;depth=1
 while depth:
  depth+=(SRC[pos]=='{')-(SRC[pos]=='}');pos+=1
 return SRC[m.start():pos]
PRE=r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <unordered_map>
#include <algorithm>
using u_int=unsigned;using bus_size_t=size_t;
#define M_DONTWAIT 0
#define BUS_DMA_NOWAIT 0
#define BUS_DMA_READ 0
#define MT_RX_BUF_SIZE 2048
#define MBUF_PKTHDR 2
#define mtod(m,t) ((t)((m)->payload))
#define MT_RXD0_PKT_TYPE_GET(x) (((x)>>27)&31)
#define PKT_TYPE_NORMAL 2
#define PKT_TYPE_NORMAL_MCU 8
#define MWX_RX_CHAIN_MAX_BYTES (UINT16_MAX + 8U * sizeof(uint32_t))
#define MWX_RX_CHAIN_MAX_SEGS 64U
#define BUS_DMASYNC_PREWRITE 1
#define BUS_DMASYNC_POSTREAD 2
#define BUS_DMASYNC_PREREAD 4
#define BUS_DMASYNC_POSTWRITE 8
#define PAGE_SIZE 4096U
#define PAGE_SHIFT 12
#define MBUF_TYPE_DATA 1
#define M_DEVBUF 0
#define M_NOWAIT 0
#define M_ZERO 0
#define kIODirectionIn 1
#define kIOMemoryMapperNone 0
#define MWX_RX_POOL_PAGES 16384
#define MWX_RX_POOL_MASK 0x00000000ffffffffULL
#define MT_DMA_CPU_IDX 8
#define MT_DMA_DMA_IDX 12
#define MT_DMA_DESC_BASE 0
#define MT_DMA_RING_SIZE 4
#define MT_DMA_CTL_LAST_SEC0 (1U<<30)
#define MT_DMA_CTL_DMA_DONE (1U<<31)
#define MT_DMA_CTL_SD_LEN0(x) (((x)&0x3fffU)<<16)
#define MT_DNA_CTL_SD_GET_LEN0(x) (((x)>>16)&0x3fffU)
#define htole32(x) (x)
#define le32toh(x) (x)
#define KASSERT(x,...) assert(x)
#define MWX_DEV_LOG(...) ((void)0)
#define DEVNAME(x) "test"
#define IFF_RUNNING 0x40
#define nitems(x) (sizeof(x)/sizeof((x)[0]))
#define SLIST_ENTRY(t) struct { t* sle_next; }
#define SLIST_HEAD(n,t) struct n { t* slh_first; }
#define SLIST_FIRST(h) ((h)->slh_first)
#define SLIST_INIT(h) do { (h)->slh_first=nullptr; } while(0)
#define SLIST_REMOVE_HEAD(h,f) do { (h)->slh_first=(h)->slh_first->f.sle_next; } while(0)
#define SLIST_INSERT_HEAD(h,e,f) do { (e)->f.sle_next=(h)->slh_first; (h)->slh_first=(e); } while(0)
using caddr_t=char*;
using addr64_t=unsigned long long;
using mbuf_type_t=int;
struct task { unsigned dummy; };
static task kernel_task_obj;
#define kernel_task (&kernel_task_obj)
struct mwx_rx_page;
SLIST_HEAD(mwx_rx_page_head, mwx_rx_page);
struct mwx_rx_page { SLIST_ENTRY(mwx_rx_page) link; uint8_t* kva=nullptr; };
static void* mallocarray(size_t n,size_t sz,int,int){return calloc(n,sz);}
static void mwx_free_mem(void*p){free(p);}
struct IOSimpleLock { unsigned held=0; };
static IOSimpleLock* IOSimpleLockAlloc(){return new IOSimpleLock;}
static void IOSimpleLockFree(IOSimpleLock*l){delete l;}
static void IOSimpleLockLock(IOSimpleLock*l){assert(l->held==0);++l->held;}
static void IOSimpleLockUnlock(IOSimpleLock*l){assert(l->held==1);--l->held;}
struct IOBufferMemoryDescriptor { uint8_t* bytes=nullptr; size_t size=0; addr64_t physBase=0x08000000ULL; bool released=false;
 ~IOBufferMemoryDescriptor(){delete[] bytes;}
 uint8_t* getBytesNoCopy(){return bytes;}
 addr64_t getPhysicalSegment(size_t off,size_t*len,int){assert(off<size);*len=size-off;return physBase+off;}
 void release(){released=true;}
 static IOBufferMemoryDescriptor* inTaskWithPhysicalMask(task*,int,size_t sz,uint64_t){auto*d=new IOBufferMemoryDescriptor;d->size=sz;d->bytes=new uint8_t[sz]{};return d;} };
struct mbuf {size_t len=2048,pklen=2048; mbuf*next=nullptr; unsigned id; unsigned flags=MBUF_PKTHDR; caddr_t extbuf=nullptr; uint8_t payload[2048];};
static unsigned live=0,nextid=0,allocs=0,loads=0,fail_alloc=0,fail_load=0,resets=0,processes=0,flagcalls=0,fail_flag=0,fail_attach=0;
struct extfree_rec { void (*fn)(caddr_t,u_int,caddr_t); caddr_t buf; caddr_t arg; };
static std::unordered_map<mbuf*,extfree_rec> extfree_map;
static int mbuf_gethdr(int,mbuf_type_t,mbuf**m){if(++allocs==fail_alloc)return ENOMEM;auto*b=new mbuf;std::memset(b->payload,0xa5,2048);b->id=++nextid;b->flags=0;++live;*m=b;return 0;}
static int mbuf_attachcluster(int,mbuf_type_t,mbuf**m,caddr_t buf,void(*fn)(caddr_t,u_int,caddr_t),size_t,caddr_t arg){if(fail_attach){auto*old=*m;if(old){assert(live);--live;delete old;*m=nullptr;}return ENOMEM;}auto*b=*m;assert(b&&!b->extbuf);b->extbuf=buf;extfree_map[b]={fn,buf,arg};return 0;}
static mbuf*MCLGETL(void*,int,size_t n){assert(n==2048);if(++allocs==fail_alloc)return nullptr;auto*m=new mbuf;std::memset(m->payload,0xa5,2048);m->id=++nextid;++live;return m;}
static void m_freem(mbuf*m);
static void mbuf_free(mbuf*m){m_freem(m);}
static void m_freem(mbuf*m){while(m){auto*n=m->next;assert(live);--live;auto it=extfree_map.find(m);if(it!=extfree_map.end()){if(it->second.fn)it->second.fn(it->second.buf,0,it->second.arg);extfree_map.erase(it);}delete m;m=n;}}
static size_t mbuf_len(mbuf*m){return m->len;}
static size_t mbuf_pkthdr_len(mbuf*m){return m->pklen;}
static void mbuf_setlen(mbuf*m,size_t n){assert(n<=2048);m->len=n;}
static void mbuf_pkthdr_setlen(mbuf*m,size_t n){m->pklen=n;}
static void mbuf_setnext(mbuf*m,mbuf*n){assert(!m->next);m->next=n;}
static int mbuf_setflags_mask(mbuf*m,unsigned flags,unsigned mask){if(++flagcalls==fail_flag)return EINVAL;m->flags=(m->flags&~mask)|(flags&mask);return 0;}
struct mbuf_list {std::vector<mbuf*> entries;};
#define MBUF_LIST_INITIALIZER() {}
static bool ml_empty(mbuf_list*m){return m->entries.empty();}
static void ml_enqueue(mbuf_list*m,mbuf*b){m->entries.push_back(b);}
struct segment{uint64_t ds_addr=0x1000;size_t ds_len=2048;};
struct map_t{size_t dm_mapsize=2048;bool dm_bounce=true;unsigned dm_nsegs=1;segment dm_segs[1];mbuf*owner=nullptr;mbuf*dm_mbuf=nullptr;uint8_t payload[2048];};
struct mwx_desc {uint32_t buf0=0,buf1=0,ctrl=0,info=0;};
struct mwx_txwi{};
struct mwx_queue_data {mbuf*md_mbuf=nullptr;mwx_txwi*md_txwi=nullptr;map_t*md_map=nullptr;};
struct mwx_queue {uint32_t mq_regbase=0;unsigned mq_count=8,mq_prod=0,mq_cons=0;mwx_desc*mq_desc=nullptr;mwx_queue_data*mq_data=nullptr;map_t*mq_map=nullptr;bool mq_refill_pending=false,mq_rx_discard=false;mbuf*mq_rx_head=nullptr,*mq_rx_tail=nullptr;unsigned mq_rx_bytes=0,mq_rx_segments=0;segment mq_seg{};unsigned dma=0,cpu=0,writes=0;};
struct mwx_softc {void*sc_dmat=nullptr;struct{struct{unsigned if_flags=IFF_RUNNING;}ic_if;}sc_ic;
 bool sc_fw_loaded=true,sc_detaching=false,sc_resetting=false,sc_suspended=false;
 mwx_queue sc_rxq,sc_rxmcuq,sc_rxfwdlq;
 IOSimpleLock* sc_rx_pool_lock=nullptr; IOBufferMemoryDescriptor* sc_rx_pool_md=nullptr;
 uint8_t* sc_rx_pool_kva=nullptr,*sc_rx_pool_end=nullptr;
 mwx_rx_page_head sc_rx_pool_free{};
 mwx_rx_page* sc_rx_pool_pages=nullptr;
 unsigned sc_rx_pool_total=0,sc_rx_pool_free_cnt=0,sc_rx_pool_allocs=0,sc_rx_pool_exhausted=0,sc_rx_pool_fallbacks=0,sc_rx_pool_returned=0;
 bool sc_rx_pool_disabled=false;
 uint64_t sc_rx_dma_bytes=0,sc_rx_dma_copy_bytes=0,sc_rx_dma_copy_saved=0,sc_rx_dma_batches=0,sc_rx_dma_desc=0;
 uint64_t sc_rx_dma_chain_completed=0,sc_rx_dma_chain_resumed=0,sc_rx_dma_chain_dropped=0;
 uint32_t sc_rx_dma_max_batch=0,sc_rx_dma_bad_len=0,sc_rx_refill_fail=0,sc_rx_refill_recover=0;
};
static std::vector<size_t> copies;static std::vector<mbuf*> delivered;
static int bus_dmamap_load_mbuf(void*,map_t*m,mbuf*b,int){if(++loads==fail_load)return ENOMEM;m->owner=b;m->dm_mapsize=b->pklen;m->dm_nsegs=1;m->dm_bounce=true;m->dm_segs[0].ds_len=b->pklen;return 0;}
static void bus_dmamap_sync(void*,map_t*m,size_t off,size_t n,int ops){if((ops&BUS_DMASYNC_POSTREAD)&&m->dm_bounce&&m->owner){assert(off+n<=m->dm_mapsize&&off+n<=2048);copies.push_back(n);std::memcpy(m->owner->payload+off,m->payload+off,n);}}
static void bus_dmamap_unload(void*,map_t*m){m->owner=nullptr;m->dm_mbuf=nullptr;m->dm_mapsize=0;m->dm_nsegs=0;m->dm_bounce=false;}
static mwx_queue& queue_for(mwx_softc*s,uint32_t addr){for(auto*q:{&s->sc_rxq,&s->sc_rxmcuq,&s->sc_rxfwdlq})if(addr>=q->mq_regbase&&addr<q->mq_regbase+16)return*q;std::abort();}
static uint32_t mwx_read(mwx_softc*s,uint32_t a){auto&q=queue_for(s,a);assert(a-q.mq_regbase==MT_DMA_DMA_IDX);return q.dma;}
static void mwx_write(mwx_softc*s,uint32_t a,uint32_t v){auto&q=queue_for(s,a);if(a-q.mq_regbase==MT_DMA_CPU_IDX){q.cpu=v;++q.writes;}if(a-q.mq_regbase==MT_DMA_DMA_IDX)q.dma=v;}
static void mwx_reset(mwx_softc*s){++resets;s->sc_resetting=true;}
static void mwx_txwi_put(mwx_softc*,mwx_txwi*){}
static void mwx_rx_pool_free_page(caddr_t addr,u_int,caddr_t arg){auto*sc=(mwx_softc*)arg;const uint64_t off=(uint64_t)((uint8_t*)addr-sc->sc_rx_pool_kva);if(sc->sc_rx_pool_kva==nullptr||off>(uint64_t)(sc->sc_rx_pool_end-sc->sc_rx_pool_kva)||(off&(PAGE_SIZE-1))!=0)return;SLIST_INSERT_HEAD(&sc->sc_rx_pool_free,&sc->sc_rx_pool_pages[off>>PAGE_SHIFT],link);sc->sc_rx_pool_free_cnt++;sc->sc_rx_pool_returned++;}
static uint32_t mwx_rx_pool_page_phys(struct mwx_softc*sc,uint8_t*kva){size_t len=0;return (uint32_t)sc->sc_rx_pool_md->getPhysicalSegment((size_t)(kva-sc->sc_rx_pool_kva),&len,kIOMemoryMapperNone);}
static void mwx_dma_rx_process(mwx_softc*,mbuf_list*l,mbuf_list*,uint8_t){++processes;for(auto*m:l->entries){assert(m->len>=4);delivered.push_back(m);}l->entries.clear();}
struct Fixture {mwx_softc sc;mbuf_list output;map_t maps[3][8],rings[3];mwx_desc desc[3][8];mwx_queue_data data[3][8];
 Fixture(){unsigned i=0;for(auto*q:{&sc.sc_rxq,&sc.sc_rxmcuq,&sc.sc_rxfwdlq}){q->mq_regbase=0x100+0x100*i;q->mq_data=data[i];q->mq_desc=desc[i];q->mq_map=&rings[i];rings[i].dm_bounce=false;for(unsigned j=0;j<8;++j){data[i][j].md_map=&maps[i][j];std::memset(maps[i][j].payload,0x5a,2048);}++i;}}
 void build_pool(unsigned pages){sc.sc_rx_pool_lock=IOSimpleLockAlloc();sc.sc_rx_pool_md=IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task,kIODirectionIn,pages*PAGE_SIZE,MWX_RX_POOL_MASK);sc.sc_rx_pool_kva=sc.sc_rx_pool_md->bytes;sc.sc_rx_pool_end=sc.sc_rx_pool_kva+pages*PAGE_SIZE;sc.sc_rx_pool_pages=(mwx_rx_page*)mallocarray(pages,sizeof(mwx_rx_page),M_DEVBUF,M_NOWAIT|M_ZERO);SLIST_INIT(&sc.sc_rx_pool_free);for(unsigned i=0;i<pages;++i){sc.sc_rx_pool_pages[i].kva=sc.sc_rx_pool_kva+i*PAGE_SIZE;SLIST_INSERT_HEAD(&sc.sc_rx_pool_free,&sc.sc_rx_pool_pages[i],link);}sc.sc_rx_pool_total=pages;sc.sc_rx_pool_free_cnt=pages;}
 void packet(unsigned slot,unsigned len,bool last=true,bool bounce=true){auto&d=data[0][slot];d.md_mbuf=MCLGETL(nullptr,0,2048);assert(d.md_mbuf);d.md_map->owner=d.md_mbuf;d.md_map->dm_mapsize=2048;d.md_map->dm_nsegs=1;d.md_map->dm_bounce=bounce;desc[0][slot].ctrl=MT_DMA_CTL_SD_LEN0(len)|(last?MT_DMA_CTL_LAST_SEC0:0);}
 ~Fixture(){for(auto*q:{&sc.sc_rxq,&sc.sc_rxmcuq,&sc.sc_rxfwdlq})m_freem(q->mq_rx_head);for(auto&m:delivered)m_freem(m);delivered.clear();for(auto&row:data)for(auto&d:row)if(d.md_mbuf)m_freem(d.md_mbuf);assert(live==0);if(sc.sc_rx_pool_lock){IOSimpleLockFree(sc.sc_rx_pool_lock);sc.sc_rx_pool_lock=nullptr;}if(sc.sc_rx_pool_md){sc.sc_rx_pool_md->release();delete sc.sc_rx_pool_md;sc.sc_rx_pool_md=nullptr;}mwx_free_mem(sc.sc_rx_pool_pages);sc.sc_rx_pool_pages=nullptr;copies.clear();fail_alloc=fail_load=fail_flag=0;fail_attach=0;extfree_map.clear();}
};
'''
def compile_run(names,post):
 with tempfile.TemporaryDirectory(prefix='rx-dma-') as tmp:
  p=Path(tmp);(p/'test.cpp').write_text(PRE+'\n'.join(fn(n) for n in names)+post)
  subprocess.run(['clang++','-std=c++14','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
  subprocess.run([str(p/'test')],check=True)
POST=r'''
int main(){
 // Pool-backed fill uses a low-4G page directly: no load, no bounce copy.
 {Fixture f;auto&q=f.sc.sc_rxq;f.build_pool(4);assert(mwx_buf_fill(&f.sc,&q.mq_data[0],&f.desc[0][0])==0);
  auto*m=q.mq_data[0].md_mbuf;assert(m&&m->extbuf);
  auto&map=*q.mq_data[0].md_map;assert(map.dm_mbuf==m&&!map.dm_bounce&&map.dm_nsegs==1&&map.dm_mapsize==PAGE_SIZE);
  assert(map.dm_segs[0].ds_len==MT_RX_BUF_SIZE&&map.dm_segs[0].ds_addr<=0xffffffffULL);
  assert(le32toh(f.desc[0][0].buf0)==map.dm_segs[0].ds_addr);
  assert(f.sc.sc_rx_pool_allocs==1&&f.sc.sc_rx_pool_fallbacks==0&&f.sc.sc_rx_pool_free_cnt==3);
  assert(loads==0&&copies.empty());m_freem(m);q.mq_data[0].md_mbuf=nullptr;assert(f.sc.sc_rx_pool_free_cnt==4&&f.sc.sc_rx_pool_returned==1);}
 // Exhaustion falls back to the bounce path and keeps the ring filled.
 {Fixture f;auto&q=f.sc.sc_rxq;f.build_pool(1);assert(mwx_buf_fill(&f.sc,&q.mq_data[0],&f.desc[0][0])==0);assert(f.sc.sc_rx_pool_free_cnt==0);
  assert(mwx_buf_fill(&f.sc,&q.mq_data[1],&f.desc[0][1])==0);assert(q.mq_data[1].md_mbuf&&f.sc.sc_rx_pool_exhausted==1&&f.sc.sc_rx_pool_fallbacks==1&&loads==1);
  assert(q.mq_data[1].md_map->dm_bounce&&q.mq_data[1].md_map->dm_mapsize==2048);
  m_freem(q.mq_data[0].md_mbuf);q.mq_data[0].md_mbuf=nullptr;m_freem(q.mq_data[1].md_mbuf);q.mq_data[1].md_mbuf=nullptr;}
 // Cluster-attach failure returns the page and does not leak the header.
 {Fixture f;auto&q=f.sc.sc_rxq;f.build_pool(2);fail_attach=1;assert(mwx_buf_fill(&f.sc,&q.mq_data[0],&f.desc[0][0])==ENOMEM);fail_attach=0;
  assert(f.sc.sc_rx_pool_free_cnt==2&&f.sc.sc_rx_pool_allocs==1&&q.mq_data[0].md_mbuf==nullptr);}
 // Header exhaustion returns the page too.
 {Fixture f;auto&q=f.sc.sc_rxq;f.build_pool(2);fail_alloc=allocs+1;assert(mwx_buf_fill(&f.sc,&q.mq_data[0],&f.desc[0][0])==ENOMEM);fail_alloc=0;
  assert(f.sc.sc_rx_pool_free_cnt==2);}
 for(unsigned len:{0U,1U,3U,4U,64U,1514U,2048U,2049U,16383U})for(bool bounce:{false,true}){
  Fixture f;auto&q=f.sc.sc_rxq;f.packet(0,len,true,bounce);q.dma=1;mbuf_list ml;
  mwx_dma_rx_dequeue(&f.sc,&q,&ml);bool valid=len>=4&&len<=2048;
  assert(q.mq_cons==1&&f.sc.sc_rx_dma_desc==1&&f.sc.sc_rx_dma_batches==1&&f.sc.sc_rx_dma_max_batch==1);
  assert(f.sc.sc_rx_dma_bad_len==unsigned(!valid));assert(ml.entries.size()==unsigned(valid));
  assert(copies.size()==unsigned(valid&&bounce));if(valid&&bounce)assert(copies[0]==len);
  assert(f.sc.sc_rx_dma_copy_bytes==(valid&&bounce?len:0));assert(f.sc.sc_rx_dma_copy_saved==(valid&&bounce?2048-len:0));
  for(auto*m:ml.entries){assert(m->len==len&&m->pklen==len);if(bounce){for(unsigned i=0;i<len;++i)assert(m->payload[i]==0x5a);for(unsigned i=len;i<2048;++i)assert(m->payload[i]==0xa5);}m_freem(m);}
 }
 // Both independently trusted capacities constrain descriptor-provided lengths.
 for(bool maplimit:{false,true}){Fixture f;auto&q=f.sc.sc_rxq;f.packet(0,128);if(maplimit)f.maps[0][0].dm_mapsize=64;else f.data[0][0].md_mbuf->len=64;q.dma=1;mbuf_list ml;mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(ml.entries.empty()&&copies.empty()&&f.sc.sc_rx_dma_bad_len==1);}
 // Contiguous chain may end in a 1-byte segment; first RX word is contiguous.
 {Fixture f;auto&q=f.sc.sc_rxq;f.packet(0,100,false);f.packet(1,1);q.dma=2;mbuf_list ml;mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(ml.entries.size()==1);auto*m=ml.entries[0];assert(m->pklen==101&&m->next->len==1);m_freem(m);assert(copies==std::vector<size_t>({100,1}));assert(f.sc.sc_rx_dma_max_batch==2);}
 // A malformed middle fragment frees prefix, skips tail, and delivers next frame.
 {Fixture f;auto&q=f.sc.sc_rxq;f.packet(0,100,false);f.packet(1,2049,false);f.packet(2,20);f.packet(3,40);q.dma=4;mbuf_list ml;mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(ml.entries.size()==1&&ml.entries[0]->pklen==40);m_freem(ml.entries[0]);assert(copies==std::vector<size_t>({100,40}));assert(!q.mq_rx_discard);}
 // Split across dequeue batches: retain prefix and append tail exactly once.
 {Fixture f;auto&q=f.sc.sc_rxq;f.packet(0,100,false);q.dma=1;mbuf_list ml;mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(ml.entries.empty()&&q.mq_rx_head&&q.mq_rx_bytes==100&&!q.mq_rx_discard);f.packet(1,1);f.packet(2,44);q.dma=3;mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(ml.entries.size()==2&&ml.entries[0]->pklen==101&&ml.entries[1]->pklen==44&&!q.mq_rx_head&&!q.mq_rx_discard);for(auto*m:ml.entries)m_freem(m);assert(copies==std::vector<size_t>({100,1,44}));}
 {Fixture f;auto&q=f.sc.sc_rxq;q.mq_cons=7;f.packet(7,100);f.packet(0,80);q.dma=1;mbuf_list ml;mwx_dma_rx_dequeue(&f.sc,&q,&ml);assert(q.mq_cons==1&&ml.entries.size()==2);for(auto*m:ml.entries)m_freem(m);}
 puts("PASS real RX dequeue: exact copy lengths/canaries, zero/short/full/oversize, bounce/direct, chains, invalid middle, cross-batch ownership, wrap and batch counters (UBSan).");
}
'''
if __name__=='__main__':compile_run(['mwx_dma_rx_dequeue','mwx_buf_fill'],POST)
