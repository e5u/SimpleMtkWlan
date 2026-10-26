from pathlib import Path
import subprocess,sys,tempfile,re
b=Path(__file__).resolve().parent
src=Path(sys.argv[1]) if len(sys.argv)>1 else b.parents[1]/'SimpleMtkWlan/hal_mwx/MtkMwx.cpp'
s=src.read_text();f=s[s.index('void\nmwx_start('):s.index('\nint\nmwx_ioctl(')]
writer=s[s.index('static inline uint8_t\nmt7921_lmac_mapping('):s.index('\nvoid\nmwx_mac_tx_free(')]
reg=(src.parent/'if_mwxreg.h').read_text()
defines='\n'.join(line for line in reg.splitlines() if re.match(r'#define\s+(MT_TXD[0135]|MT_PACKET_ID|MT_TX_TYPE_CT|MT_LMAC_ALTX0|MT_TXD_SIZE|MWX_MAX_WMM_SETS)',line))
pre=r'''
#include <cassert>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#define NBPFILTER 0
const int IFF_RUNNING=1,IFF_UP=2,IEEE80211_S_RUN=4,IEEE80211_F_TX_MGMT_ONLY=8;
struct ieee80211_node{int refs=0;};
struct mwx_node{ieee80211_node ni;uint16_t wcid=1;};
struct ieee80211_frame{unsigned char i_fc[2],i_dur[2],i_addr1[6],rest[14];};
struct ieee80211_key{unsigned k_flags=0x80;int k_cipher=0x20;};
struct mbuf{ieee80211_node*node;ieee80211_frame wh{};};struct queue{mbuf*m=nullptr;};
struct netstat{unsigned long long outputPackets=0,outputErrors=0;};
struct ifnet {void*if_softc;int if_flags=3;queue if_snd;int if_oerrors=0,if_timer=0;netstat*netStat=nullptr;};
struct ieee80211com {int ic_state=4,ic_xflags=0;queue ic_mgtq;};
struct mwx_softc{ieee80211com sc_ic;unsigned sc_tx_full_cnt=0;struct{uint8_t omac_idx=0,wmm_idx=0,band_idx=0;}sc_vif;};
struct mt76_txwi{uint32_t txwi[8]={};};
enum mt76_txq_id{MT_TXQ_BE=0,MT_TXQ_PSD=4};
#define htole32(v) (v)
#define IEEE80211_FC0_TYPE_DATA 8
#define IEEE80211_QOS_TID 15
int ieee80211_has_qos(const ieee80211_frame*){return 0;}
int ieee80211_get_qos(const ieee80211_frame*){return 0;}
size_t mbuf_pkthdr_len(mbuf*){return 64;}
void mt7921_mac_write_txwi_80211(mwx_softc*,mbuf*,ieee80211_node*,mt76_txwi*){}
void mt7921_mac_write_txwi(mwx_softc*,mbuf*,ieee80211_node*,mt76_txwi*);
mt76_txwi last_descriptor;
int room=1;
int mwx_tx_has_room(mwx_softc*,unsigned){return room;}
int paused;
void ifq_set_oactive(queue*){paused++;}struct ether_header{char bytes[14];};
bool ifq_is_oactive(queue*){return false;}
mbuf*mq_dequeue(queue*q){auto m=q->m;q->m=nullptr;return m;}
mbuf*ifq_dequeue(queue*q){return mq_dequeue(q);}
void*mbuf_pkthdr_rcvif(mbuf*m){return m->node;}
size_t mbuf_len(mbuf*){return 64;}
mbuf*m_pullup(mbuf*m,size_t){return m;}
#define mtod(m,t) ((t)&(m)->wh)
#define IEEE80211_FC0_TYPE_MASK 0x0c
#define IEEE80211_FC0_TYPE_MGT 0
#define IEEE80211_FC1_PROTECTED 0x40
#define IEEE80211_KEY_SWCRYPTO 0x80
#define IEEE80211_CIPHER_BIP 0x20
#define IEEE80211_IS_MULTICAST(a) ((a)[0]&1)
ieee80211_key txkey;
int software_encrypts=0;
ieee80211_key*ieee80211_get_txkey(ieee80211com*,ieee80211_frame*,ieee80211_node*){return &txkey;}
mbuf*ieee80211_encrypt(ieee80211com*,mbuf*m,ieee80211_key*){software_encrypts++;m->wh.i_fc[1]&=~IEEE80211_FC1_PROTECTED;return m;}
void m_freem(mbuf*){}
mbuf*ieee80211_encap(ifnet*,mbuf*m,ieee80211_node**ni){*ni=m->node;(*ni)->refs++;return m;}
void ieee80211_release_node(ieee80211com*,ieee80211_node*ni){assert(ni->refs>0);ni->refs--;}
int result;
int mwx_tx(mwx_softc*sc,mbuf*m,ieee80211_node*ni){assert(ni->refs==1);mt7921_mac_write_txwi(sc,m,ni,&last_descriptor);return result;}
'''
main=r'''
int main(){
 for(int mgmt=0;mgmt<2;mgmt++)for(int error=0;error<2;error++){
  mwx_softc sc; ifnet ifp; ifp.if_softc=&sc;mwx_node mn;auto&ni=mn.ni;mbuf m{&ni};result=error;
  if(mgmt){ni.refs++;sc.sc_ic.ic_mgtq.m=&m;}else ifp.if_snd.m=&m;
  mwx_start(&ifp);assert(ni.refs==0);assert(ifp.if_oerrors==error);
 }
 {mwx_softc sc; ifnet ifp; ifp.if_softc=&sc;mwx_node mn;auto&ni=mn.ni;mbuf m{&ni};room=0;paused=0;ifp.if_snd.m=&m;
  mwx_start(&ifp);assert(ifp.if_snd.m==&m&&paused==1&&sc.sc_tx_full_cnt==1&&ni.refs==0);room=1;}
 for(unsigned multicast=0;multicast<2;multicast++){
  mwx_softc sc;ifnet ifp;ifp.if_softc=&sc;mwx_node mn;auto&ni=mn.ni;ni.refs=1;mbuf m{&ni};
  m.wh.i_fc[0]=0xc0;m.wh.i_fc[1]=0x40;m.wh.i_addr1[0]=multicast?0xff:2;
  sc.sc_ic.ic_mgtq.m=&m;software_encrypts=0;result=0;mwx_start(&ifp);
  assert(ni.refs==0&&software_encrypts==int(multicast));
  assert(bool(last_descriptor.txwi[3]&MT_TXD3_PROTECT_FRAME)==!multicast);
 }
 puts("PASS: mwx_start balances references/backpressure; protected unicast management uses hardware exactly once, BIP group management disables descriptor encryption.");
}
'''
tmp=tempfile.TemporaryDirectory(prefix='mtk-tx-test-');art=Path(tmp.name)
cpp=art/'node-test.cpp';exe=art/'node-test';cpp.write_text(pre+defines+'\n'+writer+f+main)
subprocess.run(['clang++','-std=c++14','-fsanitize=' + __import__('os').environ.get('MTK_TEST_SANITIZERS', 'address,undefined'),'-g',str(cpp),'-o',str(exe)],check=True)
raise SystemExit(subprocess.run([str(exe)]).returncode)
