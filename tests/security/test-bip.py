#!/usr/bin/env python3
"""Execute real BIP management protection, key selection and replay checks."""
from pathlib import Path
import re
import subprocess
import tempfile
import os
from support.crypto_reference import reference_cmac

ROOT = Path(__file__).resolve().parents[2]
NET = ROOT / "mtk80211/openbsd/net80211"


def function(path, name):
    text = path.read_text()
    match = re.search(r"(?m)^(?:static )?(?:int|void|mbuf_t|struct ieee80211_key \*)\n" + name + r"\([^;]+?\)\s*\{", text)
    assert match, name
    pos = text.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (text[pos] == "{") - (text[pos] == "}")
        pos += 1
    return text[match.start():pos]


STUB = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
using u_int8_t=uint8_t;using u_int16_t=uint16_t;using u_int64_t=uint64_t;
using u_int=unsigned;using caddr_t=char*;
#define IEEE80211_ADDR_LEN 6
#define IEEE80211_FC0_TYPE_MASK 0x0c
#define IEEE80211_FC0_TYPE_MGT 0
#define IEEE80211_FC0_TYPE_DATA 8
#define IEEE80211_FC0_SUBTYPE_MASK 0xf0
#define IEEE80211_FC0_SUBTYPE_DISASSOC 0xa0
#define IEEE80211_FC0_SUBTYPE_DEAUTH 0xc0
#define IEEE80211_FC0_SUBTYPE_ACTION 0xd0
#define IEEE80211_FC1_RETRY 8
#define IEEE80211_FC1_PWR_MGT 0x10
#define IEEE80211_FC1_MORE_DATA 0x20
#define IEEE80211_FC1_PROTECTED 0x40
#define IEEE80211_IS_MULTICAST(a) ((a)[0]&1)
#define IEEE80211_ADDR_COPY(d,s) memcpy(d,s,6)
#define IEEE80211_MMIE_LEN 18
#define IEEE80211_ELEMID_MMIE 76
#define IEEE80211_KEY_SWCRYPTO 0x80
#define IEEE80211_NODE_RXMGMTPROT 0x20
#define IEEE80211_NODE_TXMGMTPROT 0x40
#define IEEE80211_C_MFP 1
#define IEEE80211_STA_ONLY 1
#define IEEE80211_FC0_VERSION_0 0
#define IEEE80211_FC1_DIR_NODS 0
#define IEEE80211_SEQ_SEQ_SHIFT 4
#define IEEE80211_FC0_SUBTYPE_PROBE_RESP 0x50
#define IEEE80211_FC0_SUBTYPE_SHIFT 4
#define IFF_DEBUG 1
#define XYLog(...) ((void)0)
#define htole16(v) (v)
#define IEEE80211_RXI_HWDEC 1
#define IEEE80211_RXI_HWDEC_SAME_PN 2
#define IEEE80211_CCMP_HDRLEN 8
#define IEEE80211_TKIP_HDRLEN 8
#define IEEE80211_WEP_EXTIV 0x20
#define IEEE80211_QOS_TID 15
#define IEEE80211_F_RSNON 1
#define IEEE80211_CIPHER_USEGROUP 0
#define IEEE80211_CIPHER_CCMP 8
#define IEEE80211_CIPHER_BIP 0x20
#define IEEE80211_CIPHER_WEP40 2
#define IEEE80211_CIPHER_TKIP 4
#define IEEE80211_CIPHER_WEP104 0x10
#define MBUF_DONTWAIT 0
#define MT_DATA 0
#define ENOMEM 12
#define EINVAL 22
#define _KASSERT(x) assert(x)
#define LE_WRITE_2(p,v) do{(p)[0]=(v);(p)[1]=(v)>>8;}while(0)
#define LE_WRITE_6(p,v) do{for(int i=0;i<6;++i)(p)[i]=(v)>>(i*8);}while(0)
#define LE_READ_2(p) ((p)[0]|((p)[1]<<8))
#define LE_READ_6(p) ((uint64_t)(p)[0]|((uint64_t)(p)[1]<<8)|((uint64_t)(p)[2]<<16)|((uint64_t)(p)[3]<<24)|((uint64_t)(p)[4]<<32)|((uint64_t)(p)[5]<<40))
#define mtod(m,t) ((t)(m)->bytes.data())
#define explicit_bzero(p,n) memset(p,0,n)
#define malloc(n,flags,wait) malloc(n)
#define timingsafe_bcmp memcmp
#define panic(...) abort()
struct ieee80211_frame {uint8_t i_fc[2],i_dur[2],i_addr1[6],i_addr2[6],i_addr3[6],i_seq[2];};
struct ieee80211_key {uint8_t k_id=0;int k_cipher=IEEE80211_CIPHER_BIP;unsigned k_flags=IEEE80211_KEY_SWCRYPTO;
 uint64_t k_rsc[16]={},k_mgmt_rsc=0,k_tsc=0;uint8_t k_key[32]={};void*k_priv=nullptr;};
struct ieee80211_node {int ni_rsncipher=IEEE80211_CIPHER_USEGROUP;unsigned ni_flags=IEEE80211_NODE_RXMGMTPROT;ieee80211_key ni_pairwise_key;unsigned ni_inact=0,ni_txseq=0;uint8_t ni_macaddr[6]={},ni_bssid[6]={};};
struct ieee80211_rxinfo{unsigned rxi_flags=0;};
struct _ifnet {unsigned if_flags=0,if_timer=0;void(*if_start)(_ifnet*);};using ifnet_t=void*;
struct ieee80211com {_ifnet ic_if;unsigned ic_flags=IEEE80211_F_RSNON;ieee80211_key ic_nw_keys[6];struct{unsigned is_tx_nombuf,is_cmac_replays,is_cmac_icv_errs,is_ccmp_replays,is_tkip_replays;}ic_stats{};unsigned ic_caps=IEEE80211_C_MFP;int ic_mgtq=0;uint8_t ic_myaddr[6]={};};
struct mbuf {std::vector<uint8_t>bytes;size_t m_len=0,pklen=0;mbuf*next=nullptr;};using mbuf_t=mbuf*;
static mbuf_t make_packet(size_t n){auto*m=new mbuf;m->bytes.resize(n);m->m_len=m->pklen=n;return m;}
static mbuf_t copy_packet(mbuf_t m){size_t total=m->pklen;auto*n=make_packet(total);size_t off=0;for(auto*p=m;p;p=p->next){memcpy(n->bytes.data()+off,p->bytes.data(),p->m_len);off+=p->m_len;}assert(off==total);return n;}
static void mbuf_freem(mbuf_t m);
static mbuf_t linearize(mbuf_t m){size_t total=m->pklen;auto*n=make_packet(total);size_t off=0;for(auto*p=m;p;p=p->next){memcpy(n->bytes.data()+off,p->bytes.data(),p->m_len);off+=p->m_len;}mbuf_freem(m);return n;}
static int mbuf_pullup(mbuf_t*m,size_t n){assert(n==(*m)->pklen);*m=linearize(*m);return 0;}
static size_t mbuf_len(mbuf_t m){return m->m_len;}
static mbuf_t mbuf_next(mbuf_t m){return m->next;}
static size_t mbuf_pkthdr_len(mbuf_t m){return m->pklen;}
static int mbuf_trailingspace(mbuf_t m){return m->bytes.size()-m->m_len;}
static int mbuf_type(mbuf_t){return MT_DATA;}
static int mbuf_mclget(int,int,mbuf_t*m){*m=make_packet(2048);(*m)->m_len=0;return 0;}
static void mbuf_setnext(mbuf_t m,mbuf_t n){assert(!m->next);m->next=n;}
static void mbuf_setlen(mbuf_t m,size_t n){m->m_len=n;}
static void mbuf_pkthdr_setlen(mbuf_t m,size_t n){m->pklen=n;}
static void mbuf_freem(mbuf_t m){while(m){auto*n=m->next;delete m;m=n;}}
static void mbuf_adj(mbuf_t m,int n){if(n>0){m->bytes.erase(m->bytes.begin(),m->bytes.begin()+n);m->m_len-=n;m->pklen-=n;}else{m->m_len+=n;m->pklen+=n;}}
static unsigned ieee80211_get_hdrlen(const ieee80211_frame*wh){return 24+((wh->i_fc[1]&0x80)?4:0);}
static int ieee80211_has_qos(const ieee80211_frame*){return 0;}
static int ieee80211_get_qos(const ieee80211_frame*){return 0;}
static int ieee80211_tkip_get_tsc(uint64_t*,uint64_t**,mbuf_t,ieee80211_key*){return EINVAL;}
#include <crypto/aes.h>
#include <crypto/cmac.h>
struct ieee80211_bip_ctx {AES_CMAC_CTX cmac;};
struct ieee80211_bip_frame {uint8_t i_fc[2],i_addr1[6],i_addr2[6],i_addr3[6];} __attribute__((packed));
static mbuf_t ieee80211_wep_decrypt(ieee80211com*,mbuf_t,ieee80211_key*){return nullptr;}
static mbuf_t ieee80211_tkip_decrypt(ieee80211com*,mbuf_t,ieee80211_key*){return nullptr;}
static unsigned software_ccmp=0;
static mbuf_t ieee80211_ccmp_decrypt(ieee80211com*,mbuf_t m,ieee80211_key*){software_ccmp++;mbuf_freem(m);return nullptr;}
static mbuf_t queued=nullptr;
static void mbuf_prepend(mbuf_t*m,size_t n,int){(*m)->bytes.insert((*m)->bytes.begin(),n,0);(*m)->m_len+=n;(*m)->pklen+=n;}
static void mbuf_pkthdr_setrcvif(mbuf_t,ifnet_t){}
static int mbuf_copydata(mbuf_t m,size_t off,size_t n,void*p){if(off+n>m->m_len)return EINVAL;memcpy(p,m->bytes.data()+off,n);return 0;}
static const char*ieee80211_action_name(ieee80211_frame*){return "";}
static const char*ieee80211_mgt_subtype_name[16]={};
static void mq_enqueue(int*,mbuf_t m){assert(!queued);queued=m;}
static void start(_ifnet*){}
'''

MAIN = r'''
int main(){
 ieee80211com ic;ieee80211_node ni;auto*k=&ic.ic_nw_keys[4];k->k_id=4;
 for(unsigned i=0;i<16;++i)k->k_key[i]=i+1;assert(ieee80211_bip_set_key(&ic,k)==0);
 auto*m=make_packet(36);auto*wh=(ieee80211_frame*)m->bytes.data();wh->i_fc[0]=0xc0;wh->i_fc[1]=0x40;memset(wh->i_addr1,0xff,6);
 for(unsigned i=0;i<12;++i)m->bytes[24+i]=i+0x50;
 m=ieee80211_bip_encap(&ic,m,k);assert(m&&m->next&&m->pklen==54&&k->k_tsc==1);assert(!(wh->i_fc[1]&0x40));
 auto*encoded=copy_packet(m);for(size_t i=0;i<encoded->m_len;i++)printf("%02x",encoded->bytes[i]);puts("");mbuf_freem(encoded);
 auto*mmie=m->next->bytes.data();assert(mmie[0]==76&&mmie[1]==16&&LE_READ_2(mmie+2)==4&&LE_READ_6(mmie+4)==1);
 auto*replayed=linearize(copy_packet(m));auto*good=linearize(m);assert(ieee80211_decrypt(&ic,good,&ni)==good);assert(k->k_mgmt_rsc==1&&good->m_len==36);mbuf_freem(good);
 assert(ieee80211_decrypt(&ic,replayed,&ni)==nullptr&&ic.ic_stats.is_cmac_replays==1);
 // A higher IPN is valid, a bit flip in its authenticated body is not.
 k->k_tsc=0x010203040505ULL;m=make_packet(36);wh=(ieee80211_frame*)m->bytes.data();wh->i_fc[0]=0xd0;memset(wh->i_addr1,0xff,6);
 m=ieee80211_bip_encap(&ic,m,k);m=linearize(m);auto*tampered=copy_packet(m);tampered->bytes[24]^=1;assert(ieee80211_decrypt(&ic,tampered,&ni)==nullptr&&ic.ic_stats.is_cmac_icv_errs==1);
 good=m;assert(ieee80211_decrypt(&ic,good,&ni)==good&&k->k_mgmt_rsc==0x010203040506ULL);mbuf_freem(good);
 // MMIE key id is checked by the real receive key selector; id 5 is valid.
 ic.ic_nw_keys[5]=*k;ic.ic_nw_keys[5].k_id=5;ic.ic_nw_keys[5].k_priv=nullptr;assert(ieee80211_bip_set_key(&ic,&ic.ic_nw_keys[5])==0);
 m=make_packet(36);wh=(ieee80211_frame*)m->bytes.data();wh->i_fc[0]=0xc0;memset(wh->i_addr1,0xff,6);m=ieee80211_bip_encap(&ic,m,&ic.ic_nw_keys[5]);
 m=linearize(m);assert(LE_READ_2(m->bytes.data()+38)==5);assert(ieee80211_decrypt(&ic,m,&ni)==m);mbuf_freem(m);
 m=make_packet(42);wh=(ieee80211_frame*)m->bytes.data();memset(wh->i_addr1,0xff,6);m->bytes[26]=6;assert(!ieee80211_get_rxkey(&ic,m,&ni));mbuf_freem(m);
 // The RX routing helper must authenticate BIP with either HWDEC flag value.
 uint8_t independent[54];assert(fread(independent,1,54,stdin)==54);
 for(unsigned hw=0;hw<2;hw++) {
  k->k_mgmt_rsc=0;ieee80211_rxinfo rx;rx.rxi_flags=hw;
  m=make_packet(54);memcpy(m->bytes.data(),independent,54);
  good=ieee80211_input_mgmt_protect(&ic,&ni,m,&rx);assert(good&&good->m_len==36&&k->k_mgmt_rsc==1);mbuf_freem(good);
  m=make_packet(54);memcpy(m->bytes.data(),independent,54);assert(!ieee80211_input_mgmt_protect(&ic,&ni,m,&rx));
  k->k_mgmt_rsc=0;m=make_packet(54);memcpy(m->bytes.data(),independent,54);m->bytes[24]^=1;assert(!ieee80211_input_mgmt_protect(&ic,&ni,m,&rx)&&k->k_mgmt_rsc==0);
  // A valid first-segment MMIE cannot hide unauthenticated trailing bytes.
  m=make_packet(54);memcpy(m->bytes.data(),independent,54);m->next=make_packet(4);m->pklen=58;
  assert(!ieee80211_input_mgmt_protect(&ic,&ni,m,&rx)&&k->k_mgmt_rsc==0);
  m=make_packet(30);memcpy(m->bytes.data(),independent,30);m->next=make_packet(24);memcpy(m->next->bytes.data(),independent+30,24);m->pklen=54;
  good=ieee80211_input_mgmt_protect(&ic,&ni,m,&rx);assert(good&&good->m_len==36&&k->k_mgmt_rsc==1);mbuf_freem(good);
 }
 // Unicast HW CCMP strips one IV, checks the independent management PN,
 // and never invokes software decryption on the already-decrypted body.
 ni.ni_rsncipher=IEEE80211_CIPHER_CCMP;ni.ni_pairwise_key.k_cipher=IEEE80211_CIPHER_CCMP;
 for(unsigned replay=0;replay<2;replay++) {
  m=make_packet(36);m->bytes[0]=0xc0;m->bytes[1]=0x40;m->bytes[4]=2;m->bytes[24]=9;m->bytes[27]=0x20;m->bytes[32]=0x17;
  ieee80211_rxinfo rx;rx.rxi_flags=IEEE80211_RXI_HWDEC;good=ieee80211_input_mgmt_protect(&ic,&ni,m,&rx);
  if(replay)assert(!good);else{assert(good&&good->m_len==28&&good->bytes[24]==0x17&&!(good->bytes[1]&0x40));mbuf_freem(good);}
 }
 assert(ni.ni_pairwise_key.k_mgmt_rsc==9&&software_ccmp==0&&ic.ic_stats.is_ccmp_replays==1);
 {m=make_packet(36);m->bytes[0]=0xc0;m->bytes[1]=0x40;m->bytes[4]=2;ieee80211_rxinfo rx;assert(!ieee80211_input_mgmt_protect(&ic,&ni,m,&rx)&&software_ccmp==1);}
 // Clear robust actions are rejected; the standard non-robust categories pass.
 for(unsigned category=0;category<256;category++)for(unsigned group=0;group<2;group++) {
  m=make_packet(25);m->bytes[0]=0xd0;m->bytes[4]=group?0xff:2;m->bytes[24]=category;ieee80211_rxinfo rx;
  good=ieee80211_input_mgmt_protect(&ic,&ni,m,&rx);
  bool exempt=category==4||category==7||category==11||category==15||category==20||category==21||category==22||category==127;
  assert(bool(good)==exempt);if(good)mbuf_freem(good);
 }
 // Real TX frame construction selects protection using the same category
 // policy, requires installed PMF keys, and preserves ordinary management.
 ic.ic_if.if_start=start;
 for(unsigned active=0;active<2;active++)for(unsigned category=0;category<256;category++)for(unsigned group=0;group<2;group++) {
  ni.ni_flags=active?IEEE80211_NODE_TXMGMTPROT:0;ni.ni_macaddr[0]=group?0xff:2;
  m=make_packet(2);m->bytes[0]=category;
  assert(ieee80211_mgmt_output(&ic.ic_if,&ni,m,IEEE80211_FC0_SUBTYPE_ACTION)==0&&queued==m);
  bool exempt=category==4||category==7||category==11||category==15||category==20||category==21||category==22||category==127;
  assert(bool(queued->bytes[1]&0x40)==bool(active&&!exempt));mbuf_freem(queued);queued=nullptr;
 }
 // HTC is authenticated as bytes following the 24-byte BIP header, while
 // Retry/PowerManagement/MoreData are masked in AAD (Linux mac80211 contract).
 uint8_t htc_vector[54];assert(fread(htc_vector,1,54,stdin)==54);k->k_mgmt_rsc=0;
 ni.ni_flags=IEEE80211_NODE_RXMGMTPROT;m=make_packet(54);memcpy(m->bytes.data(),htc_vector,54);ieee80211_rxinfo htc_rx;
 good=ieee80211_input_mgmt_protect(&ic,&ni,m,&htc_rx);assert(good&&good->m_len==36);mbuf_freem(good);
 // A fragmented body is included in CMAC and preserved when appending MMIE.
 k->k_tsc=0;m=make_packet(26);m->bytes[0]=0xc0;memset(m->bytes.data()+4,0xff,6);m->bytes[24]=0x50;m->bytes[25]=0x51;
 m->next=make_packet(10);for(unsigned i=0;i<10;i++)m->next->bytes[i]=i+0x52;m->pklen=36;
 m=ieee80211_bip_encap(&ic,m,k);good=linearize(m);assert(good->m_len==54&&!memcmp(good->bytes.data(),independent,54));mbuf_freem(good);
 k->k_tsc=0xfffffffffffeULL;m=make_packet(26);m->bytes[0]=0xc0;memset(m->bytes.data()+4,0xff,6);m=ieee80211_bip_encap(&ic,m,k);assert(m&&k->k_tsc==0xffffffffffffULL);mbuf_freem(m);
 m=make_packet(26);assert(!ieee80211_bip_encap(&ic,m,k)&&k->k_tsc==0xffffffffffffULL);
 ieee80211_bip_delete_key(&ic,k);ieee80211_bip_delete_key(&ic,&ic.ic_nw_keys[5]);assert(!k->k_priv&&!ic.ic_nw_keys[5].k_priv);
 puts("PASS real BIP independent MIC vector, replay/tamper/key-id/IPN exhaustion; PMF HW/SW routing and unicast PN check; non-robust actions and chained TX");
}
'''

with tempfile.TemporaryDirectory() as directory:
    directory = Path(directory)
    stubs = directory / "stubs"
    (stubs / "sys").mkdir(parents=True)
    (stubs / "IOKit").mkdir()
    (stubs / "sys/systm.h").write_text("#include <cstring>\n#include <cstdlib>\n#include <cstdint>\n")
    (stubs / "IOKit/IOLib.h").write_text("")
    source = directory / "test.cpp"
    ieee_header=(NET/'ieee80211.h').read_text()
    categories=ieee_header[ieee_header.index('enum {\n\tIEEE80211_CATEG_SPECTRUM'):ieee_header.index('/*\n * Block Ack Action field values')]
    source.write_text(STUB + categories + function(NET/'ieee80211_output.c','ieee80211_mgmt_output') + "\n".join(function(NET / "ieee80211_crypto_bip.c", n)
        for n in ["ieee80211_bip_set_key", "ieee80211_bip_delete_key",
                  "ieee80211_bip_encap", "ieee80211_bip_decap"]) +
        function(NET / "ieee80211_crypto.c", "ieee80211_get_rxkey") +
        function(NET / "ieee80211_crypto.c", "ieee80211_decrypt") +
        function(NET / "ieee80211_crypto_ccmp.c", "ieee80211_ccmp_get_pn") +
        function(NET / "ieee80211_input.c", "ieee80211_input_hwdecrypt") +
        function(NET / "ieee80211_input.c", "ieee80211_input_mgmt_protect") + MAIN)
    binary = directory / "test"
    crypto = ROOT / "mtk80211/openbsd/crypto"
    subprocess.run(["clang++", "-std=c++14", "-I", str(stubs), "-I", str(crypto.parent),
        "-I", str(crypto), "-fsanitize="+os.environ.get('MTK_TEST_SANITIZERS','address,undefined'), "-fno-sanitize-recover=all",
        str(source), str(crypto / "aes.c"), str(crypto / "cmac.c"),
        "-o", str(binary)], check=True)
    header=bytes([0xc0,0])+bytes(2)+bytes([0xff])*6+bytes(14)
    body=bytes(range(0x50,0x5c))
    mmie=bytes([76,16,4,0,1])+bytes(13)
    aad=header[:2]+header[4:22]
    mic=reference_cmac(bytes(range(1,17)),aad+body+mmie)[:8]
    expected=header+body+mmie[:10]+mic
    htc_header=bytes([0xd0,0xb8])+header[2:]
    htc_body=bytes([1,2,3,4,8,0,0,0,0,0,0,0])
    htc_aad=bytes([0xd0,0x80])+header[4:22]
    htc_mic=reference_cmac(bytes(range(1,17)),htc_aad+htc_body+mmie)[:8]
    htc_vector=htc_header+htc_body+mmie[:10]+htc_mic
    result = subprocess.run([str(binary)], input=expected+htc_vector, capture_output=True)
    print(result.stdout.decode(), end="")
    print(result.stderr.decode(), end="")
    result.check_returncode()
    assert bytes.fromhex(result.stdout.splitlines()[0].decode())==expected
