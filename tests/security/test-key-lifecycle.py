#!/usr/bin/env python3
"""Run real HAL key queue/MCU completion and PMF controlled-port decisions."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / 'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text()


def function(source, name):
    match = re.search(r'(?m)^(?:static )?(?:int|void)\n' + name + r'\([^;]+?\)\s*\{', source)
    assert match, name
    end = source.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


STUB = r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <vector>
#define nitems(a) (sizeof(a)/sizeof((a)[0]))
#define explicit_bzero(p,n) memset(p,0,n)
#define DPRINTF(...) ((void)0)
#define MWX_DEV_LOG(...) ((void)0)
#define DEVNAME(sc) "test"
#define IEEE80211_KEY_GROUP 1
#define IEEE80211_KEY_IGTK 4
#define IEEE80211_KEY_SWCRYPTO 0x80
#define IEEE80211_CIPHER_NONE 0
#define IEEE80211_CIPHER_CCMP 8
#define IEEE80211_CIPHER_BIP 0x20
#define IEEE80211_NODE_RXMGMTPROT 0x20
#define IEEE80211_NODE_TXMGMTPROT 0x40
#define IEEE80211_NODE_MFP 0x80
#define IEEE80211_S_SCAN 1
#define IEEE80211_S_RUN 4
#define LINK_STATE_DOWN 0
#define LINK_STATE_UP 1
#define IEEE80211_FC0_SUBTYPE_DEAUTH 0xc0
#define IEEE80211_REASON_AUTH_LEAVE 3
#define MCU_UNI_CMD_STA_REC_UPDATE 7
struct ieee80211_key{uint8_t k_id=0,k_len=16;int k_cipher=8;unsigned k_flags=0;uint8_t k_key[32]={};void*k_priv=nullptr;};
struct ieee80211_node{unsigned ni_flags=0;int ni_port_valid=0,refs=1;ieee80211_key ni_pairwise_key;uint8_t ni_macaddr[6]={};};
struct mwx_node{ieee80211_node ni;uint16_t wcid=1,flags=0;};
struct mwx_vif{mwx_node vif_mn;uint8_t idx=0;};
struct ieee80211com{void*ic_softc=nullptr;ieee80211_node*ic_bss=nullptr;int ic_state=IEEE80211_S_RUN,ic_igtk_kid=0;ieee80211_key ic_nw_keys[6];};
struct mwx_setkey_task_arg{ieee80211_node*ni=nullptr;ieee80211_key*k=nullptr;ieee80211_key snapshot;};
struct mwx_softc{ieee80211com sc_ic;mwx_vif sc_vif;int sc_setkey_cur=0,sc_setkey_tail=0,sc_nswq=0,sc_setkey_task=0,sc_ns_state=IEEE80211_S_RUN;mwx_setkey_task_arg sc_setkey_arg[8];ieee80211_node*sc_setkey_inflight=nullptr;};
static int live_contexts=0,setup_result=0,fw_result=0,fw_calls=0,fw_delete_calls=0,link_state=0,deauths=0;
static ieee80211_key*mutate_on_wait=nullptr;
static bool transition_ok=true,cleanup_only=false;
struct MwxRxAmsduTransition{MwxRxAmsduTransition(mwx_softc*){}bool ok(){return transition_ok;}};
static bool mwx_rx_amsdu_key_cleanup_only(mwx_softc*){return cleanup_only;}
static ieee80211_node*ieee80211_ref_node(ieee80211_node*ni){ni->refs++;return ni;}
static void ieee80211_release_node(ieee80211com*,ieee80211_node*ni){assert(ni->refs>1);ni->refs--;}
static int ieee80211_set_key(ieee80211com*,ieee80211_node*,ieee80211_key*k){
 if(setup_result)return setup_result;assert(!k->k_priv);k->k_priv=new int(1);live_contexts++;k->k_flags|=IEEE80211_KEY_SWCRYPTO;return 0;}
static void ieee80211_delete_key(ieee80211com*,ieee80211_node*,ieee80211_key*k){
 if(k->k_priv){delete (int*)k->k_priv;live_contexts--;}memset(k,0,sizeof(*k));}
static void ieee80211_set_link_state(ieee80211com*,int state){link_state=state;}
static void task_add(int,int*){}
static int splnet(){return 0;}static void splx(int){}
static void ieee80211_new_state(ieee80211com*ic,int state,int){((mwx_softc*)ic->ic_softc)->sc_ns_state=state;}
#define IEEE80211_SEND_MGMT(ic,ni,subtype,reason) (++deauths)
struct sta_req_hdr{uint8_t pad[8];};
struct mbuf{unsigned keyid=0,cipher=0;uint16_t wcid=0;uint8_t muar=0;};
struct Record{unsigned id,cipher,wcid,muar;};
static std::vector<Record> records;
static mbuf*mwx_alloc_sta_req_tlv(size_t){return new mbuf;}
static void mt7921_mcu_add_key_tlv(mbuf*m,uint16_t*n,ieee80211_key*k,int){(*n)++;m->keyid=k->k_id;m->cipher=k->k_cipher;}
static mbuf*mwx_fill_sta_req_hdr(mbuf*m,mwx_vif*,uint8_t muar,uint16_t wcid,uint16_t){m->muar=muar;m->wcid=wcid;return m;}
static int mwx_mcu_send_mbuf_wait(mwx_softc*,int,mbuf*m){fw_calls++;records.push_back({m->keyid,m->cipher,m->wcid,m->muar});delete m;if(mutate_on_wait){mutate_on_wait->k_key[0]^=1;mutate_on_wait=nullptr;}return fw_result;}
static int mwx_mcu_send_mbuf(mwx_softc*,int,mbuf*m,void*){fw_delete_calls++;delete m;return 0;}
int mt7921_mcu_sta_key_update(mwx_softc*,ieee80211_node*,ieee80211_key*);
void mt7921_mcu_sta_key_delete(mwx_softc*,ieee80211_node*,ieee80211_key*);
'''

MAIN = r'''
struct Fixture{
 mwx_softc sc;mwx_node mn;
 Fixture(bool pmf=true){sc.sc_ic.ic_softc=&sc;sc.sc_ic.ic_bss=&mn.ni;sc.sc_vif.vif_mn.wcid=19;
  if(pmf)mn.ni.ni_flags=IEEE80211_NODE_MFP;
  for(unsigned i=0;i<6;i++){auto&k=sc.sc_ic.ic_nw_keys[i];k.k_id=i;k.k_flags=i<4?IEEE80211_KEY_GROUP:IEEE80211_KEY_IGTK;k.k_cipher=i<4?IEEE80211_CIPHER_CCMP:IEEE80211_CIPHER_BIP;}
  setup_result=fw_result=fw_calls=fw_delete_calls=link_state=deauths=0;records.clear();}
 ~Fixture(){mwx_cancel_key_tasks(&sc,nullptr,nullptr);assert(mn.ni.refs==1);ieee80211_delete_key(&sc.sc_ic,&mn.ni,&mn.ni.ni_pairwise_key);for(auto&k:sc.sc_ic.ic_nw_keys)ieee80211_delete_key(&sc.sc_ic,&mn.ni,&k);assert(live_contexts==0);}
 void set(ieee80211_key*k){assert(mwx_set_key(&sc.sc_ic,&mn.ni,k)==EBUSY);}
 void pair_group(){set(&mn.ni.ni_pairwise_key);set(&sc.sc_ic.ic_nw_keys[1]);}
 void igtk(unsigned id){set(&sc.sc_ic.ic_nw_keys[id]);sc.sc_ic.ic_igtk_kid=id;}
 void run(){mwx_setkey_task(&sc);assert(mn.ni.refs==1);}
};
int main(){
 {Fixture f;f.pair_group();f.run();assert(fw_calls==2&&!f.mn.ni.ni_port_valid&&!link_state);
  assert(records[0].wcid==1&&records[0].muar==0&&records[1].wcid==19&&records[1].muar==14);
  f.igtk(4);f.run();assert(fw_calls==2&&f.mn.ni.ni_port_valid&&link_state);
  assert((f.mn.ni.ni_flags&0x60)==0x60);
  f.igtk(5);f.run();auto saved=f.mn.flags&0x1f;
  mwx_delete_key(&f.sc.sc_ic,&f.mn.ni,&f.sc.sc_ic.ic_nw_keys[4]);assert(fw_delete_calls==0&&f.mn.ni.ni_port_valid&&(f.mn.flags&0x1f)==saved);
  mwx_delete_key(&f.sc.sc_ic,&f.mn.ni,&f.sc.sc_ic.ic_nw_keys[5]);assert(fw_delete_calls==0&&!f.mn.ni.ni_port_valid&&(f.mn.flags&0x1f)==saved);
  mwx_delete_key(&f.sc.sc_ic,&f.mn.ni,&f.sc.sc_ic.ic_nw_keys[5]);assert(fw_delete_calls==0);}
 {Fixture f(false);f.pair_group();f.run();assert(fw_calls==2&&f.mn.ni.ni_port_valid&&link_state&&!(f.mn.ni.ni_flags&0x60));}
 {Fixture f;f.pair_group();f.igtk(4);fw_result=EIO;f.run();assert(fw_calls==1&&!link_state&&!f.mn.ni.ni_port_valid&&deauths==1);
  assert(!(f.mn.flags&0x7f)&&(f.mn.flags&MWX_NODE_FLAG_KEY_FAILED));}
 {Fixture f;setup_result=ENOMEM;assert(mwx_set_key(&f.sc.sc_ic,&f.mn.ni,&f.mn.ni.ni_pairwise_key)==ENOMEM);assert(f.sc.sc_setkey_cur==0&&f.mn.ni.refs==1&&live_contexts==0);
  setup_result=0;auto*k=&f.sc.sc_ic.ic_nw_keys[4];k->k_id=6;assert(mwx_set_key(&f.sc.sc_ic,&f.mn.ni,k)==EINVAL&&live_contexts==0);}
 {Fixture f;f.pair_group();f.igtk(4);assert(f.mn.ni.refs==4);mwx_cancel_key_tasks(&f.sc,nullptr,nullptr);f.run();assert(fw_calls==0);
  for(auto&a:f.sc.sc_setkey_arg){const auto*p=(const uint8_t*)&a.snapshot;for(unsigned i=0;i<sizeof(a.snapshot);i++)if(&a<&f.sc.sc_setkey_arg[3])assert(p[i]==0);}}
 {Fixture f;auto*k=&f.mn.ni.ni_pairwise_key;f.set(k);k->k_key[0]=7;f.set(k);assert(f.mn.ni.refs==2);f.run();assert(fw_calls==1&&!(f.mn.flags&MWX_NODE_FLAG_KEY_FAILED));}
 {Fixture f;f.pair_group();mutate_on_wait=&f.mn.ni.ni_pairwise_key;f.run();assert(fw_calls==1&&!f.mn.ni.ni_port_valid&&deauths==1&&!(f.mn.flags&0x7f));}
 {Fixture f;f.igtk(4);transition_ok=false;mwx_setkey_task(&f.sc);assert(f.mn.ni.refs==2&&fw_calls==0);transition_ok=true;f.run();assert(!f.mn.ni.ni_port_valid);}
 puts("PASS real HAL key lifecycle: software IGTK preserves GTK/PTK; PMF requires completed keys; WPA2 unchanged; software/MCU failure, stale key, cancellation and node refs");
}
'''

defines = '\n'.join(line for line in SOURCE.splitlines()
                    if re.match(r'#define\s+MWX_NODE_FLAG_', line))
has_igtk = function((ROOT / 'mtk80211/openbsd/net80211/ieee80211_crypto.c').read_text(),
                    'ieee80211_has_igtk')
functions = '\n'.join(function(SOURCE, name) for name in
    ['mwx_cancel_key_tasks', 'mwx_keys_ready', 'mwx_key_update_port', 'mwx_set_key', 'mwx_delete_key',
     'mwx_setkey_task', 'mt7921_mcu_sta_key_update', 'mt7921_mcu_sta_key_delete'])
with tempfile.TemporaryDirectory(prefix='mtk-key-lifecycle-') as directory:
    directory = Path(directory)
    source = directory / 'test.cpp'
    source.write_text(STUB + defines + '\n' + has_igtk + functions + MAIN)
    binary = directory / 'test'
    subprocess.run(['clang++', '-std=c++14', '-g',
        '-fsanitize='+os.environ.get('MTK_TEST_SANITIZERS', 'address,undefined'),
        '-fno-sanitize-recover=all', str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
