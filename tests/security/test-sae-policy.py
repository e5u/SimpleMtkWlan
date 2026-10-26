#!/usr/bin/env python3
"""Execute real SAE selection and authentication-building functions."""
from pathlib import Path
import re
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
NET = ROOT / "mtk80211/openbsd/net80211"


def function(path, name, result="void"):
    text = path.read_text()
    match = re.search(r"(?m)^" + name + r"\([^;]*?\)\n\{", text)
    assert match, name
    brace = text.index("{", match.end() - 2)
    depth, end = 1, brace + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return result + "\n" + text[match.start():end]


STUB = r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
using u_int32_t=uint32_t;using u_int8_t=uint8_t;using u_int16_t=uint16_t;using u_int=unsigned;
static const uint8_t IEEE80211_OUI[]={0,0x0f,0xac},MICROSOFT_OUI[]={0,0x50,0xf2};
enum ieee80211_akm {IEEE80211_AKM_NONE,IEEE80211_AKM_8021X=1,
 IEEE80211_AKM_PSK=2,IEEE80211_AKM_SHA256_8021X=4,
 IEEE80211_AKM_SHA256_PSK=8,IEEE80211_AKM_SAE=16};
#define IEEE80211_F_PSK 1
#define IEEE80211_F_WPA3 2
#define IEEE80211_F_MFPR 4
#define IEEE80211_F_PBAR 8
#define IEEE80211_C_MFP 1
#define IEEE80211_NODE_MFP 2
#define IEEE80211_NODE_PMKID 4
#define IEEE80211_NODE_PMK 8
#define IEEE80211_RSNCAP_MFPC 0x80
#define IEEE80211_RSNCAP_MFPR 0x40
#define IEEE80211_RSNCAP_PTKSA_RCNT_MASK 3
#define IEEE80211_RSNCAP_GTKSA_RCNT_MASK 0xc
#define IEEE80211_PROTO_RSN 1
#define IEEE80211_PROTO_WPA 2
#define IEEE80211_CIPHER_USEGROUP 0
#define IEEE80211_CIPHER_TKIP 1
#define IEEE80211_CIPHER_CCMP 2
#define IEEE80211_CIPHER_BIP 3
#define IEEE80211_CIPHER_WEP40 4
#define IEEE80211_CIPHER_WEP104 5
#define IEEE80211_RSNCAP_PBAC 0x100
#define IEEE80211_ELEMID_VENDOR 221
#define IEEE80211_KDE_PMKID 4
#define RSNA_SUPP_INITIALIZE 0
#define RSNA_SUPP_PTKNEGOTIATING 1
#define IEEE80211_NODE_RSN_NEW_PTK 0x10
#define IEEE80211_AUTH_SAE_COMMIT 1
#define IEEE80211_AUTH_SAE_CONFIRM 2
#define IEEE80211_AUTH_ALG_OPEN 0
#define IEEE80211_AUTH_OPEN_REQUEST 1
#define IEEE80211_AUTH_ALG_SAE 3
#define IEEE80211_STATUS_SAE_ANTI_CLOGGING 76
#define IEEE80211_SAE_COMMIT_LEN 98
#define IEEE80211_SAE_CONFIRM_LEN 34
#define IEEE80211_PMK_LEN 32
#define IEEE80211_PMKID_LEN 16
#define EAPOL_KEY_NONCE_LEN 32
#define IEEE80211_ADDR_EQ(a,b) (!memcmp(a,b,6))
#define LE_WRITE_2(p,v) do{(p)[0]=(v);(p)[1]=(v)>>8;}while(0)
#define BE_READ_8(p) (0)
#define BE_READ_2(p) (((p)[0]<<8)|(p)[1])
#define panic(...) abort()
#define XYLog(...) ((void)0)
#define DPRINTF(...) ((void)0)
#define explicit_bzero(p,n) memset(p,0,n)
#define IEEE80211_STA_ONLY 1
#define MBUF_DONTWAIT 0
#define MT_DATA 0
#define mtod(m,t) ((t)((m)->data.data()+24))
enum ieee80211_cipher { ieee80211_cipher_min=0,ieee80211_cipher_max=5 };
enum ieee80211_state {IEEE80211_S_INIT,IEEE80211_S_SCAN,IEEE80211_S_AUTH,IEEE80211_S_ASSOC,IEEE80211_S_RUN};
#define IEEE80211_M_STA 1
#define IEEE80211_AUTH_ALG_OPEN 0
#define IEEE80211_FC0_SUBTYPE_AUTH 0xb0
#define IEEE80211_FC0_SUBTYPE_MASK 0xf0
#define IEEE80211_REASON_UNSPECIFIED 1
#define LE_READ_2(p) ((p)[0]|((p)[1]<<8))
#define IEEE80211_SEND_MGMT(ic,ni,type,seq) fake_send_mgmt(ic,ni,type,seq)
struct ieee80211_frame {uint8_t i_fc[2],dur[2],i_addr1[6],i_addr2[6],i_addr3[6],seq[2];};
struct ieee80211_rxinfo {};

struct ieee80211_sae {uint8_t pmk[32],pmkid[16],peer_addr[6],own_addr[6];bool confirmed,peer_ready,pwe_ready;uint16_t token_len;};
struct ieee80211_pmk {uint8_t pmk_key[32],pmk_pmkid[16];};
struct ieee80211_node {
 uint32_t ni_rsnprotos,ni_rsnakms,ni_rsnciphers,ni_flags,ni_rsncaps;
 ieee80211_cipher ni_rsncipher;int ni_rsngroupcipher,ni_rsngroupmgmtcipher,ni_rsn_supp_state;bool ni_replaycnt_ok;uint64_t ni_replaycnt;
 uint8_t ni_bssid[6],ni_macaddr[6],ni_pmk[32],ni_pmkid[16],ni_nonce[32];
};
struct _ifnet {int if_flags;};
struct ieee80211com {
 uint32_t ic_flags,ic_userflags,ic_caps,ic_rsnprotos,ic_rsnakms,ic_rsnciphers;
 int ic_rsngroupmgmtcipher,ic_opmode,ic_state,ic_deauth_reason,ic_assoc_status;uint8_t ic_myaddr[6],ic_nonce[32];
 ieee80211_sae ic_sae;bool ic_sae_pmk_valid,ic_sae_confirm_ready,ic_sae_confirm_sent;
 uint8_t ic_sae_password[255],ic_sae_password_len;ieee80211_node *ic_bss;
 uint8_t ic_psk[32];
 struct {int is_rx_eapol_replay,is_rx_auth_fail,is_rx_bad_auth,is_rx_auth_unsupported;}ic_stats;
 _ifnet ic_if;
};
struct ieee80211_ptk {uint8_t kck[16];};
struct ieee80211_eapol_key {uint8_t pad[16],nonce[32];uint8_t replaycnt[8],paylen[2];};
static ieee80211_eapol_key empty_key{};
struct mbuf {std::vector<uint8_t> data;size_t chain_tail=0;};using mbuf_t=mbuf*;
static int sent,started,pmkcache,ptkcalls,msg2calls;
static int initcalls,clearcalls,token_calls,commit_calls,confirm_calls,open_calls,newstate_calls,try_bss_calls;
static int start_error,commit_error,confirm_error;
static std::vector<int> tx_seqs;
static void fake_send_mgmt(ieee80211com*,ieee80211_node*,int,int);
static size_t mbuf_len(mbuf_t m){return m->data.size()-24;}
static size_t mbuf_pkthdr_len(mbuf_t m){return mbuf_len(m)+m->chain_tail;}
static void ieee80211_sae_clear(ieee80211_sae*s){++clearcalls;memset(s,0,sizeof(*s));}
static int ieee80211_sae_start(ieee80211_sae*s,const uint8_t*own,const uint8_t*peer,const uint8_t*,size_t n){
 ++initcalls;memset(s,0,sizeof(*s));if(!n||start_error)return -1;
 memcpy(s->own_addr,own,6);memcpy(s->peer_addr,peer,6);s->pwe_ready=true;return 0;}
static int ieee80211_sae_set_token(ieee80211_sae*s,const uint8_t*p,size_t n){
 ++token_calls;if(n<3||n>258||LE_READ_2(p)!=19)return -1;s->token_len=n-2;return 0;}
static int ieee80211_sae_process_commit(ieee80211_sae*s,const uint8_t*,size_t n){
 ++commit_calls;if(n!=98||commit_error)return -1;s->peer_ready=true;return 0;}
static int ieee80211_sae_check_confirm(ieee80211_sae*s,const uint8_t*,size_t n){
 ++confirm_calls;if(n!=34||confirm_error)return -1;s->confirmed=true;return 0;}
static void ieee80211_try_another_bss(ieee80211com*){++try_bss_calls;}
static void ieee80211_new_state(ieee80211com*ic,int n,int){++newstate_calls;ic->ic_state=n;}
static void ieee80211_auth_open(ieee80211com*,const ieee80211_frame*,ieee80211_node*,ieee80211_rxinfo*,int,int){++open_calls;}

static size_t ieee80211_sae_commit_length(const ieee80211_sae*s){return 98+s->token_len;}
static int ieee80211_sae_write_commit(ieee80211_sae*s,uint8_t*out,size_t n){assert(n==98+s->token_len);++started;memset(out,0x5a,n);return 0;}
static int ieee80211_sae_write_confirm(ieee80211_sae*,uint8_t*out){++sent;memset(out,0xa5,34);return 0;}
static mbuf_t ieee80211_getmgmt(int,int,size_t n){auto*m=new mbuf;m->data.resize(n+24);return m;}
static void mbuf_pkthdr_setlen(mbuf_t m,size_t n){m->data.resize(n+24);}
static void mbuf_setlen(mbuf_t,size_t){}
static void mbuf_freem(mbuf_t m){delete m;}
static ieee80211_pmk *ieee80211_pmksa_find(ieee80211com*,ieee80211_node*,const uint8_t*){
 static ieee80211_pmk p;memset(p.pmk_key,0xe1,32);++pmkcache;return &p;}
static int ieee80211_derive_ptk(ieee80211_akm akm,ieee80211_cipher cipher,const uint8_t*pmk,
 const uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,ieee80211_ptk*){
 ++ptkcalls;assert(akm==IEEE80211_AKM_SAE);assert(!memcmp(pmk,"PMK",3));assert(cipher==IEEE80211_CIPHER_CCMP);return 0;}
static int ieee80211_send_4way_msg2(ieee80211com*,ieee80211_node*,const void*,
 const ieee80211_ptk*){++msg2calls;return 0;}
static bool ieee80211_is_8021x_akm(ieee80211_akm akm){return akm==1||akm==4;}
static uint8_t ieee80211_key_check(const uint8_t*,size_t){return 0;}
static const char *ether_sprintf(const uint8_t*){return "peer";}
static const int IFF_DEBUG=0;
'''

MAIN = r'''
static ieee80211com ic{};static ieee80211_node ni{};
static void setup(){
 memset(&ic,0,sizeof(ic));memset(&ni,0,sizeof(ni));sent=started=0;tx_seqs.clear();
 ic.ic_bss=&ni;ic.ic_opmode=IEEE80211_M_STA;ic.ic_state=IEEE80211_S_AUTH;
 ic.ic_myaddr[0]=2;ic.ic_rsnprotos=IEEE80211_PROTO_RSN;ic.ic_rsnciphers=IEEE80211_CIPHER_CCMP;
 ic.ic_rsngroupmgmtcipher=IEEE80211_CIPHER_BIP;ic.ic_caps=IEEE80211_C_MFP;
 ic.ic_sae_pmk_valid=true;ic.ic_sae.confirmed=true;
 memset(ic.ic_sae.pmk,0x4d,32);ic.ic_sae.pmk[0]='P';ic.ic_sae.pmk[1]='M';ic.ic_sae.pmk[2]='K';
 memcpy(ic.ic_sae.pmkid,"PMKID exactly 16",16);memcpy(ic.ic_sae.peer_addr,ni.ni_macaddr,6);
 ni.ni_rsncipher=(ieee80211_cipher)IEEE80211_CIPHER_CCMP;ni.ni_rsngroupmgmtcipher=IEEE80211_CIPHER_BIP;
 ni.ni_rsnprotos=IEEE80211_PROTO_RSN;ni.ni_rsnciphers=IEEE80211_CIPHER_CCMP;ni.ni_rsngroupcipher=IEEE80211_CIPHER_CCMP;
 ni.ni_rsnakms=IEEE80211_AKM_SAE;ni.ni_rsncaps=IEEE80211_RSNCAP_MFPC;ni.ni_macaddr[0]=0xa8;
 memcpy(ni.ni_bssid,ni.ni_macaddr,6);memcpy(ic.ic_sae.own_addr,ic.ic_myaddr,6);
 memcpy(ic.ic_sae.peer_addr,ni.ni_macaddr,6);ni.ni_rsn_supp_state=RSNA_SUPP_PTKNEGOTIATING;
}
static void fake_send_mgmt(ieee80211com*ic,ieee80211_node*ni,int type,int seq){
 assert(type==IEEE80211_FC0_SUBTYPE_AUTH);auto*m=ieee80211_get_auth(ic,ni,0,seq);
 if(m){tx_seqs.push_back(seq);mbuf_freem(m);}}
static mbuf_t auth_frame(int algo,int seq,int status,size_t n){
 auto*m=ieee80211_getmgmt(0,0,24+6+n);auto*w=mtod(m,ieee80211_frame*);
 w->i_fc[0]=IEEE80211_FC0_SUBTYPE_AUTH;memcpy(w->i_addr1,ic.ic_myaddr,6);
 memcpy(w->i_addr2,ni.ni_macaddr,6);memcpy(w->i_addr3,ni.ni_bssid,6);
 uint8_t*p=(uint8_t*)(w+1);LE_WRITE_2(p,algo);p+=2;LE_WRITE_2(p,seq);p+=2;LE_WRITE_2(p,status);
 return m;
}
int main(){
 uint8_t psk[]={0,0x0f,0xac,2},sae[]={0,0x0f,0xac,8},ft[]={0,0x0f,0xac,4};
 assert(ieee80211_parse_rsn_akm(psk)==IEEE80211_AKM_PSK);
 assert(ieee80211_parse_rsn_akm(sae)==IEEE80211_AKM_SAE);
 assert(ieee80211_parse_rsn_akm(ft)==IEEE80211_AKM_NONE);
 setup();ic.ic_bss=&ni;ni.ni_rsnakms|=IEEE80211_AKM_PSK;ic.ic_rsnakms=ni.ni_rsnakms;ic.ic_flags=IEEE80211_F_PSK;
 ieee80211_choose_rsnparams(&ic);assert(ni.ni_rsnakms==IEEE80211_AKM_PSK);
 setup();ic.ic_bss=&ni;ni.ni_rsnakms|=IEEE80211_AKM_PSK;ic.ic_rsnakms=ni.ni_rsnakms;ic.ic_flags=IEEE80211_F_PSK;
 ic.ic_userflags=IEEE80211_F_WPA3;ieee80211_choose_rsnparams(&ic);
 assert(ni.ni_rsnakms==IEEE80211_AKM_PSK&&(ni.ni_flags&IEEE80211_NODE_MFP));
 setup();ic.ic_bss=&ni;ni.ni_rsnakms|=IEEE80211_AKM_PSK;ic.ic_rsnakms=ni.ni_rsnakms;ic.ic_flags=IEEE80211_F_PSK;
 ic.ic_userflags=IEEE80211_F_WPA3;ic.ic_sae_password_len=8;ieee80211_choose_rsnparams(&ic);
 assert(ni.ni_rsnakms==IEEE80211_AKM_SAE&&(ni.ni_flags&IEEE80211_NODE_MFP));
 uint8_t ie[128]{};auto*end=ieee80211_add_rsn_body(ie,&ic,&ni,0);
 assert(end-ie==26&&ie[14]==0&&ie[15]==0x0f&&ie[16]==0xac&&ie[17]==8);
 ic.ic_flags|=IEEE80211_F_MFPR;end=ieee80211_add_rsn_body(ie,&ic,&ni,0);
 assert(end-ie==26&&(ie[18]&0xc0)==0xc0&&ie[20]==0&&ie[21]==0&&ie[25]==6);
 // MFP is negotiated with the AP, not implied by local MFP support.
 setup();ni.ni_rsnakms=IEEE80211_AKM_PSK;ni.ni_rsncaps=0;ic.ic_flags=IEEE80211_F_MFPR;
 end=ieee80211_add_rsn_body(ie,&ic,&ni,0);
 assert(end-ie==20&&(ie[18]&0xc0)==0);
 ni.ni_rsncaps=IEEE80211_RSNCAP_MFPC;end=ieee80211_add_rsn_body(ie,&ic,&ni,0);
 assert(end-ie==26&&(ie[18]&0xc0)==0xc0&&ie[25]==6);
 ic.ic_caps=0;end=ieee80211_add_rsn_body(ie,&ic,&ni,0);
 assert(end-ie==20&&(ie[18]&0xc0)==0);
 setup();ic.ic_bss=&ni;ic.ic_rsnakms=IEEE80211_AKM_SAE;ic.ic_userflags=IEEE80211_F_WPA3;
 assert(ieee80211_choose_rsnparams(&ic)==EINVAL&&ni.ni_rsnakms==0); // no password
 setup();ic.ic_bss=&ni;ic.ic_rsnakms=IEEE80211_AKM_SAE;ic.ic_userflags=IEEE80211_F_WPA3;ic.ic_sae_password_len=8;ni.ni_rsncaps=0;
 assert(ieee80211_choose_rsnparams(&ic)==EINVAL&&ni.ni_rsnakms==0); // no PMF
 // SAE-only BSSes must remain scan candidates before the UI has a password.
 setup();ni.ni_rsnakms=IEEE80211_AKM_SAE;ic.ic_rsnakms=IEEE80211_AKM_SAE;
 ic.ic_userflags=IEEE80211_F_WPA3;ic.ic_flags=0,ic.ic_sae_password_len=0;
 assert(ieee80211_eligible_akms(&ic,&ni)==IEEE80211_AKM_SAE);
 ic.ic_bss=&ni;assert(ieee80211_choose_rsnparams(&ic)==EINVAL&&ni.ni_rsnakms==0);
 setup();ic.ic_bss=&ni;ic.ic_rsnakms=IEEE80211_AKM_SAE;ic.ic_userflags=IEEE80211_F_WPA3;ic.ic_sae_password_len=8;ni.ni_rsngroupcipher=IEEE80211_CIPHER_TKIP;
 assert(ieee80211_choose_rsnparams(&ic)==EINVAL&&ni.ni_rsnakms==0); // SAE has no TKIP fallback
 setup();ic.ic_bss=&ni;ic.ic_rsnakms=IEEE80211_AKM_SAE;ic.ic_userflags=IEEE80211_F_WPA3;ic.ic_sae_password_len=8;ni.ni_rsngroupmgmtcipher=0;
 assert(ieee80211_choose_rsnparams(&ic)==EINVAL&&ni.ni_rsnakms==0); // unsupported IGTK cipher
 setup();ic.ic_bss=&ni;ic.ic_rsnakms=IEEE80211_AKM_PSK;ni.ni_rsnakms=IEEE80211_AKM_PSK;ic.ic_flags=IEEE80211_F_PSK;ni.ni_flags=IEEE80211_NODE_MFP|IEEE80211_NODE_PMKID;ic.ic_caps=0;
 assert(ieee80211_choose_rsnparams(&ic)==0&&!(ni.ni_flags&(IEEE80211_NODE_MFP|IEEE80211_NODE_PMKID)));
 setup();ic.ic_userflags=IEEE80211_F_WPA3;
 assert(ieee80211_get_auth(&ic,&ni,0,IEEE80211_AUTH_SAE_CONFIRM)==nullptr);
 assert(ieee80211_get_auth(&ic,&ni,0,9)==nullptr);
 assert(ieee80211_get_auth(&ic,&ni,1,IEEE80211_AUTH_SAE_COMMIT)==nullptr);
 auto*m=ieee80211_get_auth(&ic,&ni,0,IEEE80211_AUTH_SAE_COMMIT);
 assert(m&&mtod(m,uint8_t*)[0]==3&&mtod(m,uint8_t*)[2]==1);
 assert(m->data.size()==24+6+98&&started==1);mbuf_freem(m);
 ic.ic_sae.peer_ready=true;m=ieee80211_get_auth(&ic,&ni,0,IEEE80211_AUTH_SAE_COMMIT);
 assert(m&&mtod(m,uint8_t*)[2]==1&&started==2&&ic.ic_sae_confirm_ready);
 assert(m->data.size()==24+6+98);mbuf_freem(m);
 m=ieee80211_get_auth(&ic,&ni,0,IEEE80211_AUTH_SAE_CONFIRM);
 assert(m&&mtod(m,uint8_t*)[2]==2&&sent==1&&ic.ic_sae_confirm_sent);mbuf_freem(m);
 ic.ic_sae.token_len=256;m=ieee80211_get_auth(&ic,&ni,0,IEEE80211_AUTH_SAE_COMMIT);
 assert(m&&m->data.size()==24+6+98+256);mbuf_freem(m);
 setup();ieee80211_recv_4way_msg1(&ic,&empty_key,&ni);
 assert(!memcmp(ni.ni_pmk,ic.ic_sae.pmk,32)&&ptkcalls==1&&msg2calls==1);
 ni.ni_flags=0;ic.ic_sae.confirmed=false;ieee80211_recv_4way_msg1(&ic,&empty_key,&ni);
 assert(!(ni.ni_flags&IEEE80211_NODE_PMK)&&ptkcalls==1&&msg2calls==1);
 // The shared sequence1 request must still use the selected SAE algorithm.
 setup();ic.ic_userflags=IEEE80211_F_WPA3;tx_seqs.clear();
 fake_send_mgmt(&ic,&ni,IEEE80211_FC0_SUBTYPE_AUTH,IEEE80211_AUTH_OPEN_REQUEST);
 assert(tx_seqs==std::vector<int>{1}&&started==1);
 setup();ic.ic_sae_pmk_valid=false;ieee80211_recv_4way_msg1(&ic,&empty_key,&ni);
 assert(!(ni.ni_flags&IEEE80211_NODE_PMK)&&ptkcalls==1&&msg2calls==1);
 // Fresh SAE auth clears old secrets; retransmission keeps the same exchange.
 setup();ic.ic_userflags=IEEE80211_F_WPA3;ic.ic_sae_password_len=8;ni.ni_flags=IEEE80211_NODE_PMK|IEEE80211_NODE_PMKID;
 assert(ieee80211_sae_prepare_auth(&ic,&ni,IEEE80211_S_SCAN)==0&&initcalls==1);
 assert(!ic.ic_sae_pmk_valid&&!ic.ic_sae_confirm_sent&&!ic.ic_sae_confirm_ready&&ni.ni_flags==0);
 for(auto x:ni.ni_pmk)assert(x==0);
 ic.ic_sae.token_len=12;ic.ic_sae.peer_ready=true;ic.ic_sae_confirm_ready=true;
 assert(ieee80211_sae_prepare_auth(&ic,&ni,IEEE80211_S_AUTH)==0&&initcalls==1);
 assert(ic.ic_sae.token_len==12&&ic.ic_sae.peer_ready&&ic.ic_sae_confirm_ready);
 ni.ni_macaddr[1]=1;
 assert(ieee80211_sae_prepare_auth(&ic,&ni,IEEE80211_S_AUTH)==0&&initcalls==2&&ic.ic_sae.token_len==0);
 ni.ni_rsnakms=IEEE80211_AKM_PSK;
 assert(ieee80211_sae_prepare_auth(&ic,&ni,IEEE80211_S_AUTH)==0&&clearcalls==1&&!ic.ic_sae.pwe_ready);
 // Actual receive-auth routing: bound peer, token retry, commit/confirm, no Open downgrade.
 setup();ic.ic_userflags=IEEE80211_F_WPA3;ic.ic_sae.confirmed=false;
 m=auth_frame(3,1,76,18);auto*p=mtod(m,uint8_t*)+30;p[0]=19;
 ieee80211_recv_auth(&ic,m,&ni,nullptr);assert(token_calls==1&&tx_seqs==std::vector<int>{1}&&ic.ic_sae.token_len==16);mbuf_freem(m);
 m=auth_frame(3,1,0,98);ieee80211_recv_auth(&ic,m,&ni,nullptr);
 assert(commit_calls==1&&tx_seqs==std::vector<int>({1,1,2})&&ic.ic_sae_confirm_sent);mbuf_freem(m);
 m=auth_frame(3,2,0,34);confirm_error=1;ieee80211_recv_auth(&ic,m,&ni,nullptr);
 assert(newstate_calls==0&&!ic.ic_sae.confirmed);confirm_error=0;
 ieee80211_recv_auth(&ic,m,&ni,nullptr);assert(newstate_calls==1&&ic.ic_state==IEEE80211_S_ASSOC&&ic.ic_sae_pmk_valid&&(ni.ni_flags&IEEE80211_NODE_PMKID));mbuf_freem(m);
 setup();ic.ic_userflags=IEEE80211_F_WPA3;ic.ic_sae.confirmed=false;
 m=auth_frame(0,2,0,0);ieee80211_recv_auth(&ic,m,&ni,nullptr);assert(open_calls==0);mbuf_freem(m);
 m=auth_frame(3,1,0,98);mtod(m,ieee80211_frame*)->i_addr1[0]^=1;
 ieee80211_recv_auth(&ic,m,&ni,nullptr);assert(commit_calls==1);mbuf_freem(m);
 m=auth_frame(3,1,0,98);m->chain_tail=8;ieee80211_recv_auth(&ic,m,&ni,nullptr);assert(commit_calls==1);mbuf_freem(m);
 m=auth_frame(3,1,1,0);ieee80211_recv_auth(&ic,m,&ni,nullptr);
 assert(try_bss_calls==1&&!ic.ic_sae_pmk_valid&&!ic.ic_sae_confirm_sent&&!ic.ic_sae_confirm_ready);mbuf_freem(m);
 puts("PASS real SAE selection, auth RX/TX, anti-clogging routing, retry lifecycle and four-way PMK binding.");
}
'''

def build_source():
    source = STUB
    for path, name, result in [
        (NET / "ieee80211_input.c", "ieee80211_parse_rsn_akm", "static int"),
        (NET / "ieee80211_node.c", "ieee80211_eligible_akms", "static u_int32_t"),
        (NET / "ieee80211_node.c", "ieee80211_choose_rsnparams", "int"),
        (NET / "ieee80211_output.c", "ieee80211_get_auth", "static mbuf_t"),
        (NET / "ieee80211_output.c", "ieee80211_add_rsn_body", "static uint8_t *"),
        (NET / "ieee80211_input.c", "ieee80211_recv_auth", "void"),
        (NET / "ieee80211_proto.c", "ieee80211_sae_prepare_auth", "static int"),
        (NET / "ieee80211_pae_input.c", "ieee80211_recv_4way_msg1", "void")]:
        source += function(path, name, result)
    return source + MAIN

source = build_source()

with tempfile.TemporaryDirectory(prefix="mtk-sae-policy-") as directory:
    path = Path(directory) / "test.cpp"
    path.write_text(source)
    binary = path.with_suffix("")
    subprocess.run(["clang++", "-std=c++14", "-fsanitize=" + os.environ.get("MTK_TEST_SANITIZERS", "address,undefined"),
                    "-fno-sanitize-recover=all", str(path), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)
