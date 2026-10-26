#!/usr/bin/env python3
"""Drive real EAPOL ingress, M3/group handling and egress with independent wire packets."""
from pathlib import Path
import json
import hashlib
import hmac
import re
import struct
import subprocess
import tempfile
from support.crypto_reference import NET, compile_crypto, function, reference_cmac, reference_wrap
from support.eapol_fixture import WIRE_SOURCE, CRYPTO_HELPERS, reference_ptk

KEY_STRUCT = re.search(r"struct ieee80211_key \{.*?\n\};", (NET / "ieee80211_crypto.h").read_text(), re.S)[0]

STUB = r'''
#include <vector>
#include <arpa/inet.h>
static uint16_t host_to_network16(uint16_t v){uint8_t b[2]={uint8_t(v>>8),uint8_t(v)};uint16_t out;memcpy(&out,b,2);return out;}
#define htons(v) host_to_network16(v)
#define IEEE80211_NUM_TID 16
#define IEEE80211_STA_ONLY 1
#define IEEE80211_PROTO_RSN 1
#define IEEE80211_PROTO_WPA 2
#define IEEE80211_M_STA 1
#define IEEE80211_S_SCAN 1
#define IEEE80211_S_RUN 4
#define IEEE80211_NODE_RXPROT 0x8
#define IEEE80211_NODE_TXPROT 0x10
#define IEEE80211_NODE_TXRXPROT 0x18
#define IEEE80211_NODE_MFP 0x80
#define IEEE80211_NODE_PMK 0x100
#define IEEE80211_NODE_RSN_NEW_PTK 0x2000
#define IEEE80211_ELEMID_RSN 48
#define IEEE80211_KDE_GTK 1
#define IEEE80211_KDE_IGTK 9
#define IEEE80211_FC0_SUBTYPE_DEAUTH 0xc0
#define IEEE80211_REASON_AUTH_LEAVE 3
#define IEEE80211_REASON_RSN_DIFFERENT_IE 17
#define IEEE80211_REASON_BAD_PAIRWISE_CIPHER 19
#define LINK_STATE_UP 1
#define LINK_STATE_DOWN 0
#define IFF_DEBUG 0
#define MCLBYTES 4096
#define MBUF_DONTWAIT 0
#define MT_DATA 0
#define ETHERTYPE_PAE 0x888e
#define IEEE80211_IS_MULTICAST(p) ((p)[0]&1)
#define IEEE80211_ADDR_COPY(a,b) memcpy(a,b,6)
#define DPRINTF(...) ((void)0)
#define LE_READ_2(p) ((p)[0]|((p)[1]<<8))
static uint64_t read_be(const uint8_t*p,size_t n){uint64_t v=0;for(size_t i=0;i<n;++i)v=(v<<8)|p[i];return v;}
static uint64_t read_le(const uint8_t*p,size_t n){uint64_t v=0;for(size_t i=0;i<n;++i)v|=(uint64_t)p[i]<<(8*i);return v;}
static void write_be(uint8_t*p,uint64_t v,size_t n){for(size_t i=0;i<n;++i)p[n-1-i]=v>>(8*i);}
#define BE_READ_8(p) read_be(p,8)
#define LE_READ_6(p) read_le(p,6)
#define BE_WRITE_8(p,v) write_be(p,v,8)
static const uint8_t IEEE80211_OUI[]={0,0x0f,0xac},MICROSOFT_OUI[]={0,0x50,0xf2};
static uint8_t ap_rsn[]={48,26,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,8,128,0,0,0,0,15,172,6};
static const uint8_t aa[]={2,0,0,0,0,1},spa[]={2,0,0,0,0,2};
struct ether_header {uint8_t ether_dhost[6],ether_shost[6];uint16_t ether_type;} __attribute__((packed));
struct mbuf {std::vector<uint8_t> buffer;size_t offset=64,length=0;};using mbuf_t=mbuf*;
#define mtod(m,t) ((t)((m)->buffer.data()+(m)->offset))
static mbuf_t packet(size_t length){auto*m=new mbuf;m->buffer.resize(8192);m->length=length;return m;}
static size_t mbuf_len(mbuf_t m){return m->length;}
static size_t mbuf_pkthdr_len(mbuf_t m){return m->length;}
static void mbuf_adj(mbuf_t m,size_t n){assert(n<=m->length);m->offset+=n;m->length-=n;}
static int mbuf_pullup(mbuf_t*,size_t){return 0;}
static void mbuf_freem(mbuf_t m){delete m;}
static void mbuf_prepend(mbuf_t*m,size_t n,int){assert((*m)->offset>=n);(*m)->offset-=n;(*m)->length+=n;}
static void mbuf_pkthdr_setlen(mbuf_t m,size_t n){assert(m->offset+n<=m->buffer.size());m->length=n;}
static void mbuf_setlen(mbuf_t m,size_t n){mbuf_pkthdr_setlen(m,n);}
static mbuf_t ieee80211_get_eapol_key(int,int,unsigned n){return packet(sizeof(ieee80211_eapol_key)+n);}
static std::vector<std::vector<uint8_t>> transmitted;
static int ifq_enqueue(int*,mbuf_t m){transmitted.emplace_back(mtod(m,uint8_t*),mtod(m,uint8_t*)+m->length);mbuf_freem(m);return 0;}
struct _ifnet {int if_flags=0,if_ibytes=0,if_imcasts=0,if_snd=0;char if_xname[8]="test";void(*if_start)(_ifnet*);};
static void start(_ifnet*){}
struct ieee80211_node {
 int ni_rsnprotos=IEEE80211_PROTO_RSN,ni_rsnakms=IEEE80211_AKM_SAE,ni_rsnciphers=IEEE80211_CIPHER_CCMP;
 enum ieee80211_cipher ni_rsncipher=IEEE80211_CIPHER_CCMP,ni_rsngroupcipher=IEEE80211_CIPHER_CCMP,ni_rsngroupmgmtcipher=IEEE80211_CIPHER_BIP;
 uint32_t ni_flags=IEEE80211_NODE_PMK|IEEE80211_NODE_MFP|IEEE80211_NODE_RSN_NEW_PTK;
 int ni_rsn_supp_state=1,ni_port_valid=0,ni_assoc_fail=0;bool ni_replaycnt_ok=false;uint64_t ni_replaycnt=0;
 uint8_t ni_pmk[32]={},ni_nonce[32]={},ni_macaddr[6]={};const uint8_t*ni_rsnie=ap_rsn;
 ieee80211_ptk ni_ptk{};ieee80211_key ni_pairwise_key{};
};
#define RSNA_SUPP_PTKNEGOTIATING 1
#define RNSA_SUPP_PTKDONE 2
struct ieee80211com {
 _ifnet ic_if;uint8_t ic_globalcnt[32]={},ic_nonce[32]={},ic_myaddr[6]={};
 int ic_opmode=IEEE80211_M_STA,ic_state=IEEE80211_S_RUN,ic_rsnciphers=IEEE80211_CIPHER_CCMP,ic_igtk_kid=0;
 enum ieee80211_cipher ic_rsngroupcipher=IEEE80211_CIPHER_CCMP;
 struct {int is_rx_nombuf=0,is_rx_eapol_key=0,is_rx_eapol_replay=0,is_rx_eapol_badmic=0;}ic_stats;
 int(*ic_keys_ready)(ieee80211com*,ieee80211_node*)=nullptr;
 ieee80211_key ic_nw_keys[6]{};int(*ic_set_key)(ieee80211com*,ieee80211_node*,ieee80211_key*);
};
struct ieee80211_rsnparams {int rsn_akms,rsn_groupcipher,rsn_nciphers,rsn_ciphers;};
// These fixtures contain one exact RSN IE. A second IE must never reach this stub.
static int ieee80211_parse_rsn(ieee80211com*,const uint8_t*,ieee80211_rsnparams*){assert(false);return EINVAL;}
static int deauths=0,link_ups=0,install_mode=0,failed_id=-1;static std::vector<int> installs;static std::vector<int> pending;
static int keys_ready(ieee80211com*,ieee80211_node*){return pending.empty();}
static void fake_deauth(ieee80211com*,ieee80211_node*,int,int){++deauths;}
#define IEEE80211_SEND_MGMT(ic,ni,type,reason) fake_deauth(ic,ni,type,reason)
static void ieee80211_new_state(ieee80211com*ic,int state,int){ic->ic_state=state;}
static void ieee80211_set_link_state(ieee80211com*,int state){if(state==LINK_STATE_UP)++link_ups;}
static const char*ether_sprintf(const uint8_t*){return "peer";}
static void ieee80211_delete_key(ieee80211com*,ieee80211_node*,ieee80211_key*k){k->k_priv=nullptr;}
static int set_key(ieee80211com*,ieee80211_node*,ieee80211_key*k){
 int id=(k->k_flags&(IEEE80211_KEY_GROUP|IEEE80211_KEY_IGTK))?k->k_id:0;installs.push_back(id);
 if(id==failed_id)return EIO;
 k->k_priv=(void*)1;k->k_flags|=IEEE80211_KEY_SWCRYPTO;
 if(install_mode){pending.push_back(id);return EBUSY;}return 0;
}
static void ieee80211_recv_4way_msg1(ieee80211com*,ieee80211_eapol_key*,ieee80211_node*){assert(false);}
static void ieee80211_recv_wpa_group_msg1(ieee80211com*,ieee80211_eapol_key*,ieee80211_node*){assert(false);}
'''

MAIN = r'''
static void hex(const uint8_t*p,size_t n){for(size_t i=0;i<n;++i)printf("%02x",p[i]);}
int main(int argc,char**argv){
 assert(argc==5);install_mode=atoi(argv[1]);failed_id=atoi(argv[2]);bool mfp=atoi(argv[3]);int akm=atoi(argv[4]);
 ieee80211com ic;ieee80211_node ni;ic.ic_set_key=set_key;ic.ic_keys_ready=keys_ready;ic.ic_if.if_start=start;
 ni.ni_rsnakms=akm;if(akm==IEEE80211_AKM_PSK)ap_rsn[19]=2;if(!mfp)ap_rsn[20]=0;
 if(!mfp)ni.ni_flags&=~IEEE80211_NODE_MFP;
 memcpy(ic.ic_myaddr,spa,6);memcpy(ni.ni_macaddr,aa,6);
 for(unsigned i=0;i<32;++i){ni.ni_pmk[i]=i;ni.ni_nonce[i]=i+32;ic.ic_nonce[i]=i+64;}
 unsigned index=0;
 while(true){
  uint8_t wire_len[2];if(fread(wire_len,1,2,stdin)!=2)break;size_t n=BE_READ_2(wire_len);
  if(n==0){assert(!pending.empty());pending.erase(pending.begin());continue;}
  assert(n<=4096);
  auto*m=packet(n+sizeof(ether_header));auto*eh=mtod(m,ether_header*);memcpy(eh->ether_dhost,spa,6);memcpy(eh->ether_shost,aa,6);eh->ether_type=htons(ETHERTYPE_PAE);
  assert(fread(eh+1,1,n,stdin)==n);
  // Set nonzero PN after each accepted packet so duplicate key reinstall is visible.
  size_t before=installs.size(),tx_before=transmitted.size();
  ieee80211_eapol_key_input(&ic,m,&ni);
  printf("{\"index\":%u,\"port\":%d,\"state\":%d,\"deauth\":%d,\"up\":%d,\"kid\":%d,\"badmic\":%d,\"replay\":%llu,\"installs\":[",index++,ni.ni_port_valid,ic.ic_state,deauths,link_ups,ic.ic_igtk_kid,ic.ic_stats.is_rx_eapol_badmic,(unsigned long long)ni.ni_replaycnt);
  for(size_t i=before;i<installs.size();++i)printf("%s%d",i==before?"":",",installs[i]);
  printf("],\"tk\":\"");hex(ni.ni_pairwise_key.k_key,16);printf("\",\"gtk\":\"");hex(ic.ic_nw_keys[1].k_key,16);
  printf("\",\"igtk\":\"");if(ic.ic_igtk_kid<6)hex(ic.ic_nw_keys[ic.ic_igtk_kid].k_key,16);
  printf("\",\"pn\":[%llu,%llu,%llu,%llu],\"tx\":[",(unsigned long long)ni.ni_pairwise_key.k_rsc[0],(unsigned long long)ic.ic_nw_keys[1].k_rsc[0],(unsigned long long)ic.ic_nw_keys[4].k_mgmt_rsc,(unsigned long long)ic.ic_nw_keys[5].k_mgmt_rsc);
  for(size_t i=tx_before;i<transmitted.size();++i){printf("%s\"",i==tx_before?"":",");hex(transmitted[i].data(),transmitted[i].size());printf("\"");}puts("]}");
  ni.ni_pairwise_key.k_rsc[0]=0x1234;ic.ic_nw_keys[1].k_rsc[0]=0x2345;
  if(ic.ic_nw_keys[4].k_cipher)ic.ic_nw_keys[4].k_mgmt_rsc=0x3456;
  if(ic.ic_nw_keys[5].k_cipher)ic.ic_nw_keys[5].k_mgmt_rsc=0x4567;
 }
}
'''

PMK, AA, SPA = bytes(range(32)), bytes([2, 0, 0, 0, 0, 1]), bytes([2, 0, 0, 0, 0, 2])
ANONCE, SNONCE = bytes(range(32, 64)), bytes(range(64, 96))
PTK = reference_ptk(16, 8, PMK, AA, SPA, ANONCE, SNONCE)
RSN = bytes.fromhex("301a0100000fac040100000fac040100000fac0880000000000fac06")
GTK, IGTK = bytes(range(0x80, 0x90)), bytes(range(0xa0, 0xb0))


def kde(kind, data):
    body = b"\x00\x0f\xac" + bytes([kind]) + data
    return bytes([221, len(body)]) + body


def packet(counter=1, group=False, kid=4, include_igtk=True, malformed_igtk=False,
           version=None, gtk=GTK, igtk=IGTK, mic_tamper=False, encrypted=True,
           keylen=16, truncated_igtk=False, trailing=b"", akm=16, mfp=True):
    if version is None:
        version = 0 if akm == 16 else 2
    ptk = reference_ptk(akm, 8, PMK, AA, SPA, ANONCE, SNONCE)
    rsn = bytearray(RSN)
    if akm == 2:
        rsn[19] = 2
    if not mfp:
        rsn[20] = 0
    plain = (b"" if group else bytes(rsn)) + kde(1, b"\x01\x00" + gtk)
    if include_igtk:
        tail = kid.to_bytes(2, "little") + (9).to_bytes(6, "little") + igtk
        if malformed_igtk:
            tail = tail[:-1]
        encoded = kde(9, tail)
        if truncated_igtk:
            encoded = encoded[:1] + b"\xfa" + encoded[2:-1]
        plain += encoded
    plain += trailing
    if encrypted:
        if len(plain) < 16 or len(plain) % 8:
            plain = (plain + b"\xdd").ljust(max(16, (len(plain) + 7) // 8 * 8), b"\0")
        data = reference_wrap(ptk[16:32], plain)
    else:
        data = plain
    info = 0x380 | (0 if group else 0x48) | (0x1000 if encrypted else 0) | version
    header = bytearray(bytes([2, 3]) + struct.pack(">H", 95 + len(data)) + bytes([2]) +
                       struct.pack(">HHQ", info, keylen, counter) + ANONCE + bytes(16) +
                       (7).to_bytes(6, "little") + bytes(2) + bytes(8) + bytes(16) +
                       struct.pack(">H", len(data)))
    assert len(header) == 99
    header[81:97] = (reference_cmac(ptk[:16], header + data) if akm == 16 else
                     hmac.new(ptk[:16], header + data, hashlib.sha1).digest()[:16])
    if mic_tamper:
        header[81] ^= 1
    return bytes(header) + data


def check_reply(reply, counter, pairwise, akm=16):
    wire = bytes.fromhex(reply)
    assert wire[:6] == AA and wire[6:12] == SPA and wire[12:14] == b"\x88\x8e"
    wire = wire[14:]
    assert len(wire) == 99 and wire[:5] == b"\x01\x03\x00\x5f\x02"
    info = int.from_bytes(wire[5:7], "big")
    assert info == ((0x308 if pairwise else 0x300) | (0 if akm == 16 else 2))
    assert int.from_bytes(wire[9:17], "big") == counter
    blank = wire[:81] + bytes(16) + wire[97:]
    ptk = reference_ptk(akm, 8, PMK, AA, SPA, ANONCE, SNONCE)
    assert wire[81:97] == (reference_cmac(ptk[:16], blank) if akm == 16 else
                          hmac.new(ptk[:16], blank, hashlib.sha1).digest()[:16])


source = WIRE_SOURCE + "\n#define IEEE80211_NUM_TID 16\n" + KEY_STRUCT + STUB + CRYPTO_HELPERS
source += "\n".join(function(NET / "ieee80211_crypto.c", name) for name in
                    ("ieee80211_has_igtk", "ieee80211_igtk_kde_valid", "ieee80211_keys_ready", "ieee80211_eapol_key_data_valid"))
source += "\n".join(function(NET / "ieee80211_pae_output.c", name) for name in
                    ("ieee80211_send_eapol_key", "ieee80211_send_4way_msg4", "ieee80211_send_group_msg2"))
source += "\n".join(function(NET / "ieee80211_pae_input.c", name) for name in
                    ("ieee80211_must_update_group_key", "ieee80211_recv_4way_msg3",
                     "ieee80211_recv_rsn_group_msg1", "ieee80211_eapol_key_input"))
source += MAIN

with tempfile.TemporaryDirectory(prefix="mtk-eapol-handshake-") as directory:
    binary = compile_crypto(Path(directory), source,
        ["aes.c", "cmac.c", "key_wrap.c", "sha1.c", "sha2.c", "md5.c", "hmac.c", "arc4.c"])

    def run(packets, mode=0, failed=-1, mfp=True, akm=16):
        wire = b"".join(b"\x00\x00" if p is None else struct.pack(">H", len(p)) + p for p in packets)
        result = subprocess.run([str(binary), str(mode), str(failed), str(int(mfp)), str(akm)], input=wire, capture_output=True)
        if result.returncode:
            print(result.stderr.decode(errors="replace"))
        result.check_returncode()
        return [json.loads(line) for line in result.stdout.splitlines()]

    for kid in (4, 5):
        state, repeat = run([packet(kid=kid), packet(counter=2, kid=kid)])
        assert state["port"] == 1 and state["deauth"] == 0 and state["installs"] == [0, 1, kid]
        assert state["tk"] == PTK[32:48].hex() and state["gtk"] == GTK.hex() and state["igtk"] == IGTK.hex()
        assert state["kid"] == kid and state["pn"][kid-2] == 9
        assert len(state["tx"]) == 1
        check_reply(state["tx"][0], 1, True)
        assert repeat["installs"] == [] and repeat["pn"][:2] == [0x1234, 0x2345]
        assert repeat["pn"][kid-2] == (0x3456 if kid == 4 else 0x4567)
        check_reply(repeat["tx"][0], 2, True)

    for bad in (packet(include_igtk=False), packet(malformed_igtk=True), packet(kid=3), packet(kid=6)):
        state = run([bad])[0]
        assert state["port"] == 0 and state["up"] == 0 and state["installs"] == [] and state["tx"] == [] and state["deauth"] == 1
    for bad in (packet(version=3), packet(version=2), packet(version=1), packet(mic_tamper=True), packet(encrypted=False)):
        state = run([bad])[0]
        assert state["port"] == 0 and state["up"] == 0 and state["installs"] == [] and state["tx"] == []
    for failed in (0, 1, 4):
        state = run([packet()], failed=failed)[0]
        assert state["port"] == 0 and state["up"] == 0 and state["deauth"] == 1
    state, pending_retry = run([packet(), packet(counter=2)], mode=1)
    assert state["port"] == 0 and state["up"] == 0 and state["installs"] == [0, 1, 4] and state["deauth"] == 0
    assert pending_retry["port"] == 0 and pending_retry["up"] == 0, pending_retry
    states = run([packet(), packet(counter=2), None, packet(counter=3), None,
                  packet(counter=4), None, packet(counter=5)], mode=1)
    assert all(state["port"] == 0 and state["up"] == 0 for state in states[:4])
    assert states[-1]["port"] == 1 and states[-1]["up"] == 1 and states[-1]["installs"] == []
    plain = run([packet(include_igtk=False, akm=2, mfp=False)], mfp=False, akm=2)[0]
    assert plain["port"] == 1 and plain["installs"] == [0, 1]
    assert plain["tk"] == reference_ptk(2, 8, PMK, AA, SPA, ANONCE, SNONCE)[32:48].hex()
    check_reply(plain["tx"][0], 1, True, akm=2)
    for bad in (packet(keylen=32), packet(gtk=GTK[:-1]), packet(truncated_igtk=True),
                packet(trailing=b"\xf0\xff\x01"), packet(trailing=b"\xdd\x00\x01")):
        state = run([bad])[0]
        assert state["port"] == 0 and state["installs"] == [] and state["tx"] == [], state

    fresh_gtk, fresh_igtk = bytes(range(0xc0, 0xd0)), bytes(range(0xe0, 0xf0))
    first, group, replay = run([packet(), packet(counter=2, group=True, kid=5, gtk=fresh_gtk, igtk=fresh_igtk),
                                packet(counter=3, group=True, kid=5, gtk=fresh_gtk, igtk=fresh_igtk)])
    assert group["installs"] == [1, 5] and group["kid"] == 5 and group["port"] == 1
    assert group["gtk"] == fresh_gtk.hex() and group["igtk"] == fresh_igtk.hex()
    check_reply(group["tx"][0], 2, False)
    assert replay["installs"] == [] and replay["pn"] == [0x1234, 0x2345, 0x3456, 0x4567]
    check_reply(replay["tx"][0], 3, False)
    first, malformed = run([packet(), packet(counter=2, group=True, gtk=fresh_gtk, malformed_igtk=True)])
    assert malformed["installs"] == [] and malformed["gtk"] == GTK.hex() and malformed["tx"] == [] and malformed["replay"] == 1
    for malformed_packet in (packet(counter=2, group=True, gtk=fresh_gtk, truncated_igtk=True),
                             packet(counter=2, group=True, gtk=fresh_gtk, trailing=b"\xf0\xff\x01")):
        first, malformed = run([packet(), malformed_packet])
        assert malformed["installs"] == [] and malformed["gtk"] == GTK.hex() and malformed["tx"] == [] and malformed["replay"] == 1
    first, absent = run([packet(), packet(counter=2, group=True, gtk=fresh_gtk, include_igtk=False)])
    assert absent["installs"] == [1] and absent["kid"] == 4 and absent["igtk"] == IGTK.hex() and absent["port"] == 1
    check_reply(absent["tx"][0], 2, False)
    first, old = run([packet(), packet(counter=1)])
    assert old["installs"] == [] and old["tx"] == [] and old["replay"] == 1
    print("PASS real EAPOL ingress/egress + independently encrypted/MICed SAE M3/group rekey, IGTK gating, install failures and no key reinstall.")
