#!/usr/bin/env python3
"""Exercise real EAPOL crypto and PTK derivation against independent references."""
from pathlib import Path
import hashlib
import hmac
import subprocess
import tempfile
from support.crypto_reference import compile_crypto, reference_cmac, reference_wrap
from support.eapol_fixture import WIRE_SOURCE, CRYPTO_HELPERS, reference_ptk

MAIN = r'''
static void dump(const uint8_t*p,size_t n){for(size_t i=0;i<n;++i)printf("%02x",p[i]);puts("");}
int main(int argc,char**argv){
 assert(argc==4);int ver=atoi(argv[2]),arg=atoi(argv[3]);
 assert(ieee80211_eapol_key_version(IEEE80211_AKM_SAE,IEEE80211_CIPHER_CCMP,IEEE80211_CIPHER_CCMP)==0);
 assert(ieee80211_eapol_key_version(IEEE80211_AKM_SHA256_PSK,IEEE80211_CIPHER_CCMP,IEEE80211_CIPHER_CCMP)==3);
 assert(ieee80211_eapol_key_version(IEEE80211_AKM_PSK,IEEE80211_CIPHER_CCMP,IEEE80211_CIPHER_CCMP)==2);
 assert(ieee80211_eapol_key_version(IEEE80211_AKM_PSK,IEEE80211_CIPHER_TKIP,IEEE80211_CIPHER_TKIP)==1);
 if(argv[1][0]=='p'){
  uint8_t in[108];assert(fread(in,1,sizeof(in),stdin)==sizeof(in));ieee80211_ptk ptk;memset(&ptk,0xaa,sizeof(ptk));
  int ret=ieee80211_derive_ptk((ieee80211_akm)ver,(ieee80211_cipher)arg,in,in+32,in+38,in+44,in+76,&ptk);
  printf("%d\n",ret);dump((uint8_t*)&ptk,sizeof(ptk));return 0;
 }
 alignas(8) uint8_t storage[sizeof(ieee80211_eapol_key)+512]={};
 auto*k=(ieee80211_eapol_key*)storage;uint8_t kck[16],kek[16];
 assert(fread(kck,1,16,stdin)==16&&fread(kek,1,16,stdin)==16);
 uint8_t*data=(uint8_t*)(k+1);size_t n=fread(data,1,256,stdin);
 k->version=2;k->type=3;k->desc=2;BE_WRITE_2(k->info,0x100|ver);
 BE_WRITE_2(k->len,sizeof(*k)+n-4);BE_WRITE_2(k->paylen,n);
 if(argv[1][0]=='m'){
  dump(storage,sizeof(*k)+n);ieee80211_eapol_key_mic(k,kck);dump(k->mic,16);
  if(ver>3){assert(ieee80211_eapol_key_check_mic(k,kck)!=0);return 0;}
  assert(ieee80211_eapol_key_check_mic(k,kck)==0);
  uint8_t mic[16];memcpy(mic,k->mic,16);
  assert(ieee80211_eapol_key_check_mic(k,kck)==0&&memcmp(mic,k->mic,16)==0);
  k->mic[0]^=1;assert(ieee80211_eapol_key_check_mic(k,kck)!=0);k->mic[0]^=1;
  if(n){data[n-1]^=1;assert(ieee80211_eapol_key_check_mic(k,kck)!=0);data[n-1]^=1;}
  k->nonce[31]^=1;assert(ieee80211_eapol_key_check_mic(k,kck)!=0);
  BE_WRITE_2(k->len,0);assert(ieee80211_eapol_key_check_mic(k,kck)!=0);
 }else if(argv[1][0]=='w'){
  ieee80211com ic{};ieee80211_eapol_key_encrypt(&ic,k,kek);
  dump(data,BE_READ_2(k->paylen));
  uint8_t saved[sizeof(storage)];memcpy(saved,storage,sizeof(storage));
  assert(ieee80211_eapol_key_decrypt(k,kek)==0);
  assert(BE_READ_2(k->len)==sizeof(*k)+BE_READ_2(k->paylen)-4);
  dump(data,BE_READ_2(k->paylen));
  memcpy(storage,saved,sizeof(storage));data[0]^=1;
  uint16_t before=BE_READ_2(k->paylen);assert(ieee80211_eapol_key_decrypt(k,kek)!=0);
  assert(BE_READ_2(k->paylen)==before);
 }else{
  if(arg)BE_WRITE_2(k->len,sizeof(*k)-4+n-1);
  assert(ieee80211_eapol_key_decrypt(k,kek)!=0);
 }
}
'''


with tempfile.TemporaryDirectory(prefix="mtk-eapol-descriptor-") as directory:
    binary = compile_crypto(Path(directory), WIRE_SOURCE +
        "struct ieee80211com {uint8_t ic_globalcnt[32];};\n" + CRYPTO_HELPERS + MAIN,
        ["aes.c", "cmac.c", "key_wrap.c", "sha1.c", "sha2.c", "md5.c", "hmac.c", "arc4.c"])
    kck, kek = bytes(range(16)), bytes(range(16, 32))

    def run(mode, version, payload, argument=0):
        return subprocess.check_output([str(binary), mode, str(version), str(argument)],
                                       input=kck+kek+payload).splitlines()

    for version in range(4):
        for n in [0, 1, 16, 24, 99, 123]:
            payload = bytes(range(n))
            frame, mic = [bytes.fromhex(line.decode()) for line in run("m", version, payload)]
            assert len(frame) == 99+n and frame[-n:] == payload if n else len(frame) == 99
            expected = (reference_cmac(kck, frame) if version in (0, 3) else
                hmac.new(kck, frame, hashlib.md5 if version == 1 else hashlib.sha1).digest()[:16])
            assert mic == expected, (version, n)
    run("m", 7, b"bad descriptor")
    for version in [0, 2, 3]:
        for n in [0, 1, 8, 15, 16, 17, 23, 24, 32, 45]:
            payload = bytes(range(n))
            padded = payload
            if n < 16 or n % 8:
                padded = (payload + b"\xdd").ljust(max(16, ((n+7)//8)*8), b"\0")
            wrapped, clear = [bytes.fromhex(line.decode()) for line in run("w", version, payload)]
            assert wrapped == reference_wrap(kek, padded)
            assert clear == padded
        # A valid vendor IE with trailing zero octets is authenticated data.
        payload = b"\xdd\x16" + bytes(range(14)) + bytes(8)
        wrapped, clear = [bytes.fromhex(line.decode()) for line in run("w", version, payload)]
        assert clear == payload and wrapped == reference_wrap(kek, payload)
        for n in [0, 1, 8, 16, 23, 25, 31]:
            run("u", version, bytes(n))
        run("u", version, reference_wrap(kek, bytes(16)), 1)
    run("u", 7, bytes(24))
    pmk, aa, spa = bytes(range(32)), bytes.fromhex("001122334455"), bytes.fromhex("aabbccddeeff")
    anonce, snonce = bytes(range(32, 64)), bytes(range(96, 128))
    for akm, cipher in [(16, 8), (8, 8), (4, 8), (2, 8), (1, 8), (2, 4), (8, 4), (2, 1)]:
        expected = reference_ptk(akm, cipher, pmk, aa, spa, anonce, snonce)
        for addr1, addr2, nonce1, nonce2 in [(aa, spa, anonce, snonce), (spa, aa, snonce, anonce)]:
            lines = subprocess.check_output([str(binary), "p", str(akm), str(cipher)],
                input=pmk+addr1+addr2+nonce1+nonce2).splitlines()
            assert lines[0] == b"0" and bytes.fromhex(lines[1].decode()) == expected
    lines = subprocess.check_output([str(binary), "p", "16", "0"],
        input=pmk+aa+spa+anonce+snonce).splitlines()
    assert lines[0] != b"0" and bytes.fromhex(lines[1].decode()) == bytes(64)
print("PASS EAPOL v0/1/2/3 complete-frame MIC, wrap/padding/length/tamper; real SAE/WPA2 PTK derivation and AKM descriptor mapping")
