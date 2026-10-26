#!/usr/bin/env python3
"""Real AES primitives: RFC 3394/4493 vectors and independently checked splits."""
from pathlib import Path
import random
import subprocess
import tempfile
from support.crypto_reference import compile_crypto, reference_wrap, reference_cmac

SOURCE = r'''
#include <crypto/aes.h>
#include <crypto/key_wrap.h>
#include <crypto/cmac.h>
static void dump(const uint8_t*p,size_t n){for(size_t i=0;i<n;++i)printf("%02x",p[i]);puts("");}
int main(int argc,char**argv){
 assert(argc==4);size_t keylen=strtoul(argv[2],nullptr,10),split=strtoul(argv[3],nullptr,10);
 uint8_t key[32],data[512],cipher[520],recovered[512];
 assert(keylen<=sizeof(key)&&fread(key,1,keylen,stdin)==keylen);
 size_t n=fread(data,1,sizeof(data),stdin);
 if(argv[1][0]=='w'){
  assert(n>=16&&n%8==0);aes_key_wrap_ctx ctx;
  aes_key_wrap_set_key_wrap_only(&ctx,key,keylen);aes_key_wrap(&ctx,data,n/8,cipher);dump(cipher,n+8);
  aes_key_wrap_set_key(&ctx,key,keylen);assert(aes_key_unwrap(&ctx,cipher,recovered,n/8)==0);
  assert(memcmp(data,recovered,n)==0);dump(recovered,n);
  for(size_t i=0;i<n+8;++i){cipher[i]^=1;assert(aes_key_unwrap(&ctx,cipher,recovered,n/8)!=0);cipher[i]^=1;}
 }else{
  assert(keylen==16&&split<=n);AES_CMAC_CTX ctx;
  AES_CMAC_Init(&ctx);AES_CMAC_SetKey(&ctx,key);
  AES_CMAC_Update(&ctx,data,split);AES_CMAC_Update(&ctx,data+split,n-split);
  AES_CMAC_Final(cipher,&ctx);dump(cipher,16);
 }
}
'''

# RFC 3394 sections 4.1--4.6 (AES-128/192/256 KEKs).
WRAP_VECTORS = [
    (16, 16, "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"),
    (24, 16, "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d"),
    (32, 16, "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7"),
    (24, 24, "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2"),
    (32, 24, "a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1"),
    (32, 32, "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21"),
]
MESSAGE = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710")
CMAC_VECTORS = [
    (0, "bb1d6929e95937287fa37d129b756746"),
    (16, "070a16b46b4d4144f79bdd9dd04a287c"),
    (40, "dfa66747de9ae63030ca32611497c827"),
    (64, "51f0bebf7e3b9d92fc49741779363cfe"),
]

with tempfile.TemporaryDirectory(prefix="mtk-eapol-aes-") as directory:
    binary = compile_crypto(Path(directory), SOURCE, ["aes.c", "cmac.c", "key_wrap.c"])

    def run(mode, key, data, split=0):
        return [bytes.fromhex(s.decode()) for s in subprocess.check_output(
            [str(binary), mode, str(len(key)), str(split)], input=key+data).splitlines()]

    plain = bytes.fromhex("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f")
    for keylen, n, expected in WRAP_VECTORS:
        key, data = bytes(range(keylen)), plain[:n]
        assert reference_wrap(key, data).hex() == expected
        assert run("w", key, data) == [bytes.fromhex(expected), data]
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    for n, expected in CMAC_VECTORS:
        assert reference_cmac(key, MESSAGE[:n]).hex() == expected
        for split in range(n+1):
            assert run("c", key, MESSAGE[:n], split) == [bytes.fromhex(expected)]
    rng = random.Random(0x33944493)
    for n in [1, 2, 7, 15, 17, 24, 31, 33, 48, 65, 99, 123, 255]:
        key = bytes(rng.getrandbits(8) for _ in range(16))
        data = bytes(rng.getrandbits(8) for _ in range(n))
        expected = reference_cmac(key, data)
        for split in sorted({0, min(n, 16), n//2, n}):
            assert run("c", key, data, split) == [expected]
    for n in [16, 24, 32, 40, 48, 56, 128]:
        key = bytes(rng.getrandbits(8) for _ in range(16))
        data = bytes(rng.getrandbits(8) for _ in range(n))
        assert run("w", key, data) == [reference_wrap(key, data), data]
print("PASS real AES wrap: 6 RFC3394 vectors, corruption rejection; CMAC: 4 RFC4493 vectors, arbitrary lengths and every fixed-vector split")
