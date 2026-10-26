"""Synthetic EAPOL fixture definitions; use real wire structs and crypto code."""
import re
import hashlib
import hmac
from .crypto_reference import NET, function

crypto_h = (NET / "ieee80211_crypto.h").read_text()
wire_h = (NET / "ieee80211.h").read_text()
DEFINES = "\n".join(line for line in wire_h.splitlines()
                     if line.startswith("#define EAPOL_") or
                     line.startswith("#define IEEE80211_ADDR_LEN") or
                     line.startswith("#define IEEE80211_ELEMID_VENDOR"))
DEFINES += "\n#define IEEE80211_ELEMID_VENDOR " + re.search(
    r"IEEE80211_ELEMID_VENDOR\s*=\s*(\d+)", wire_h)[1]
ENUMS = "\n".join(re.search(r"enum " + name + r" \{.*?\};", crypto_h, re.S)[0]
                  for name in ["ieee80211_cipher", "ieee80211_akm"])
STRUCTS = "\n".join(re.search(r"struct " + name + r" \{.*?\} __packed;", wire_h, re.S)[0]
                    for name in ["ieee80211_eapol_key", "ieee80211_ptk"])
STUB = r'''
#include <crypto/aes.h>
#include <crypto/cmac.h>
#include <crypto/key_wrap.h>
#include <crypto/arc4.h>
#include <crypto/md5.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <crypto/hmac.h>
#define BE_READ_2(p) (((p)[0]<<8)|(p)[1])
#define BE_WRITE_2(p,v) do{(p)[0]=(v)>>8;(p)[1]=(v);}while(0)
#define XYLog(...) ((void)0)
#define timingsafe_bcmp memcmp
#define __packed __attribute__((packed))
#define IEEE80211_PMK_LEN 32
typedef union {HMAC_MD5_CTX md5;HMAC_SHA1_CTX sha1;AES_CMAC_CTX cmac;} ANY_CTX;
'''
functions = ["ieee80211_cipher_keylen", "ieee80211_prf", "ieee80211_kdf",
             "ieee80211_derive_ptk", "ieee80211_eapol_key_mic",
             "ieee80211_eapol_key_check_mic", "ieee80211_eapol_key_encrypt",
             "ieee80211_eapol_key_decrypt"]
WIRE_SOURCE = STUB + DEFINES + "\n" + ENUMS + "\n" + STRUCTS + "\n"
CRYPTO_HELPERS = "\n".join(function(NET / "ieee80211_crypto.h", name) for name in
                    ["ieee80211_is_sha256_akm", "ieee80211_eapol_key_version"])
CRYPTO_HELPERS += "\n".join(function(NET / "ieee80211_crypto.c", name) for name in functions)


def reference_ptk(akm, cipher, pmk, aa, spa, anonce, snonce):
    context = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
    length = {8: 48, 4: 64, 1: 32}[cipher]
    label = b"Pairwise key expansion"
    if akm in (4, 8, 16):
        result = b"".join(hmac.new(pmk, i.to_bytes(2, "little") + label + context +
            (length*8).to_bytes(2, "little"), hashlib.sha256).digest() for i in range(1, 3))
    else:
        result = b"".join(hmac.new(pmk, label + b"\0" + context + bytes([i]),
            hashlib.sha1).digest() for i in range(4))
    return result[:length].ljust(64, b"\0")
