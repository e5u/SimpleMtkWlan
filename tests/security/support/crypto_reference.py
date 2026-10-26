"""Host crypto references and kernel-header shims, never loaded by the driver."""
import ctypes
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
NET = ROOT / "mtk80211/openbsd/net80211"
CRYPTO = ROOT / "mtk80211/openbsd/crypto"


def function(path, name):
    text = path.read_text()
    match = re.search(r"(?m)^(?:static __inline |static )?(?:void|int|u_int16_t)\n" +
                      name + r"\([^;]+?\)\s*\{", text)
    assert match, name
    pos = text.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (text[pos] == "{") - (text[pos] == "}")
        pos += 1
    return text[match.start():pos]


def compile_crypto(directory, source, primitives):
    stubs = directory / "stubs"
    (stubs / "sys").mkdir(parents=True)
    (stubs / "IOKit").mkdir()
    (stubs / "compat.h").write_text(r'''
#pragma once
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#else
#include <endian.h>
#endif
#ifndef BYTE_ORDER
#define BYTE_ORDER __BYTE_ORDER__
#define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#define BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif
#ifndef NBBY
#define NBBY 8
#endif
#define MIN(a,b) ((a)<(b)?(a):(b))
#define explicit_bzero(p,n) memset((p),0,(n))
''')
    for name in ("param.h", "systm.h", "endian.h", "_endian.h"):
        (stubs / "sys" / name).write_text('#include "compat.h"\n')
    (stubs / "IOKit/IOLib.h").write_text('#include "compat.h"\n')
    (stubs / "types.h").write_text('#pragma once\n#include <stdint.h>\ntypedef uint8_t u8;\n')
    cpp = directory / "test.cpp"
    cpp.write_text(source)
    binary = directory / "test"
    sanitizer = os.environ.get("MTK_TEST_SANITIZERS", "address,undefined")
    subprocess.run(["clang++", "-x", "c++", "-std=c++14",
        "-Wno-unknown-attributes", "-D_KERNEL=1", "-include", str(stubs / "compat.h"),
        "-I", str(stubs), "-I", str(CRYPTO.parent), "-I", str(CRYPTO),
        f"-fsanitize={sanitizer}", "-fno-sanitize-recover=all", str(cpp),
        *(str(CRYPTO / name) for name in primitives), "-o", str(binary)], check=True)
    return binary


if sys.platform == "darwin":
    _system = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    _system.CCCrypt.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t)]


def aes_block(key, block):
    assert len(block) == 16
    if sys.platform == "darwin":
        out, used = ctypes.create_string_buffer(16), ctypes.c_size_t()
        # AES ECB, no padding; this calls the OS implementation, not driver AES.
        assert _system.CCCrypt(0, 0, 2, key, len(key), None, block, len(block),
            out, 16, ctypes.byref(used)) == 0 and used.value == 16
        return out.raw
    return subprocess.check_output(["openssl", "enc", f"-aes-{len(key)*8}-ecb",
        "-nopad", "-nosalt", "-K", key.hex()], input=block)


def reference_wrap(key, plain):
    assert len(plain) >= 16 and len(plain) % 8 == 0
    blocks = [plain[i:i+8] for i in range(0, len(plain), 8)]
    a = b"\xa6" * 8
    for iteration in range(6):
        for i in range(len(blocks)):
            b = aes_block(key, a + blocks[i])
            a = (int.from_bytes(b[:8], "big") ^
                 (len(blocks) * iteration + i + 1)).to_bytes(8, "big")
            blocks[i] = b[8:]
    return a + b"".join(blocks)


def reference_cmac(key, message):
    def double(block):
        value = int.from_bytes(block, "big")
        return (((value << 1) & ((1 << 128) - 1)) ^
                (0x87 if value >> 127 else 0)).to_bytes(16, "big")
    k1 = double(aes_block(key, bytes(16)))
    k2 = double(k1)
    blocks = max(1, (len(message) + 15) // 16)
    complete = bool(message) and len(message) % 16 == 0
    last = message[(blocks-1)*16:]
    if not complete:
        last = (last + b"\x80").ljust(16, b"\0")
    x = bytes(16)
    for i in range(blocks - 1):
        x = aes_block(key, bytes(a ^ b for a, b in zip(x, message[i*16:(i+1)*16])))
    return aes_block(key, bytes(a ^ b ^ c for a, b, c in zip(x, last, k1 if complete else k2)))
