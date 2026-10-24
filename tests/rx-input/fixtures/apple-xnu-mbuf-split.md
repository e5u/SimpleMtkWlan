# Apple XNU mbuf_split test provenance

Fetched 2026-10-24 from the Apple open-source distribution. The .inc fixture
contains unchanged m_split0, m_split and mbuf_split functions. The harness
supplies host storage/allocation shims and runs these actual functions under
UBSan. It does not execute the running kernel's private mbuf implementation.
The public source confirms an exact-end split on M_PKTHDR allocates a non-NULL
zero-length tail on success, and reports ENOMEM with a NULL tail on failure.
The parser avoids that unnecessary final allocation entirely.

- https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kpi_mbuf.c
  SHA256: 83657b43c721b1f246e23532dfa13b30a652efeeb6e849e13e6b9da50253361f
- https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/uipc_mbuf.c
  SHA256: 0c28efea7c333879f59bafe368eb8b4f91c573c9462d77fe664b738f53b95f28

Apple source license: https://github.com/apple-oss-distributions/xnu/blob/main/APPLE_LICENSE
