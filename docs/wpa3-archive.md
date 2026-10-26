# WPA3 / SAE experimental archive

This branch preserves an incomplete WPA3 investigation for macOS 26 Tahoe.
It is not a working WPA3 release and must not be merged or presented as a
tested interoperability fix. The installed driver and EFI were not changed
when this archive was created.

## What is preserved

- The opt-in `-mtkwpa3` capability path, PMF/BIP integration, SAE group 19,
  and the associated EAPOL/key-lifecycle changes.
- WCL scan security records, association field decoding, private-MAC restart
  diagnostics, and a separate SAE password field.
- Host tests for the protocol, cryptographic primitives, WCL decoding,
  capabilities, and lifecycle handling.
- Third-party notices for micro-ecc and the hostap protocol references.

The 44 host tests in `tests/run-all.sh` passed with UBSan when archived.
The final uninstalled source revision did not receive a hardware WPA3 test.
Host tests do not validate the kernel ABI, firmware behavior, or SAE over the
air. WPA2 regression testing and a full constant-time ECC audit also remain
necessary before considering a release.

## Where the hardware investigation stopped

On macOS 26.7.1 (25G241), AirportMtkWlan 1.5.30 correctly identified the
SAE-only test AP in its scan records. airportd constructed an SAE-only request
with PMF required. The failed attempt did not reach `setMacAddress` or
`setWCL_ASSOCIATE` for the target network. Therefore the driver had not been
given an association request, and no SAE over-the-air handshake was tested.

The immediate investigation target is the WCL candidate-network bridge, not
DNS, Internet connectivity, or more independent capability bits. In
particular, airportd displaying a WPA3 network does not prove that the WCL BSS
cache has received and parsed its RSN IE.

Confirmed Tahoe request layout:

- `apple80211_assoc_data` is copied in full by `initWCLJoinRequest`.
- The complete `apple80211_key` at association offset `0x64` is copied to
  candidate offset `0x40`; the current key data offset `0x50` is consistent.
- Candidate `0x1ec` contains the independent password length, and `0x1f0`
  contains its bytes. This is distinct from the 32-byte key/PMK field.
- `isOnRSNNetwork` checks an internal RSN AKM bitmap for SAE. Its complete
  mapping was not yet established; do not infer an Apple bug from bit values
  alone.

When work resumes, verify the `ScanResult` IE pointer, length, metadata flags,
and resulting WCL BSS security state first. The `setBeaconDataFromMsg` and
`setBeaconDataEx` paths are relevant. Do not assume that the independent
password field is the root cause: the observed failure occurs before join
request decoding.

## Local-only material

Runtime logs, EFI snapshots, WirelessDiagnostics archives, and reverse
engineering scratch files are deliberately excluded from Git. On the
development machine, the diagnostics are under the repository's local
`outputs/` directory and the Tahoe disassembly notes are under the sibling
`work/research/wpa3/` directory. Preserve them separately if moving this
investigation to another machine.

The archive does not implement or claim support for H2E, SAE-PK, additional
SAE groups, WPA3 Enterprise, 6 GHz, or AWDL. WPA3 work is paused at the user's
request; the normal `main` branch remains the non-WPA3 baseline.
