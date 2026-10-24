# Receive handoff regression

Run `python3 tests/rx-input/test-input.py`. The harness extracts the actual `_if_input` and `ml_dequeue` functions. ASan/UBSan check six batch sizes (0,1,2,16,64,1024), ordered exact-once delivery, cleared source list, one flush per nonempty batch and ownership transfer. The stub requires `nextpkt == NULL` and consumes packets immediately; this is an ownership-contract test, not a Darwin performance simulation. Original traversal fails the test.

Apple reference: https://github.com/apple-oss-distributions/IONetworkingFamily/blob/main/IONetworkInterface.cpp (`inputPacket` asserts `mbuf_nextpkt(packet) == 0`).


`python3 tests/rx-input/test-ampdu-stats.py` runs the pure timestamp-grouping helper under UBSan. Linux `drivers/net/wireless/mediatek/mt76/mt7921/mac.c` (GROUP_2 handling) identifies its first word as MAC start time and groups A-MPDU subframes with the same timestamp. `rxampdu observed` reports completed groups of unicast data MPDUs reaching the parser, with size bins, maximum and separate non-A-MPDU/missing-GROUP_2/deaggregation counters. This is host-observed reception, not air capture: RXD errors or frames dropped before the observer can undercount a group. Pending groups carry across 30-poll intervals; missing metadata or hardware A-MSDU subframes discard the pending group as uncertain. The final pending group is not included until a timestamp change or non-A-MPDU marks its end.

`python3 tests/rx-input/test-descriptor-bounds.py --ubsan` tests the extracted actual RX parser against protected guard pages: 432 truncated optional-group layouts must be rejected before accessing RXV words, and 32 complete layouts accepted. `--test-original` temporarily removes the precheck in the extracted harness to confirm the original parser faults. The default enables ASan+UBSan; `--ubsan` is usable on this AMD macOS environment where even an empty ASan executable raises SIGILL.
