# Capture filter oracle correction

The first regression run retained in evidence/runs/lab-20261120T023554Z-8adb0339 failed capture-udp.membership. The original expected set [1,5,8,9,10,12] incorrectly reused higher-level protocol understanding. No parser was changed to match that expectation.

Official syntax source: https://npcap.com/guide/wpcap/pcap-filter.html (udp/proto, VLAN and header-chain scope). A filter is a byte-selection predicate, not a full protocol validator. The online manual describes general semantics; the precise Fragment special case below was checked in this installed libpcap 1.10.5.

Independent command used: E:/APP/Wireshark/dumpcap.exe -i 2 -d -f udp. The -d option prints compiled BPF instructions and exits; it does not save traffic. Interface 2 was an Ethernet-type local adapter in this run. Raw output is preserved as bpf-udp-instructions.txt. The code's accepting branches are:

1. Ethernet type at byte 12 is 0x0800 and IPv4 protocol byte 23 equals 17.
2. Ethernet type is 0x86dd and IPv6 Next Header byte 20 equals 17.
3. Ethernet type is 0x86dd, byte 20 equals 44 (immediate Fragment), and byte 54 equals 17.

Every other branch rejects. Packet offsets outside captured data reject. This expression never reads IPv4 IHL or UDP length, so deliberately malformed IHL frame 11 can match. VLAN frame 8 has outer type 0x8100 and requires an explicit VLAN-aware expression; bare udp excludes it. IPv6 hop-by-hop frame 15 is not followed by these instructions, but immediate Fragment frame 16 is handled by branch 3.

The corrected frozen set is [1,5,9,10,11,12,16]. tests/verify.py now separately evaluates those documented byte offsets against immutable input before comparing CLI capture results. This adds an independent input-level predicate rather than copying the implementation's output. Display UDP remains [1,5,8,12,15] because the parser traverses VLAN/hop headers and deliberately marks fragmented packets without claiming a reconstructed transport header. Neither set should silently replace the other.

Original fixture v1 remains intact. New fixture v2 has identical PCAP bytes but corrected expected.json. Failed evidence is retained. This correction is a useful report/PPT case: an independent test can reveal an incorrect expected answer as well as a code defect.
