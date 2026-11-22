# Fixed synthetic packet fixtures

Generated deterministically by scripts/generate-fixtures.py. Each frame has a case ID and manually selected semantic expectation in expected.json. PCAP SHA256 fixes the exact test input.

Malformed, truncated, unsupported and fragmented inputs are deliberate. Checksums are outside parser scope; IPv6 transport checksums are not valid. Never present these synthetic samples as real captured traffic. load.pcap repeats 5000 copies of one frame for offline throughput measurement only.
