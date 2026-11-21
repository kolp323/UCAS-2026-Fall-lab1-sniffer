"""Verify ICMP type/code from saved parser JSON, PCAP bytes and TShark fields."""
import argparse
import csv
import json

from review import read_pcap


def main(run):
    raw = read_pcap(run/'local-protocols.pcap')
    parsed = json.loads((run/'parsed.json').read_text(encoding='utf-8'))['packets']
    with (run/'tshark.csv').open(encoding='utf-8', newline='') as f:
        rows = list(csv.DictReader(f))
    matches = []
    for row in rows:
        if not (row['icmp.type'] or row['icmpv6.type']):
            continue
        i = int(row['frame.number'])-1
        ipv6 = bool(row['icmpv6.type'])
        expected_protocol = 'ICMPv6' if ipv6 else 'ICMP'
        expected_type = int(row['icmpv6.type'] if ipv6 else row['icmp.type'])
        expected_offset = 4+40 if ipv6 else 4+4*(raw[i][4]&15)
        fields = {f['name']: f for f in parsed[i]['fields']}
        typ, code = fields['icmp.type'], fields['icmp.code']
        direct_bytes = list(raw[i][expected_offset:expected_offset+2])
        ok = (parsed[i]['protocol']==expected_protocol and direct_bytes==[expected_type,0]
              and typ['offset']==expected_offset and code['offset']==expected_offset+1
              and int(typ['value'])==expected_type and int(code['value'])==0)
        matches.append(dict(frame=i+1, protocol=expected_protocol, offset=expected_offset,
                            tshark_type=expected_type, bytes=direct_bytes, passed=ok))
    passed = ({(r['protocol'],r['tshark_type']) for r in matches}==
              {('ICMP',0),('ICMP',8),('ICMPv6',128),('ICMPv6',129)} and all(r['passed'] for r in matches))
    record = {'outcome': 'pass' if passed else 'fail', 'rows': matches,
              'inputs': ['local-protocols.pcap', 'parsed.json', 'tshark.csv']}
    with (run/'icmp-oracle.json').open('x', encoding='utf-8') as f:
        json.dump(record, f, indent=2)
    print(json.dumps(record))
    return 0 if passed else 1


if __name__ == '__main__':
    from pathlib import Path
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('run', type=Path)
    raise SystemExit(main(p.parse_args().run))

