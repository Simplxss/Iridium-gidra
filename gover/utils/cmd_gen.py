import sys
import json

header = [
    'package utils',
    '',
    'import (',
    '	"github.com/MoonlightPS/Iridium-gidra/gover/gen"',
    ')',
    '',
    'var protoMap = map[int]Message{}',
    '',
    'const ('
]

body = [
    ')',
    '',
    'func init() {',
]

footer = [
    '}',
    '',
]

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python cmd_gen.py <path to packetIds.json>')
        exit(1)
    else:
        packets = json.load(open(sys.argv[1]))
        for k,v in packets.items():
            header.append(f"	{v} = {k}")
            body.append(f"	protoMap[{v}] = &gen.{v}" + "{}")
        header.extend(body)
        header.extend(footer)
        with open('./packet_gen.go', 'w') as f:
            for i in header:
                f.write(i + "\n")
        print('Done!')