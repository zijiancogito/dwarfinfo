import sys
from collections import defaultdict

def map_src_vs_asm(src_file, asm_file, line_map):
    src_maps = build_map(src_file)
    asm_maps = build_map(asm_file)

    map_list = []
    for line in line_map:
        src = src_maps[line]
        insts = []
        for addr_range in line_map[line]:
            start = addr_range[0]
            end = addr_range[1]
            for addr in asm_maps:
                if addr >= start and addr < end:
                    insts.append(asm_maps[addr])
        map_list.append((src, insts))
    return map_list


def build_map(filename):
    maps = defaultdict(str)

    with open(filename, 'r') as f:
        while line = f.readline():
            maps[line.strip(':\t')[0]] = line.strip(':\t')[1]

    return maps
    
def disassemble(filename):
    :