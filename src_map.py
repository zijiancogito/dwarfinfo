import sys
from collections import defaultdict
import elf_parser
import os

def source(srcfiles):
    srcs = defaultdict(str)
    for filename in srcfiles:
        with open(filename, 'r') as f:
            line = f.readline()
            idx = 1
            while line:
                srcs[f"{os.path.abspath(filename)}:{idx}"] = line
                line = f.readline()
                idx += 1
    return srcs

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
        if len(insts) > 0:
            map_list.append((src, insts))
    
    # for src in map_list:
        # print(src[0])
        # print(src[1])
        # print()
    return map_list


def build_map(filename):
    maps = defaultdict(str)

    with open(filename, 'r') as f:
        line = f.readline()
        while line:
            maps[line.split(':\t')[0]] = line.split(':\t')[1].strip()
            line = f.readline()

    return maps
    

if __name__ == '__main__':
    ir = "test.db"
    insns = elf_parser.disassemble(ir, 'x86')
    with open("asm.list", 'w') as f:
        for insn in insns:
            f.write(f"{insn}:\t{insns[insn]}\n")
    srcs = ["test.c"]
    src_lines = source(srcs)
    with open("c.list", 'w') as f:
        for line in src_lines:
            f.write(f"{line}:\t{src_lines[line]}")
            
    _, line_map, _ = elf_parser.parse_dwarf('test.o')

    map_src_vs_asm("c.list", "asm.list", line_map)