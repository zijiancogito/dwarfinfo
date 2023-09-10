from collections import defaultdict
import os
import sys
import posixpath

from elftools.elf.elffile import ELFFile
from capstone import *

import gtirb

def parse_dwarf(filename, address=None):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            return -1, None, None

        dwarfinfo = elffile.get_dwarf_info()
        # if given address, decode one line
        if address:
            file, line = decode_file_line(dwarfinfo, address)
            return 1, file, line
        else:
            line_map = decode_all_file_line(dwarfinfo)
            return 0, line_map, None
        
def decode_file_line(dwarfinfo, address):
    for CU in dwarfinfo.iter_CUs():
        # First, look at line programs to find the file/line for the address
        lineprog = dwarfinfo.line_program_for_CU(CU)
        delta = 1 if lineprog.header.version < 5 else 0
        prevstate = None
        for entry in lineprog.get_entries():
            # We're interested in those entries where a new state is assigned
            if entry.state is None:
                continue
            # Looking for a range of addresses in two consecutive states that
            # contain the required address.
            if prevstate and prevstate.address <= address < entry.state.address:
                filename = lineprog['file_entry'][prevstate.file - delta].name
                line = prevstate.line
                return filename, line
            if entry.state.end_sequence:
                # For the state with `end_sequence`, `address` means the address
                # of the first byte after the target machine instruction
                # sequence and other information is meaningless. We clear
                # prevstate so that it's not used in the next iteration. Address
                # info is used in the above comparison to see if we need to use
                # the line information for the prevstate.
                prevstate = None
            else:
                prevstate = entry.state
    return None, None

def decode_all_file_line(dwarfinfo):
    line_map = defaultdict(list)
    for CU in dwarfinfo.iter_CUs():
        lineprog = dwarfinfo.line_program_for_CU(CU)
        delta = 1 if lineprog.header.version < 5 else 0

        prevstate = None
        for entry in lineprog.get_entries():
            if entry.state is None:
                continue

            if prevstate:
                filename = lineprog['file_entry'][prevstate.file - delta].name.decode()
                line = prevstate.line
                line_map[f'{filename}:{line}'].append((hex(prevstate.address), hex(entry.state.address)))
            if entry.state.end_sequence:
                prevstate = None
            else:
                prevstate = entry.state
    # print(line_map)
    return line_map

def disassemble(irfile, machine):
    arch, mode = None, None
    if machine == 'x64':
        arch = CS_ARCH_X86
        mode = CS_MODE_64
    elif machine == 'aarch64':
        arch = CS_ARCH_ARM:
        mode = CS_MODE_64
    else:
        raise NotImplementedError

    # irfile is the ir output by ddisasm
    md = Cs(arch, mode)
    ir = gtirb.ir.IR.load_protobuf(irfile)
    m = ir.modules[0]
    insns = defaultdict(str)
    # print(m.entry_point.address)

    for b in m.code_blocks:
        code = b.contents
        base = b.address
        for insn in md.disasm(code, base):
            addr = insn.address
            body = f"{insn.mnemonic} {insn.op_str}"
            insns[hex(addr)] = body
            # print(hex(addr), end=' ')
            # print(body)
    
    return insns


if __name__ == '__main__':
    # parse_dwarf('test.o')
    # disassemble('test.db', CS_ARCH_X86, CS_MODE_64)
    source(['test.c'])