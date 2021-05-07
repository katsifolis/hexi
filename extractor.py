# This scirpt extracts the analysed disassembled function collcetion
# and dumps to a file

import angr
from pprint import pp
import logging
import sys

sys.stdout = open("output.txt", "w")
logging.getLogger('angr').setLevel('DEBUG')
p = angr.Project('./test', load_options={'auto_load_libs': False})
cfg = p.analyses.CFG(
        normalize=True,
        resolve_indirect_jumps=True, 
        cross_references=False,
        force_segment=True)
funcs = dict(cfg.kb.functions)

for f in funcs.values():
    name = f.name
    addr = f.addr
    if not name.startswith("__"): # don't log internal and stub functions
        for block in f.blocks:
            print(name + ": " + str(addr))
            for ins in block.capstone.insns:
                print(ins.mnemonic + "\t" + ins.op_str)
            # print(block.disassembly.pp())
            print("")
