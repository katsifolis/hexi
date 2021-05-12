# This scirpt extracts the analysed disassembled function collection 
# of various binary files and dumps to files

import angr
from pprint import pp
import logging
import glob
import sys
import os

# logging.getLogger('angr').setLevel('DEBUG')
logging.disable()
# Collecting files from given directory
for arg in glob.glob("test/dumps/*"): #glob.glob(sys.argv[1] + "*"):
    sys.stdout = open("test/dis/" + str(os.path.basename(arg)) + ".txt", "w")
    p = angr.Project(str(arg), load_options={'auto_load_libs': False})
    cfg = p.analyses.CFGFast(
            normalize=True,
            resolve_indirect_jumps=False)
    funcs = dict(cfg.kb.functions)

    for f in funcs.values():
        name = f.name
        addr = f.addr
        if not name.startswith("__"): # don't log internal and stub functions
            for block in f.blocks:
                print(name) # + ": " + str(addr))
                for ins in block.capstone.insns:
                    if ins.op_str == "":
                        print(ins.mnemonic)
                        continue
                    print(ins.mnemonic + " " + ins.op_str)
                print("")

