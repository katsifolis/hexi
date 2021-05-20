# This scirpt extracts the analysed disassembled function collection 
# of various binary files and dumps to files

import angr

import networkx as nx
from icecream import ic
from networkx.algorithms.dag import dag_longest_path
from networkx.algorithms.traversal import depth_first_search as dfs
import logging
import glob
import sys
import os
import matplotlib.pyplot as plt

logging.disable()
# Collecting files from given directory
#p = angr.Project(str("test/dumps/target"), load_options={'auto_load_libs': False})
#cfg = p.analyses.CFGEmulated(keep_state=True, normalize=True, resolve_indirect_jumps=False, context_sensitivity_level=1)
#logging.getLogger('angr').setLevel('DEBUG')
#ic(cfg.remove_cycles())
#cfg.remove_cycles() # Converting the directed graph to acyclic by pruning cycles
#dag_longest_path(cfg.graph)
#ic(cfg.graph)


# Step 1
for arg in glob.glob("test/dumps/*"): #glob.glob(sys.argv[1] + "*"):
    sys.stdout = open("test/dis/" + str(os.path.basename(arg)) + ".txt", "w")
    p = angr.Project(str(arg), load_options={'auto_load_libs': False})
    cfg = p.analyses.CFGEmulated(
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

