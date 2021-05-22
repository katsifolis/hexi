# This scirpt extracts the analysed disassembled function collection 
# of various binary files and dumps to files

import angr
import time
#import networkx as nx
from icecream import ic
#from networkx.algorithms.dag import dag_longest_path
#from networkx.algorithms.traversal import depth_first_search as dfs
import logging
import glob
import sys
import os
from pprint import pprint as pp
#import matplotlib.pyplot as plt

logging.disable()
# Collecting files from given directory
#p = angr.Project(str("test/dumps/target"), load_options={'auto_load_libs': False})
#cfg = p.analyses.CFGEmulated(keep_state=True, normalize=True, resolve_indirect_jumps=False, context_sensitivity_level=1)
#logging.getLogger('angr').setLevel('DEBUG')
#ic(cfg.remove_cycles())
#cfg.remove_cycles() # Converting the directed graph to acyclic by pruning cycles
#dag_longest_path(cfg.graph)
#ic(cfg.graph)


ic("now running")
start = time.time()
# Step 1
for arg in glob.glob("test/dumps/*"): #glob.glob(sys.argv[1] + "*"):
    file = open("test/dis/" + str(os.path.basename(arg)) + ".txt", "w")
    p = angr.Project(str(arg), load_options={'auto_load_libs': False})
    cfg = p.analyses.CFGEmulated(
            normalize=True,
            resolve_indirect_jumps=True,
            enable_symbolic_back_traversal=True)
    funcs = dict(cfg.kb.functions)
    for f in funcs.values():
        name = f.name
        addr = f.addr
        if not name.startswith("__"): # don't log internal and stub functions
            for block in f.blocks:
                file.write(name + "\n")
                for ins in block.capstone.insns:
                    if ins.op_str == "":
                        file.write(ins.mnemonic + "\n")
                        continue
                    file.write(ins.mnemonic + " " + ins.op_str + "\n")
                file.write("\n")

ic(time.time() - start)
