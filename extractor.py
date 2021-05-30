# This scirpt extracts the analysed disassembled function collection
# of various binary files and dumps to files
import angr
import logging
from glob import glob
import os
import io
import networkx as nx
from pprint import pprint as pp

logging.disable()

def extractor():
    print("Extractor now running..")
    # Step 1
    for arg in glob("test/dumps/*"):  # glob.glob(sys.argv[1] + "*"):
        f = open("test/dis/" + str(os.path.basename(arg)) + ".txt", "w")
        p = angr.Project(str(arg), load_options={"auto_load_libs": False})
        p.arch.capstone_x86_syntax = "at&t"
        cfg = p.analyses.CFGEmulated(
            context_sensitivity_level=10,
            normalize=True,
            resolve_indirect_jumps=False,
            enable_symbolic_back_traversal=False,
        )
        cfg.remove_cycles()
        cfg.force_unroll_loops(10)
        dump_assembly(f, cfg)


def dump_assembly(file: io.FileIO, cfg: angr.analyses.cfg.cfg_emulated.CFGEmulated):
    for node in cfg.model.nodes():
        if node.block == None:
            continue
        name = node.name or str(node.addr)  # log the name or the address
        parents = "".join(
            [
                (elem.name is not None) and (elem.name + " ") or ""
                for elem in node.predecessors
            ]
        )
        successors = "".join(
            [
                (elem.name is not None) and (elem.name + " ") or ""
                for elem in node.successors
            ]
        )

        in_degree = cfg.graph.in_degree(node)
        out_degree = cfg.graph.out_degree(node)

        block = node.block
        file.write(name + " " + parents + ", " + successors + ", " + str(in_degree) + " " + str(out_degree) + "\n")
        for ins in block.capstone.insns:
            file.write(ins.mnemonic + " " + (ins.op_str + "\n") or "\n")

        file.write("\n")


extractor()
