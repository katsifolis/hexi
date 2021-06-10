import sys, glob, os, time, angr, logging
from icecream import ic as icy
from pprint import pprint as pp

# Interpret : seq(Instruction) ×State →State

# State = LValue →RValue
# LValue = Register + Mem
# Mem = RValue →RValue
# RValue = Int + def(LValue) + (RValue op RValue) + (op RValue)
def interpreter(instr):
    mem = ("-", "0x", "*", "$", "%") # MEM constraint
    instr.split(" ")


def simplify(rvalue):
    pass


# Decomposes the disassembled program into procedures and blocks
def decompose():
    # First pass to store target cfg
    p = angr.Project("test/dumps/target", load_options={"auto_load_libs": False})
    p.arch.capstone_x86_syntax = "at&t"
    cfg = p.analyses.CFGEmulated(
        normalize=True,
    )
    procedures = {
        func: [func for func in func.blocks] for func in cfg.functions.values()
    }

    for name, blocks in procedures.items():
        for block in blocks:
            for ins in block.disassembly.insns:
                interpreter(ins.mnemonic + " " + ins.op_str)


icy("Decomposer now running..")
logging.disable()
t = time.time()
decompose()
icy(time.time() - t)
