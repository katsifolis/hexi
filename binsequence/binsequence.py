# Implementation of the algorithms and structures of Binsequence paper
import os, sys
import glob
import re
import queue
from pprint import pprint as pp

# GLOBALS
IDENTICAL_OPERAND_SCORE = 1
IDENTICAL_MNEMONIC_SCORE = 2
IDENTICAL_CONSTANT_SCORE = 3

class BB:
    """ Basic Block class
    """
    def __init__(self, instructions):
        self.instructions = instructions

# Assembly Instruction struct
class Instr:
    def __init__(self):
        self.mnemonic = "" 
        self.operand = [''] * 3 # assembly instruction up to 3 operands max
        self.type = ""

class Differ:
    def __init__(self, lines):
        self.bbs = parse_bbs(lines) # dictionary of basic blocks

    def print_bbs_names(self):
        print(self.bbs_names)

    def print_bbs(self):
        for i in self.bbs:
            print(i)
        

def parse_instr(instruction):
    parsed_instr = Instr()

    # chops instruction string 
    instr = re.split(", |\n", instruction)
    parsed_instr.mnemonic = instr[0].split(" ")[0]
    # 1. Parsing
    # if it has no operands pop the list until we get empty list
#    print(instr)
    for i, v in enumerate(instr):
        if i == 0:
            tmp = v.split(" ")
            parsed_instr.mnemonic = tmp[0]
            word_list = ["qword", "dword", "byte", "word"]
            try:
                parsed_instr.operand[i] = tmp[1]
                for o in tmp[2:]:
                    if o in "ptr":
                        parsed_instr.operand[i] = "".join(str(re.findall("\[(.*?)\]", " ".join(tmp[1:])))) 
            except:
                pass

        elif len(v.split(" ")) <= 2:
            parsed_instr.operand[i] = str(v)
            parsed_instr.operand[i-1] = "" # workaround when instruction has one operand and the operand list should have 2 entries not one
        else:
            for o in v.split(" "):
                if "dword" in o or "word" in o or "byte" in o:
                    parsed_instr.operand[i] = "".join(str(re.findall("\[(.*?)\]", v)))


    parsed_instr.operand = [i for i in parsed_instr.operand if i != '']



    """ 
    Normalization

    3 categories for the operands:
        * registers
        * memory references
        * immediate values -> memory offsets | constant values

    """

    # hardcoded every possible register in x86
    regs64 = ["rax", "rbx", "rcx", "rdx", "rbp", "rsp", "rsi", "rdi"]
    regs32 = ["eax", "ebx", "ecx", "edx", "ebp", "esp", "esi", "edi"]
    regs16 = ["ax", "bx", "cx", "dx", "bp", "sp", "si", "di"]
    regs8  = ["ah", "al", "bh", "bl", "ch", "cl", "dh", "dl", "bpl", "spl", "sil", "dil"]
    regsr  = ["r" + str(i) for i in range(1, 15)]

    # Iterate through operands
    for i, op in enumerate(parsed_instr.operand):
        if op in regs64 or op in regs32 or op in regs16 or op in regs8 or op in regsr:
            parsed_instr.operand[i] = "REG"
            parsed_instr.type = "REGISTER"
        elif op.startswith("["):
            parsed_instr.type = "MEMORY"
        elif op.startswith("0x"):
            parsed_instr.type = "MEMORY"
        elif op.isnumeric():
            parsed_instr.type = "CONSTANT"

    if len(parsed_instr.operand) == 0:
            parsed_instr.type = "NONE"

    pp(parsed_instr.operand)
    return parsed_instr

def parse_bbs(lines):
    tmp_bbs = []
    tmp_lst = []
    # Constructing an array containing each individual disassembled func
    for i, v in enumerate(lines):
        # The extractor script divides every basic block with a new line
        # So we detect it with a blank comparison
        # Then we append to the list of bbs
        # And empty the temporary for another round
        if v == "":
            tmp_bbs.append(tmp_lst.copy())
            tmp_lst = []
            continue

        tmp_lst.append(v)

    name = 0
    bbs = {}
    for bb in tmp_bbs:
        for i, instr in enumerate(bb):
            # In idx 0 lies the name of the basic block
            # So we assign it and continue with the instructions
            if i == 0:
                name = instr
                bbs[name] = bbs.get(name) or []
                continue
            bbs[name].append(parse_instr(instr))

    return bbs

def comp_ins(instr, instr1):
    """ Algorithm 1: Compare two instructions 
    name:   compare instructions
    input:  normalized instructions
    output: matching score between two instructions
    """

    score = 0
    if instr.mnemonic == instr1.mnemonic:
        n = len(instr1.operand)
        score += IDENTICAL_MNEMONIC_SCORE
        for i in range(0, n):
            try:
                if instr.operand[i] == instr1.operand[i]:
                    if instr.type == "CONSTANT":
                        score += IDENTICAL_CONSTANT_SCORE
                    else:
                        score += IDENTICAL_OPERAND_SCORE
            except:
                pass
    else:
        score = 0

    return score

def comp_BBS(bb1, bb2):

    """ Algorithm 2: Calculate the similarity score of two basic blocks

    name: compare basic blocks
    input: Two basic blocks BB1, BB2
    output: The similarity score of two blocks

    """

    # The memoization table
    M = [[0] * (len(bb2) + 1)]* (len(bb1) +1)

    for i in range(1,len(bb1)):
        for j in range(1,len(bb2)):
            M[i][j] = max(
                    comp_ins(bb1[i], bb2[j]) + M[i - 1][j - 1],
                    M[i-1][j],
                    M[i][j-1])

    return M[len(bb1)-1][len(bb2)-1]

def path_exploration(P,G):

    """ Algorithm 3: Path exploration

	input:  P: the longest path from the target function
		    G: the CFG of the reference function

	Output: d: The memoization table

	s: the array that stores the largest LCS score for every node in G

    """
    d = [[0] * len(P)] * 1
    s = [0] * len(G)
    Q = queue.Queue()


def LCS(u, P, d):
    # u target node
    # P path of nodes
    sim = 0 
    for v in P.nodes():
        if SameDegree(u, v):
            sim = comp_BBS(u,v)
        else:
            sim = 0

# Loading the dissasembled txt for each individual binary,
# computing the similarity score of basic blocks,
# into ram.
lines = []
f = 0
differs = {}
for v in glob.glob("test/dis/*"):
    f        = open(v)
    lines    = f.read().splitlines()
    d        = Differ(lines)
    filename = os.path.splitext(os.path.basename(v))[0]
    differs[filename] = d
    f.close()

res = 0
target = differs["target"].bbs
for name, i in differs.items():
    sim = i.bbs
    for prog, prog1 in zip(target.values(), sim.values()):
        res += comp_BBS(prog, prog1)

    print(name + " " + str(res))
    res=0
    
#a = [1,2,3,4]
#b = [1,2]
#path_exploration(a,b)
#
