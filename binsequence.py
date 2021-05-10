# Implementation of the algorithms and structures of Binsequence paper
import os, sys
import glob
from pprint import pp
import re

class BB:
    """ Basic Block class
    """
    def __init__(self, instrs):
        self.instrs = instrs

class Instr:
    def __init__(self):
        self.mnemonic = ""
        self.operand = [0] * 2 # operands max
        self.type = ""

def parse_instr(instruction):
    parsed_instr = Instr()
    CONSTANT = 1
    IDENTICAL_OPERAND_SCORE = 1
    IDENTICAL_MNEMONIC_SCORE = 2
    IDENTICAL_CONSTANT_SCORE = 3
    instr = re.split(", |\n", instruction)
    

    parsed_instr.mnemonic = instr[0].split(" ")[0]
    # if it has no operands pop the list until we get empty list
    try:
        parsed_instr.operand[0] = instr[0].split(" ")[1]
    except:
        parsed_instr.operand.pop()
            
    try:
        parsed_instr.operand[1] = instr[1] or ''
    except:
        parsed_instr.operand.pop()
    
    return parsed_instr

def parse_bbs(lines):
    tmp_bbs = []
    tmp_lst = []
    # Constructing an array containing each individual disassembled func
    for i, v in enumerate(lines):
        if v == "":
            tmp_bbs.append(tmp_lst.copy())
            tmp_lst = []
            continue

        tmp_lst.append(v)

    name = 0
    bbs = {}
    for bb in tmp_bbs:
        for i, instr in enumerate(bb):
            if i == 0:
                name = instr
                bbs[name] = bbs.get(name) or []
                continue
            bbs[name].append(parse_instr(instr))

    return bbs

class Differ:
    def __init__(self, lines):
        self.bbs = parse_bbs(lines) # dictionary of basic blocks

    def print_bbs_names(self):
        pp(self.bbs_names)

    def print_bbs(self):
        for i in self.bbs:
            pp(i)
        
    def comp_ins(self,instr, instr1):
        """ Algorithm 1: Compare two instructions 
        name:   compare instructions
        input:  normalized instructions
        output: matching score between two instructions
        """
        score = 0
        if instr.mnemonic == instr1.nemonic:
            n = num_of_operands(intr.operand, instr1.operand)
            score += IDENTICAL_MNEMONIC_SCORE
            for i in range(0, n):
                if intsr.operands[i] == instr1.operands[i]:
                    if instr.type == CONSTANTS:
                        score += IDENTICAL_CONSTANT_SCORE
                    else:
                        score += IDENTICAL_OPERAND_SCORE
        else:
            score = 0

        return score

    def comp_BBS(self, bb1, bb2):
        """ Algorithm 2: Calculate the similarity score of two basic blocks

        name: compare basic blocks
        input: Two basic blocks BB1, BB2
        output: The similarity score of two blocks
        """
        # The memoization table
        M = [[0] * (len(bb1) + 1), [0] * (len(bb2) + 1)]

        for i in range(1,len(bb1)):
            for j in range(1,len(bb2)):
                M[i, j] = max(
                        self.comp_ins(bb1[i], bb2[j]) + M[i - 1, j - 1],
                        M[i-1, j],
                        M[i, j-1])

        return M

# Entry point
if len(sys.argv) < 2:
    print("No directory given")
    sys.exit()

lines = []
f = 0
differs = {}
for v in glob.glob(sys.argv[1] + "*"):
    f        = open(v)
    lines      = f.read().splitlines()
    d        = Differ(lines)
    filename = os.path.splitext(os.path.basename(v))[0]
    differs[filename] = d
    f.close()

for i in differs["target"].bbs.values():
    for j in i:
        print(j.operand)
