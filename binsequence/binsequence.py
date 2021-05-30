# Implementation of the algorithms and structures of Binsequence paper
import os, sys
import glob
import re
import queue
from icecream import ic
from networkx.algorithms import all_simple_paths

# GLOBALS
IDENTICAL_OPERAND_SCORE = 1
IDENTICAL_MNEMONIC_SCORE = 2
IDENTICAL_CONSTANT_SCORE = 3

CFGs = {} # Control-Flow-Graphs of all binaries

class BB:
    """Basic Block class"""

    def __init__(self, instructions):
        self.instructions = instructions

    def __str__(self):
        return f"{self.instructions}"


# Assembly Instruction struct
class Instr:
    def __init__(self):
        self.mnemonic = ""
        self.operand = []  # assembly instruction up to 3 operands max
        self.type = ""

    def __str__(self):
        return f"{self.mnemonic} {self.operand}"


class CFGNode:
    def __init__(self):
        self.name = ""
        self.bb = []
        self.score = 0
        self.succs = []
        self.preds = []
        self.in_degree = ""
        self.out_degree = ""
        pass


class CFG:
    def __init__(self, lines):
        self.nodes = construct_nodes(lines)


def parse_instr(instruction: Instr):
    parsed_instr = Instr()

    # chops instruction string
    instr = re.split(" |\n", instruction)
    parsed_instr.mnemonic = instr[0].split(" ")[
        0
    ]  # first part of the string is always the mnemonic
    # 1. Parsing
    # We slice from 1 to the end and retrieve the operands
    for v in instr[1:]:
        try:
            parsed_instr.operand.append(v)
        except:
            parsed_instr.operand.append("")

    """ 
    Normalization

    3 categories for the operands:
        * registers
        * memory references
        * immediate values -> memory offsets | constant values

    """

    # Iterate through operands
    for i, op in enumerate(parsed_instr.operand):
        if "%" in op:
            parsed_instr.operand[i] = "REG"
            parsed_instr.type = "REGISTER"
        elif op.startswith("0x") or op.startswith("-0x"):
            parsed_instr.operand[i] = "MEMORY"
            parsed_instr.type = "MEMORY"
        elif op.startswith("*"):
            parsed_instr.operand[i] = "MEMORY"
            parsed_instr.type = "MEMORY"
        elif op.startswith("$"):
            parsed_instr.operand[i] = "CONSTANT"
            parsed_instr.type = "CONSTANT"

    if len(parsed_instr.operand) == 0:
        parsed_instr.type = "NONE"

    for i in range(3):
        try:
            parsed_instr.operand[i] != ""
        except:
            parsed_instr.operand.append("")

    return parsed_instr


# This function constructs CFGNodes which contain the basic block, name, parents, successors
def construct_nodes(lines: list[str]) -> list[CFGNode]:
    tmp_bbs = []
    tmp_lst = []
    nodes = {}
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

    for line, bb in enumerate(tmp_bbs):
        node = CFGNode()
        for i, instr in enumerate(bb):
            # In idx 0 lies the name of the basic block
            # So we assign it and continue with the instructions
            if i == 0:
                # Keep a close EYE here 
                # Format is
                # NAME_NODE SUCCESSORS, PARENTS , IN_DEGREE OUT_DEGREE
                name = instr.split(" ")
                node.name = name[0]
                comma = name.index(",")
                n_comma = name[name.index(",")+1:]
                n_comma1 = n_comma[n_comma.index(",")+1:]
                node.preds = list(filter(None, name[1:comma]))
                node.succs = list(filter(None, n_comma[:n_comma.index(",")]))
                node.in_degree = n_comma1[0]
                node.out_degree = n_comma1[1]
                continue
            node.bb.append(parse_instr(instr))
        nodes[node.name] = node

    return nodes

# construct_succs_preds builds the CFGNodes of each parent and successors
# from each individual Node
def construct_succs_preds(c: CFG):
    for v in c.nodes.values():
        tmp_succs = {}
        tmp_preds = {}
        if len(v.succs) > 0: 
            for s in v.succs:
                try:
                    tmp_succs[s] = c.nodes[s]
                except:
                    pass
        elif len(v.preds) > 0:
            for s in v.preds:
                try:
                    tmp_preds.append(c.nodes[s])
                except:
                    pass

        v.succs = tmp_succs
        v.preds = tmp_preds


def comp_ins(instr: Instr, instr1: Instr) -> int:
    """Algorithm 1: Compare two instructions
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
                break
    else:
        score = 0

    return score


def comp_BBS(bb1: BB, bb2: BB) -> int:

    """Algorithm 2: Calculate the similarity score of two basic blocks

    name: compare basic blocks
    input: Two basic blocks BB1, BB2
    output: The similarity score of two blocks

    """

    # The memoization table
    M = [[0] * (len(bb2) + 1)] * (len(bb1) + 1)

    for i in range(1, len(bb1)):
        for j in range(1, len(bb2)):
            M[i][j] = max(
                comp_ins(bb1[i], bb2[j]) + M[i - 1][j - 1], M[i - 1][j], M[i][j - 1]
            )

    return M[len(bb1) - 1][len(bb2) - 1]


def path_exploration(P: CFG, G: CFG) -> list:

    """Algorithm 3: Path exploration

    input:  P: the longest path from the target function -- CFG
                G: the CFG of the reference function

    Output: d: The memoization table

    s: the array that stores the largest LCS score for every node in G

    """
    d = [[0] * (len(P.nodes) + 1)]
    s = [0] * len(G.nodes)
    Q = queue.Queue()
    [Q.put(n) for n in G.nodes.values()]
    while not Q.empty():
        currNode = Q.get()
        d.append([])  # Always add a new row
        LCS(currNode, P)


def LCS(u: CFGNode, P: CFG):
    # u target node
    # P path of nodes
    sim = 0
#    for v in P.nodes():
#        if SameDegree(u, v):
#            sim = comp_BBS(u, v)
#        else:
#            sim = 0


# Loading the dissasembled txt for each individual binary,
# computing the similarity score of basic blocks,
# into ram.
def load_cfgs() -> None:
    for v in glob.glob("test/dis/*"):
        f = open(v)
        disas = f.read().splitlines()
        d = CFG(disas)
        construct_succs_preds(d)
        filename = os.path.splitext(os.path.basename(v))[0]
        CFGs[filename] = d
        f.close()


load_cfgs()

for i in CFGs["target"].nodes.values():
    ic(str(i.succs) + " - " + str(i.preds) + " - " + i.in_degree + i.out_degree)
#target = CFGs["target"].nodes["min"]
#for i in CFGs["simcc"].nodes.values():
#    print(target.name + " -> " + i.name + " -> " + str(comp_BBS(i.bb, target.bb)))
#
#print(target.name + " -> " + str(comp_BBS(target.bb, target.bb)))
#path_exploration(CFGs["target"], CFGs["simcc"])
