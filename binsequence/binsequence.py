import angr
import logging
import os
import io
import networkx as nx
from networkx.algorithms import all_simple_paths
from icecream import ic as icy
import sys
import pydot
import re, queue, glob
from pprint import pprint as pp

# graph = nx.drawing.nx_pydot.to_pydot(cfg.graph)
# graph.write_png("out.png")


# GLOBALS
IDENTICAL_OPERAND_SCORE = 1
IDENTICAL_MNEMONIC_SCORE = 2
IDENTICAL_CONSTANT_SCORE = 3


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
def construct_functions(cfg):
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
                n_comma = name[name.index(",") + 1 :]
                n_comma1 = n_comma[n_comma.index(",") + 1 :]
                node.preds = list(filter(None, name[1:comma]))
                node.succs = list(filter(None, n_comma[: n_comma.index(",")]))
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


def comp_ins(instr, instr1):
    """Algorithm 1: Compare two instructions
    name:   compare instructions
    input:  normalized instructions
    output: matching score between two instructions
    """

    score = 0
    op = instr.op_str.split(",")
    op1 = instr1.op_str.split(",")
    mem = ["-", "0x", "*"]
    if instr.mnemonic == instr1.mnemonic:
        n = len(instr1.operands)
        score += IDENTICAL_MNEMONIC_SCORE
        for i in range(0, n):
            if op[i].startswith(tuple(mem)) and op1[i].startswith(
                tuple(mem)
            ):  # if immediate value
                if op[i].startswith("$"):  # if CONSTANTS
                    if op[i][1:] == op[i][1:]:  #  if constants equal
                        score += IDENTICAL_CONSTANT_SCORE
                else:
                    score += IDENTICAL_OPERAND_SCORE
    else:
        score = 0

    return score


def comp_BBS(bb1, bb2):

    """Algorithm 2: Calculate the similarity score of two basic blocks

    name: compare basic blocks
    input: Two basic blocks BB1, BB2
    output: The similarity score of two blocks

    """

    # The memoization table
    len_bb1 = len(bb1.disassembly.insns)
    len_bb2 = len(bb2.disassembly.insns)
    M = [[0] * (len_bb2 + 1)] * (len_bb1 + 1)

    for i in range(1, len_bb1 + 1):
        for j in range(1, len_bb2 + 1):
            M[i][j] = max(
                comp_ins(bb1.disassembly.insns[i - 1], bb2.disassembly.insns[j - 1])
                + M[i - 1][j - 1],
                M[i - 1][j],
                M[i][j - 1],
            )

    return M[len_bb1 - 1][len_bb2 - 1]


def path_exploration(P: CFG, G: CFG) -> list:

    """Algorithm 3: Path exploration

    input:  P: the longest path from the target function -- CFG
                G: the CFG of the reference function

    Output: d: The memoization table

    s: the array that stores the largest LCS score for every node in G

    """
    def LCS(u, P):
        # u target node
        # P path of nodes
        sim = 0
        u = Reference_CFG.get_any_node(u.addr)
        for v in P:
            v = Target_CFG.get_any_node(v.addr)
            if same_degree(u, v):
                sim = comp_BBS(u.block, v.block)
            else:
                sim = 0

   #         d[u.name][v.name] = max( d[u.predecessors][v.predecessors] + sim, d[u.predecessors][v], d[u][v.predecessors])

   # d = [[0] * len(P)] * 1
   # s = [0] * len(G)
    Q = queue.Queue()
    [Q.put(n) for n in G]
    while not Q.empty():
        currNode = Q.get()
   #     d.append([])  # Always add a new row
        LCS(currNode, P)





def same_degree(u, v):
    u_degree = Reference_CFG.graph.degree(Reference_CFG.get_any_node(u.addr))
    v_degree = Target_CFG.graph.degree(Target_CFG.get_any_node(v.addr))
    if u_degree == v_degree:
        return True

    return False
    # icy(u_degree, v_degree)


def longest_path_generation(func):
    nodes = [i for i in func.graph.nodes()]
    paths = all_simple_paths(func.graph, nodes[0], nodes[-1])
    target = nx.DiGraph()
    _max = 0
    longest_path = 0
    for path in paths:
        if len(path) > _max:
            _max = len(path)
            longest_path = path

    for l in longest_path:
        target.add_node(l.addr)

    return target


def extractor():
    print("Extractor now running..")
    # Step 1

    # First pass to store target cfg
    target = 0
    p = angr.Project("test/dumps/target", load_options={"auto_load_libs": False})
    p.arch.capstone_x86_syntax = "at&t"
    cfg = p.analyses.CFGEmulated(
        context_sensitivity_level=10,
        normalize=True,
        resolve_indirect_jumps=False,
        enable_symbolic_back_traversal=False,
    )
    Target_Keys = {i.name: i for i in cfg.graph.nodes.keys()}
    global Target_CFG
    Target_CFG = cfg.copy()
    funcs = {i.name: i for i in cfg.functions.values()}
    target = funcs["main"]

    # Second pass for all the others
    for arg in glob.glob("test/dumps/*"):
        if str(arg) == "test/dumps/simcc":
            continue
        p = angr.Project(str(arg), load_options={"auto_load_libs": False})
        p.arch.capstone_x86_syntax = "at&t"
        cfg = p.analyses.CFGEmulated(
            context_sensitivity_level=10,
            normalize=True,
            resolve_indirect_jumps=False,
            enable_symbolic_back_traversal=False,
        )
        global Reference_CFG
        Reference_CFG = cfg.copy()
        funcs = {i.name: i for i in cfg.functions.values()}
        # Generating longest_path of the target function
        # target = longest_path_generation(funcs["main"])
        for func in funcs.values():
            path_exploration(target.graph, func.graph)


Target_CFG = 0  # Control-Flow-Graphs of all binaries
Reference_CFG = 0
Keys = {}  # Keys to find out the degree
Target_Keys = {}
logging.disable()

extractor()

# for i in CFGs["target"].nodes.values():
#    ic(str(i.succs) + " - " + str(i.preds) + " - " + i.in_degree + i.out_degree)
