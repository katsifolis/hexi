import angr
import logging
import time
import networkx as nx
from icecream import ic as icy
from pprint import pprint as ppp
import sys
import pydot
import queue, glob


# GLOBALS
IDENTICAL_OPERAND_SCORE = 1
IDENTICAL_MNEMONIC_SCORE = 2
IDENTICAL_CONSTANT_SCORE = 3


def comp_ins(instr, instr1):
    """Algorithm 1: Compare two instructions
    name:   compare instructions
    input:  normalized instructions
    output: matching score between two instructions
    """

    score = 0
    # trim the whitespace and make the operand list
    op = [x.strip(" ") for x in instr.op_str.split(",")]
    op1 = [x.strip(" ") for x in instr1.op_str.split(",")]
    mem = ("-", "0x", "*", "$", "%")
    if instr.mnemonic == instr1.mnemonic:
        n = len(instr1.operands)
        score += IDENTICAL_MNEMONIC_SCORE
        for i in range(0, n):
            # if immediate value
            if op[i].startswith(mem) and op1[i].startswith(mem):
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

    return M[len_bb1][len_bb2]


# Returns the self score of the given path
def score(P):
    score = 0
    for node in P:
        v = Reference_CFG.get_any_node(node.addr)
        if v.block != None:
            score += comp_BBS(v.block, v.block)

    return score


def path_exploration(P, G) -> list:

    """Algorithm 3: Path exploration

    input:  P: the longest path from the target function -- CFG
                G: the CFG of the reference function

    Output: d: The memoization table

    s: the array that stores the largest LCS score for every node in G

    """

    def LCS(u, P):
        # u reference node
        # P path of target function nodes
        sim = 0
        u_pred = None
        v_pred = None
        unode = Reference_CFG.get_any_node(u.addr)
        if u.is_hook:
            return
        for v in P.nodes:
            # We don't want a hook node
            if v.is_hook:
                continue

            vnode = Target_CFG.get_any_node(v.addr)
            if same_degree(u, v):
                sim = comp_BBS(unode.block, vnode.block)
            else:
                sim = 0

            for i in G.predecessors(u):
                if not i.is_hook:
                    u_pred = i
            for i in P.predecessors(v):
                if not i.is_hook:
                    v_pred = i

            if u_pred is None or v_pred is None:
                d[mref[u]][mtarget[v]] = 0

            else:
                try:
                    d[mref[u]][mtarget[v]] = max(
                        d[mref[u_pred]][mtarget[v_pred]] + sim,
                        d[mref[u_pred]][mtarget[v]],
                        d[mref[u]][mtarget[v_pred]],
                    )
                except:
                    icy(mtarget[v])
                    sys.exit()

    mref = {node: idx for idx, node in enumerate(G.nodes) if not node.is_hook}
    mtarget = {node: idx for idx, node in enumerate(P.nodes) if not node.is_hook}
    d = [[0] * (len(P.nodes) + 1)]
    s = [0] * len(G.nodes)
    Q = queue.Queue()
    [Q.put(n) for n in G.nodes if not n.is_hook]
    while not Q.empty():
        currNode = Q.get()
        d.append([0] * (len(P.nodes) + 1))  # Always add a new row
        LCS(currNode, P)
        if s[mref[currNode]] < d[mref[currNode]][len(P) - 1]:
            s[mref[currNode]] = d[mref[currNode]][len(P) - 1]
            for succ in G.successors(currNode):
                Q.put(succ)

    return d


def same_degree(u, v):
    u_degree = Reference_CFG.graph.degree(Reference_CFG.get_any_node(u.addr))
    v_degree = Target_CFG.graph.degree(Target_CFG.get_any_node(v.addr))
    if u_degree == v_degree:
        return True

    return False


def extractor():
    global Target_CFG
    global Reference_CFG
    print("Extractor now running..")
    t = time.time()
    # Step 1

    # First pass to store target cfg
    p = angr.Project("test/dumps/target", load_options={"auto_load_libs": False})
    p.arch.capstone_x86_syntax = "at&t"
    c = p.analyses.CFGEmulated(
        normalize=True,
    )
    Target_CFG = c.copy()
    funcs = {i.name: i for i in c.functions.values()}
    # Hash every BlockNode with a number
    for arg in glob.glob("test/dumps/*"):
        icy("new")
        p = angr.Project(str(arg), load_options={"auto_load_libs": False})
        p.arch.capstone_x86_syntax = "at&t"
        cfg = p.analyses.CFGEmulated(
            normalize=True,
        )
        Reference_CFG = cfg.copy()
        # Generating longest_path of the target function
        for f in funcs.values():
            for func in cfg.functions.values():
                #            path_exploration(target.graph, func.graph)
                p = path_exploration(f.graph, func.graph)
    #                print("target ->" + f.name + " -> " + func.name)

    icy(time.time() - t)


Target_CFG = 0  # Control-Flow-Graphs of all binaries
Reference_CFG = 0
logging.disable()
extractor()
