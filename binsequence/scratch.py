##############################################################
g = nx.drawing.nx_pydot.to_pydot(target.graph)
g.write_png("out.png")
sys.exit()
##############################################################
def init_memoization(P, G):
    mem = {}
    for i, j in zip(P, G):
        u = Target_CFG.get_any_node(i.addr)
        v = Reference_CFG.get_any_node(j.addr)
        mem[(u, v)] = 0

        for u_succs, v_succs in zip(u.successors, v.successors):
            mem[(u_succs, v_succs)] = 0
        for u_preds, v_preds in zip(u.predecessors, v.predecessors):
            mem[(u_preds, v_preds)] = 0
    icy(mem)
    return mem


##############################################################
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
        target.add_node(l)

    return target

    ##############################################################
    # Longest path
    t = longest_path_generation(funcs["main"])
    for i in t:
        icy(Target_CFG.get_any_node(i.addr).block)


##############################################################
def largest_LCS_score(graph):
    lcs = []
    for node in graph:
        v = Reference_CFG.get_any_node(node.addr)
        if v.block != None:
            lcs.append(comp_BBS(v.block, v.block))

    return lcs
