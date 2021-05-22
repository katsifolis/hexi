import glob, os
from pprint import pprint as pp

#Interpret : seq(Instruction) ×State →State

# State = LValue →RValue
# LValue = Register + Mem
# Mem = RValue →RValue
# RValue = Int + def(LValue) + (RValue op RValue) + (op RValue)
def interpreter():
    pass

def simplify(rvalue):

# Decomposes the disassembled program into procedures and blocks
def decompose():
    lines = []
    f = 0
    progs = {}
    for v in glob.glob("test/dis/*"):
        tmp_bbs = []
        tmp_lst = []
        f        = open(v)
        lines    = f.read().splitlines()
        filename = os.path.splitext(os.path.basename(v))[0]

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

        progs[filename] = tmp_bbs

    for i, v in progs.items():
        pp(i + " -> ")
        for vv in v:
            print(str(vv))

decompose()
