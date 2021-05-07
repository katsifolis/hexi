# Implementation of the algorithms and structures of Binsequence paper

class BB:
    """ Basic Block class

    """
    pass

class Instr:
    CONSTANT = 1
    IDENTICAL_OPERAND_SCORE = 1
    IDENTICAL_MNEMONIC_SCORE = 2
    IDENTICAL_CONSTANT_SCORE = 3
    def __init__(self, _type, _mnemonic, _operand):
        self.type = _type
        self.mnemonic = _mnemonic
        self.operand = _operand


class Differ:
    def comp_ins(instr, instr1):
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
                for intsr.operands[i] == instr1.operands[i]:
                    if instr.type == CONSTANTS:
                        score += IDENTICAL_CONSTANT_SCORE
                    else:
                        score += IDENTICAL_OPERAND_SCORE
        else:
            score = 0

        return score

    def comp_BBS(bb1, bb2):
        """" Algorithm 2: Calculate the similarity score of two

        name: compare basic blocks
        input: Two basic blocks BB1, BB2
        output: The similarity score of two blocks
        """

        @TODO

