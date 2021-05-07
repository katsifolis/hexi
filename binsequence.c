/* 
 * This is an implementation of a fuzzy binary code similarity detector
 * From: BinSequence: Fast, Accurate and Scalable Binary Code 
 */

#ifndef STDLIB_H
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#endif

#define CONSTANTS 1
#define INSTRUCTION_SIZE 		 200
#define MNEMONIC_SIZE 	 		 200
#define OPERAND_SIZE 			 200
/* Scores */
#define IDENTICAL_OPERAND_SCORE  1
#define IDENTICAL_MNEMONIC_SCORE 2
#define IDENTICAL_CONSTANT_SCORE 3

#include "binsequence.h"


/* Returns a normalized instruction */
Instruction* new_instruction() {
	/* Allocating memory for instruction struct */
	Instruction *instr = malloc(sizeof(Instruction*));
	instr->mnemonic    = malloc(sizeof(char) * MNEMONIC_SIZE);
	Operands *op 	   = malloc(sizeof(Operands));
	op->operand 	   = malloc(sizeof(char) * OPERAND_SIZE);

	strcpy(op->operand, "Something in the way");
	strcpy(instr->mnemonic, "Something in the other way");
	instr->operands = op;
	return instr;
}

int num_of_operands(char* op) {
	return 1;
}

/* 
 * Algorithm 1: Compare two instructions 
 * name:   compare instructions
 * input:  normalized instructions
 * output: matching score between two instructions
 */
int comp_ins(Instruction *instr, Instruction *instr1) {
	int score = 0;
	if (strcmp(instr->mnemonic, instr1->mnemonic) == 0) {
		int n = num_of_operands(instr1->operands->operand);
		score += IDENTICAL_MNEMONIC_SCORE;
		for (int i = 0; i < n; i++) {
			if (strcmp(instr->operands[i].operand, instr1->operands[i].operand) == 0) {
				if (instr->operands[i].type == CONSTANTS) {
					score += IDENTICAL_CONSTANT_SCORE;
				} else {
					score += IDENTICAL_OPERAND_SCORE;
				}
			}
		}
	} else {
		score = 0;
	}
	return score;
}

/*
 * Algorithm 2: Calculate the similarity score of two
 * name: compare basic blocks
 * input: Two basic blocks BB1, BB2
 * output: The similarity score of two blocks
 */
int comp_bbs(BB bb1, BB bb2) {
	int score = 0;
	return 1;
}
