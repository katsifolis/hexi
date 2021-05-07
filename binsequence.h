#define NUM_OF_TYPES 10
typedef struct {
	int  type;
	char* operand;
}Operands;

typedef struct {
	char* mnemonic;
	Operands* operands;
}Instruction;

typedef struct {


} BB;

Instruction* new_instruction();
// Algorith 1: Compare two instructions
int comp_ins(Instruction*, Instruction*);
int num_of_operands(char*);
