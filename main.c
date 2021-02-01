#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	unsigned char *data;
	long len;
} Buffer;

#define BUFFER  0
#define ADDRESS 1
#define ASCII   2

int is_printable(char ch) {
	return (ch > 0x20 && ch < 0x7f) ? 1 : 0;
}

Buffer* read_file(char *flname) 
{

	Buffer *buf = malloc(sizeof(Buffer));
	if (buf) {
		FILE *fileptr;

		fileptr = fopen(flname, "rb");        // Open the file in binary mode
		if (fileptr == NULL) {
			fprintf(stderr, "What the fuck\n");
			exit(1);
		}

		fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
		buf->len = ftell(fileptr);             // Get the current byte offset in the file
		rewind(fileptr);                      // Jump back to the beginning of the file

		buf->data = malloc(buf->len * sizeof(unsigned char)); // Enough memory for the file
		fread(buf->data, buf->len, 1, fileptr); // Read in the entire file
		fclose(fileptr); // Close the file
		return buf;
	} else {
		fprintf(stderr, "Can't allocate memory for the buffer");
		exit(1);
	}

}

void create_ltable(lua_State *L, Buffer *b, int type) {
	char ch;
	char str[12];
	lua_newtable(L);
	switch(type) {
	case BUFFER:
		for (int i = 1; i < b->len+1; i++) {
			lua_pushnumber(L, i);   				/* Push the table index */
			lua_pushinteger(L, b->data[i-1]); /* Push hex representation into the table */
			lua_rawset(L, -3);      				/* Stores the pair in the table */
		}
		lua_setglobal(L, "buf");
		break;
	case ADDRESS:
		for (int i = 1; i < (b->len / 0x10)+2; i++) {
			sprintf(str, "%08x:", (i-1) * 16);
			lua_pushnumber(L, i);
			lua_pushstring(L, str); /* Push hex representation into the table */
			lua_rawset(L, -3);      				/* Stores the pair in the table */
		}
		lua_setglobal(L, "address");
		break;
	case ASCII:
		for (int i = 1; i < b->len+1; i++) {
			ch = is_printable(b->data[i-1]) ? b->data[i-1] : '.';	
			lua_pushnumber(L, i);
			lua_pushnumber(L, ch);
			lua_rawset(L, -3);      				/* Stores the pair in the table */
		}

		lua_setglobal(L, "ascii");
		break;
	}
	return;
}


int main(int argc, char *argv[])
{
	// Initializing the file
	if (argc < 2) {
		fprintf(stderr, "Not enough files\n");
		exit(1);
	}

	Buffer* buf = read_file(argv[1]);

	// Initializing lua, opening script, needed libs, setting globals
	int i, status, result;
	lua_State *L;
	L = luaL_newstate();
	luaL_openlibs(L);
	status = luaL_loadfile(L, "hex.lua");
	if (status) {
		/* If something went wrong, error message is at the top of */
		/* the stack */
		fprintf(stderr, "Couldn't load file: %s\n", lua_tostring(L, -1));
		exit(1);
	}
	/* Creates the tables */
	create_ltable(L, buf, BUFFER);
	create_ltable(L, buf, ADDRESS);
	create_ltable(L, buf, ASCII);

	/* The filename */
	lua_pushstring(L, argv[1]);
	lua_setglobal(L, "fln");


	/* Ask Lua to run our little script */
	result = lua_pcall(L, 0, LUA_MULTRET, 0);
	if (result) {
		fprintf(stderr, "Failed to run script: %s\n", lua_tostring(L, -1));
		exit(1);
	}

	

	lua_close(L);
	return 0;
}
