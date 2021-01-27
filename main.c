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


Buffer* read_file(Buffer *buf, char *flname) 
{

	FILE *fileptr;
	buf->len = 1;

	fileptr = fopen(flname, "rb");        // Open the file in binary mode
	if (fileptr == NULL) {
		fprintf(stderr, "What the fuck");
		exit(1);
	}

	fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
	buf->len = ftell(fileptr);             // Get the current byte offset in the file
	rewind(fileptr);                      // Jump back to the beginning of the file

	buf->data = (unsigned char*)malloc(buf->len * sizeof(unsigned char)); // Enough memory for the file
	fread(buf->data, buf->len, 1, fileptr); // Read in the entire file
	fclose(fileptr); // Close the file
	return buf;

}



int is_printable(char ch) {
	return (ch > 0x20 && ch < 0xf7) ? 1 : 0;
}


int main(int argc, char *argv[])
{
	// Initializing the file
	if (argc < 2) {
		fprintf(stderr, "Not enough files");
		exit(1);
	}

	Buffer buff;
	Buffer* buf = read_file(&buff, argv[1]);


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


	lua_newtable(L);
	for (int i = 1; i < buf->len; i++) {
		lua_pushnumber(L, i);   				/* Push the table index */
		lua_pushinteger(L, buf->data[i-1]); /* Push hex representation into the table */
		lua_rawset(L, -3);      				/* Stores the pair in the table */
	}

	lua_setglobal(L, "buf");

	lua_newtable(L);
	char str[12];
	for (int i = 1; i < buf->len / 0x10; i++) {
		sprintf(str, "%08x: ", i * 16);
		lua_pushnumber(L, i);
		lua_pushstring(L, str); /* Push hex representation into the table */
		lua_rawset(L, -3);      				/* Stores the pair in the table */
	}
	lua_setglobal(L, "address");

	lua_newtable(L);

	char ch;
	for (int i = 1; i < buf->len; i++) {
		ch = is_printable(buf->data[i-1]) ? buf->data[i-1] : '.';	
		lua_pushnumber(L, i);
		lua_pushnumber(L, ch);
		lua_rawset(L, -3);      				/* Stores the pair in the table */
	}

	lua_setglobal(L, "ascii");


	/* Ask Lua to run our little script */
	result = lua_pcall(L, 0, LUA_MULTRET, 0);
	if (result) {
		fprintf(stderr, "Failed to run script: %s\n", lua_tostring(L, -1));
		exit(1);
	}

	lua_close(L);

	return 0;
}
