/* be is a binary editor - hex editor */
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "be.h" 

/* utils */

static struct E* ge;

int
is_printable(char ch) 
{
	return (ch > 0x20 && ch < 0x7f) ? 1 : 0;
}

int
get_term_size(int* x, int* y)
{
	struct winsize w;
	ioctl(0, TIOCGWINSZ, &w);
	*x = w.ws_row; *y = w.ws_col;
	return 1;
}

void
term_state_save()
{
	(void) (write(STDOUT_FILENO, "\x1b[?1049h", 8) + 1);
}

void
term_state_restore() 
{
	(void) (write(STDOUT_FILENO, "\x1b[?1049l", 8) + 1);
}

void
enable_raw_mode()
{
	/* only enable raw mode when STDIN_FILENO is a tty.*/
	if (!isatty(STDOUT_FILENO)) {
		perror("Input is not a TTY");
		exit(1);
	}

	tcgetattr(STDOUT_FILENO, &orig_termios);

	struct termios raw = orig_termios;
	/* input modes: no break, no CR to NL, no parity check, no strip char,*/
	/* no start/stop output control.*/
	raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
	/* output modes - disable post processing*/
	raw.c_oflag &= ~(OPOST);
	/* control modes - set 8 bit chars*/
	raw.c_cflag |= (CS8);
	/* local modes - echoing off, canonical off, no extended functions,*/
	/* no signal chars (^Z,^C)*/
	raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
	/* control chars - set return condition: min number of bytes and timer.*/
	/* Return each byte, or zero for timeout.*/
	raw.c_cc[VMIN] = 0;
	/* 100 ms timeout (unit is tens of second). Do not set this to 0 for*/
	/* whatever reason, because this will skyrocket the cpu usage to 100%!*/
	raw.c_cc[VTIME] = 1;

	/* put terminal in raw mode after flushing*/
	if (tcsetattr(STDOUT_FILENO, TCSAFLUSH, &raw) != 0) {
		perror("Unable to set terminal to raw mode");
		exit(1);
	}
}

void
disable_raw_mode()
{
	/* Reset the terminal settings to the state before hx was started.*/
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
	/* Also, emit a ^[?25h sequence to show the cursor again. The void*/
	/* construct (with the + 1) is to squelch GCC warnings about unused*/
	/* return values.*/
	(void) (write(STDOUT_FILENO, "\x1b[?25h", 6) + 1);
}


void
clear_screen()
{
	/* clear the colors, move the cursor up-left, clear the screen.*/
	char stuff[80];
	int bw = snprintf(stuff, 80, "\x1b[0m\x1b[H\x1b[2J");
	if (write(STDOUT_FILENO, stuff, bw) == -1) {
		perror("Unable to clear screen");
	}
}


/* Reads keypresses from STDIN_FILENO, and processes them accordingly. Escape sequences
 * will be read properly as well (e.g. DEL will be the bytes 0x1b, 0x5b, 0x33, 0x7e).
 * The returned integer will contain the key pressed.
 *
 * read_key() returns -1 if it fails.
 */
int
read_key()
{
	char c;
	ssize_t nread;
	/* check == 0 to see if EOF.*/
	while ((nread = read(STDIN_FILENO, &c, 1)) == 0);
	if (nread == -1) {
		/* When the read call is interrupted by a signal (such as SIGWINCH), the*/
		/* nread will be -1. In that case, just return -1 prematurely and continue*/
		/* the main loop.*/
		return -1;
	}

	char seq[4]; /* escape sequence buffer.*/

	switch (c) {
		case BACKSPACE:
		case CTRL_H:
			return BACKSPACE;
		case ESC:
			/* Escape key was pressed, OR things like delete, arrow keys, ...*/
			/* So we will try to read ahead a few bytes, and see if there's more.*/
			/* For instance, a single Escape key only produces a single 0x1b char.*/
			/* A delete key produces 0x1b 0x5b 0x33 0x7e.*/
			if (read(STDIN_FILENO, seq, 1) == 0) {
				return ESC; /* Escape ascii*/
			}
			if (read(STDIN_FILENO, seq + 1, 1) == 0) {
				return ESC;
			}

			/* home = 0x1b, [ = 0x5b, 1 = 0x31, ~ = 0x7e,*/
			/* end  = 0x1b, [ = 0x5b, 4 = 0x34, ~ = 0x7e,*/
			/* pageup   1b, [=5b, 5=35, ~=7e,*/
			/* pagedown 1b, [=5b, 6=36, ~=7e,*/

			if (seq[0] == '[') {
				if (seq[1] >= '0' && seq[1] <= '9') {
					if (read(STDIN_FILENO, seq + 2, 1) == 0) {
						return ESC;
					}
					if (seq[2] == '~') {
						switch (seq[1]) {
							case '1': return HOME;
							case '3': return DEL;
							case '4': return END;
							case '5': return PAGEUP;
							case '6': return PAGEDOWN;
										 /* TODO: with rxvt-unicode, ^[[7~ and ^[[8~ seem to be*/
										 /* emitted when the home/end key are pressed. We can*/
										 /* currently mitigate it like this.*/
							case '7': return HOME;
							case '8': return END;
						}
					}
				}
				switch (seq[1]) {
					case 'A': return UP;
					case 'B': return DOWN;
					case 'C': return RIGHT;
					case 'D': return LEFT;
					case 'H': return HOME; /* does not work with me?*/
					case 'F': return END;  /* ... same?*/
				}
			} else if (seq[0] == 'O') {
				/* Some terminal emulators emit ^[[O sequences for HOME/END,*/
				/* such as xfce4-terminal.*/
				switch (seq[1]) {
					case 'H': return HOME;
					case 'F': return END;
				}
			}
	}

	return c;
}

/* Buffer routines */

struct buffer*
buf_create() 
{
	struct buffer *buf = malloc(sizeof(struct buffer));
	if (buf) {
		buf->len = 0;
		buf->cap = 0;
		buf->data = NULL;
		return buf;
	}
	else {
		fprintf(stderr, "Can't allocate memory for the buffer");
		exit(1);
	}
}

void
buf_append(struct buffer* buf, const char* what, size_t len)
{
	/* Prevent reallocing a lot by using some sort of geometric progression */
	/* by increasing the cap with len, then doubling it. */
	if ((int)(buf->len + len) >= buf->cap) {
		buf->cap += len;
		buf->cap *= 2;
		/* reallocate with twice the capacity*/
		buf->data = realloc(buf->data, buf->cap);
		if (buf->data == NULL) {
			perror("Unable to realloc charbuf");
			exit(1);
		}
	}

	/* copy 'what' to the target memory*/
	memcpy(buf->data+buf->len, what, len);
	buf->len += len;
}

int
buf_appendf(struct buffer* buf, const char* fmt, ...)
{
	/* small buffer for whole fmt */
	char buffer[20]; 

	va_list ap;
	va_start(ap, fmt);
	int len = vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	buf_append(buf, buffer, len);
	return len;
}


void buf_draw(struct buffer* b) {
	if(write(STDOUT_FILENO, b->data, b->len) == -1) {
		fprintf(stderr, "Can't write buffer data");
		exit(1);
	}
}

/* Editor routines */
struct E*
editor_create()
{
	struct E* e = malloc(sizeof(struct E));
	e->flname     = malloc(0);
	e->data       = malloc(0);
	memset(e->s_buffer, 0, 20);
	e->data_len   = 0;
	e->oct_offset = 16;
	e->grouping   = 2;
	e->cx         = 0;
   e->cy         = 0;
	e->ln = 0;
	get_term_size(&e->size[0], &e->size[2]);
	return e;
}

void
editor_readfile(struct E* e, char *flname)
{
	FILE *fileptr;
	e->flname = flname; /* copying the filename */

	fileptr = fopen(flname, "rb");        /* Open the file in binary mode*/
	if (fileptr == NULL) {
		fprintf(stderr, "Error opening the file");
		exit(1);
	}

	fseek(fileptr, 0, SEEK_END);          /* Jump to the end of the file*/
	e->data_len = ftell(fileptr);             /* Get the current byte offset in the file*/
	rewind(fileptr);                      /* Jump back to the beginning of the file*/
	e->data = malloc(e->data_len * sizeof(unsigned char)); /* Enough memory for the file*/
	fread(e->data, e->data_len, 1, fileptr); /* Read in the entire file*/

	fclose(fileptr); /* Close the file*/
}

void
editor_free(struct E* e)
{
	free(e->data);
	free(e);
}

void
editor_render(struct E* e)
{
	struct buffer* b = buf_create();
	if (e->data_len < 0) {
		buf_appendf(b, "There is nothing here");
		return;
	}

	unsigned int start_offset = e->ln * e->oct_offset;

	int end_offset = e->size[0];
	int cols = e->size[1];
	int offset = 0;
	buf_append(b, "\x1b[?25l", 6); /* hides cursor */
	buf_append(b, "\x1b[H", 3);    /* resets cursor */
	
	for (offset = start_offset; offset < end_offset; offset++) {
		buf_appendf(b, "\x1b[1;35m%09x\x1b[0m: \r\n", offset);
	}

	buf_append(b, "\x1b[?25h", 6); /* hides cursor */
	buf_draw(b);
}

void
editor_keypress(struct E* e)
{
}

void
editor_exit()
{
	editor_free(ge);
	clear_screen();
	disable_raw_mode();
	term_state_restore();
}

/* Entry */
main(int argc, char *argv[])
{
	/* Initializing the file*/
	if (argc < 2) {
		fprintf(stderr, "Not enough files\n");
		exit(1);
	}

	ge = editor_create();
	editor_readfile(ge, argv[1]);
	printf("%d\n", ge->size[0]);
	sleep(1);

	term_state_save();
	enable_raw_mode();
	atexit(editor_exit); /* Cleaning up after exit */ 
	clear_screen();
	
	for (;;) {
		editor_render(ge);
		if (read_key() == 'q') {
			exit(1);
		}
	}
}
