/* be is a binary editor - hex editor */
#include <assert.h>
#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "be.h" 

static struct E* ge; /* Global configuration of the editor */
static FILE* SIGNATURES;

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
	write(STDOUT_FILENO, "\x1b[?1049h", 8);
}

void
term_state_restore() 
{
	write(STDOUT_FILENO, "\x1b[?1049l", 8);
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

	/* Some flags basically for echoing off and no break */
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
	/* Reset the terminal settings to the state before the program was started.*/
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
	/* Show us the cursor again */
	write(STDOUT_FILENO, "\x1b[?25h", 6);
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

int
read_key()
{
	char c;
	ssize_t nread;
	/* check == 0 to see if EOF.*/
	while ((nread = read(STDIN_FILENO, &c, 1)) == 0);
	if (nread == -1) {
		 /* This is when a signal comes in. It will interrupt the read */
		 /* and return -1. So return to the main loop */
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
buf_free(struct buffer* buf)
{
	free(buf->data);
	free(buf);
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
			perror("Unable to realloc buffer");
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
	char buffer[1024]; 

	va_list ap;
	va_start(ap, fmt);
	int len = vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	buf_append(buf, buffer, len);
	return len;
}


void
buf_draw(struct buffer* b) {
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
	e->flname     = NULL;
	e->data       = NULL;
	e->data_len   = 0;
	e->oct_offset = 16;
	e->grouping   = 2;
	e->cx         = 1;
	e->cy         = 1;
	e->ln         = 0;
	e->mode       = NORMAL_MODE;

	memset(e->status_msg, '\0', sizeof(e->status_msg));
	editor_statusmsg(e, "-- NORMAL --");

	memset(e->search_str, '\0', sizeof(e->search_str));

	get_term_size(&e->size[0], &e->size[1]);
	return e;
}

void
editor_readfile(struct E* e, char *flname)
{
	FILE *fp;

	e->flname = malloc(strlen(flname)+1);
	strncpy(e->flname, flname, strlen(flname));

	fp = fopen(e->flname, "rb");        /* Open the file in binary mode*/
	if (fp == NULL) {
		fprintf(stderr, "Error opening the file");
		exit(1);
	}

	fseek(fp, 0, SEEK_END);				/* Jump to the end of the file*/
	e->data_len = ftell(fp);			/* Get the current byte offset in the file*/
	rewind(fp);								/* Jump back to the beginning of the file*/
	e->data = malloc(e->data_len * sizeof(unsigned char)); /* Enough memory for the file */
	fread(e->data, e->data_len, 1, fp); /* Read in the entire file */
	editor_statusmsg(e, "%s (%d bytes)", e->flname, e->data_len);

	fclose(fp); /* Close the file */
}

void
editor_writefile(struct E* e)
{
	if (!e->dirty) {
		editor_statusmsg(e, "You haven't editted anything");
		return;
	}

	FILE *fp = fopen(e->flname, "wb");
	if (!fp) {
		fprintf(stderr, "Error writing to file"); /* TODO We should print at the status bar */
		return;
	}
	int bw = fwrite(e->data, sizeof(char), e->data_len, fp);
	if (bw < 0) {
		fprintf(stderr, "No bytes written to file");
		return;
	}
	editor_statusmsg(e, "Written %d bytes to %s", e->data_len, e->flname);
	/* TODO We should set the status message with bytes and filename saved */
	e->dirty = 0;
	fclose(fp);
}

void
editor_free(struct E* e)
{
	free(e->data);
	free(e->flname);
	free(e);
}

void
editor_refresh_loop(struct E* e)
{
	struct buffer* b = buf_create();
	buf_append(b, "\x1b[?25l", 6); /* hides cursor */
	buf_append(b, "\x1b[H", 3);    /* resets cursor */

	/* Cleans buffer and rerenders */
	if (e->mode & (NORMAL_MODE | INSERT_MODE | REPLACE_MODE | QUIT_DIRTY_MODE)) {
		editor_render(e, b);
		editor_render_status(e, b);
		editor_render_coords(e, b);
	}

	buf_draw(b);
	buf_free(b);
}

void
editor_render(struct E* e, struct buffer* b)
{
	if (e->data_len < 0) {
		fprintf(stderr, "There is nothing here, move along");
		return;
	}

	/* terminal dimensions */
	int screen_rows = e->size[0];
	int row_ch_count = 0; /* used for padding */

	/* the hex char string and its len */
	int hexlen = 0;
	char hex[32 + 1];

	 /* 
	 * We are calculating the start-end_offset of the current buffer_draw
	 * based on what
	 * 1. the octet offset is
	 * 2. which line we are in
	 * 3. how many bytes can the screen draw
	 */
	unsigned int start_offset = e->ln * e->oct_offset;
	int bytes_per_screen = screen_rows * e->oct_offset;

	long end_offset = bytes_per_screen + start_offset - e->oct_offset;
	if (end_offset > e->data_len) {
		end_offset = e->data_len;
	}

	unsigned int offset;
	int row = 0, col = 0;
	for (offset = start_offset; offset < end_offset; offset++) {
		unsigned char cur_byte = e->data[offset];
		/* print the address */
		if (offset % e->oct_offset == 0) {
			buf_appendf(b, "\x1b[1;36m%09x\x1b[0m:", offset);
			col = 0;
			row_ch_count = 0;
			row++;
		}

		col++;


		if (isprint(cur_byte)) {
			/* Every character that can be printed change its color to be more visible */
			hexlen = snprintf(hex, sizeof(hex), "\x1b[1;34m%02x", cur_byte);
		} else {
			/* Just write it with normal color */
			hexlen = snprintf(hex, sizeof(hex), "%02x", cur_byte);
		}

		/* space after the grouping variable for clear understanding */
		if (offset % e->grouping == 0) {
			buf_append(b, " ", 1);
			row_ch_count++;
		}

		/* Hex Cursor rendering. */
		if (e->cy == row) {
			/* Render the selected byte with a different color. */
			if (e->cx == col) {
				buf_append(b, "\x1b[7m", 4);
			}
	
		}

		/* Write the hex value of the byte at the current offset, and reset attributes. */
		buf_append(b, hex, hexlen);
		buf_append(b, "\x1b[0m", 4);

		row_ch_count +=2;

		/* If we reached the end of a 'row', start writing the ASCII equivalents. */
		if ((offset+1) % e->oct_offset == 0) {
			buf_append(b, "  ", 2);
			/* Calculate the 'start offset' of the ASCII part to write. Delegate */
			/* this to the render_ascii function. */
			int the_offset = offset + 1 - e->oct_offset;
			editor_render_asc(e, row, the_offset, b);
			/* New line and return */
			buf_append(b, "\r\n", 2);
		}
	}

	unsigned int leftovers = offset % e->oct_offset;
	if (leftovers > 0) {
		size_t pad_size = (e->oct_offset*2) + (e->oct_offset / e->grouping)-row_ch_count;
		char *padding = malloc((pad_size) * sizeof(char));
		memset(padding, ' ', pad_size);
		buf_append(b, padding, pad_size);
		buf_append(b, "  ", 2);
		editor_render_asc(e, row, offset-leftovers, b);
		free(padding); /* free f@@@@ up with malloc and cursor disappears*/ 
	} 
	buf_append(b, "\x1b[0K", 4);
}

void
editor_render_asc(struct E* e, int rown, unsigned int off, struct buffer* buf)
{

	int cc = 0;
	unsigned int offset1;
	for (offset1 = off; offset1 < off+e->oct_offset; offset1++) {
		if (offset1 >= e->data_len) {
			return;
		}
		cc++;
		unsigned char cur_byte = e->data[offset1];
		if (rown == e->cy && cc == e->cx) {
			/* Ascii cursor rendering */
			buf_append(buf, "\x1b[7m", 4);
		} else {
			buf_append(buf, "\x1b[0m", 4);
		}

		if (isprint(cur_byte)) {
			buf_appendf(buf, "\x1b[34m%c", cur_byte);
		} else {
			buf_appendf(buf, "\x1b[90m.");
		}
		/* Clear all formatting and the attributes after EOL */
	}
	buf_append(buf, "\x1b[0m\x1b[K", 7);
}

void
editor_render_status(struct E* e, struct buffer* b)
{ 
	/* Reset, drop down, clear */
	buf_appendf(b, "\x1b[%dH\x1b[J", e->size[0]);
	/* Write status message */
	/* Filename, and File size */
	buf_appendf(b, "\x1b[0m %s", e->status_msg);
}

void
editor_render_coords(struct E* e, struct buffer* b)
{
	char coords[100];
	
	unsigned int offset  = editor_offset_at_cursor(e);
	float percent        = (float)offset / (e->data_len) * 100; 
	unsigned char val    = e->data[offset];
	int len = snprintf(coords, sizeof(coords), "%09x,%d (%02x) (%.f%%)", offset, offset, val, percent);
	
	buf_appendf(b, "\x1b[0m\x1b[%d;%dH", e->size[0], e->size[1]-len);
	buf_append(b, coords, len); 
}

int
editor_statusmsg(struct E* e, const char *fmt, ...) {

	va_list ap;
	va_start(ap, fmt);
	int len = vsnprintf(e->status_msg, sizeof(e->status_msg), fmt, ap);
	va_end(ap);

	return len;
}

void
editor_setmode(struct E* e, enum e_mode mode)
{
	e->mode = mode;
	switch (e->mode) {
	case NORMAL_MODE:		   editor_statusmsg(e, "- NORMAL -"); break;
	case REPLACE_MODE:		   editor_statusmsg(e, "- REPLACE -"); break;
	case INSERT_MODE:		   editor_statusmsg(e, "- INSERT -"); break;
	case CMD_MODE:			   editor_statusmsg(e, ""); break;
	case SEARCH_MODE:		   editor_statusmsg(e, "~> "); break;
	case QUIT_DIRTY_MODE:	   editor_statusmsg(e, "You have unsaved changes. Do you wish to quit? y/n "); break;
	case QUIT_MODE:	   		   editor_statusmsg(e, "You quitter!"); break;
	}
}

void
editor_replace_b(struct E* e, char c)
{
	/* Backspace */
	unsigned int offset = editor_offset_at_cursor(e);
	if (c == 0x7F) {
		editor_mv_cursor(e, LEFT, 1);
		e->data[offset] = 0;
	/* Everything else */
	} else {
		editor_mv_cursor(e, RIGHT, 1);
		e->data[offset] = c;
	}
	e->dirty = 1;
}

void
editor_incr_b(struct E* e, int amount)
{
	int offset = editor_offset_at_cursor(e);
	char prev = e->data[offset];
	e->data[offset] += amount;
}


void
editor_keypress(struct E* e)
{
	if (e->mode & QUIT_DIRTY_MODE) {
		int c = read_key();
		if (c == 'y' || c == 'Y') {
			exit(0);
		}
		editor_setmode(e, NORMAL_MODE);

		return;
	}
	if (e->mode & QUIT_MODE) {

		exit(0);
	}

	if (e->mode & REPLACE_MODE) {
		int c = read_key();
		if (c == ESC) {
			editor_setmode(e, NORMAL_MODE);
			return;
		}
		editor_replace_b(e, c);
		return;
	}
	if (e->mode & INSERT_MODE) {
		int c = read_key();
		if (c == ESC) {
			editor_setmode(e, NORMAL_MODE);
			return;
		}
		/* TODO */
		/* editor_insert_b(e, c); */
		return;
		
	}

	/* TODO */
	if (e->mode & SEARCH_MODE) {
		int c = read_key();
		if (c == ESC) {
			editor_setmode(e, NORMAL_MODE);
			return;
		}
	}

	int k = read_key();
	if (k == -1) {
		return;
	}

	switch (k) { 
		case 'q':
			if (e->dirty) {
				editor_setmode(e, QUIT_DIRTY_MODE); return;
			} else {
				editor_setmode(e, QUIT_MODE); return;
			}
	case ESC: editor_setmode(e, NORMAL_MODE); return; 
	case CTRL_S: editor_writefile(e); return;
	} 

	if (e->mode & NORMAL_MODE) {
		switch (k) {
		/* Vim-like bindings */
		case 'j': editor_mv_cursor(e, DOWN, 1); break;
		case 'k': editor_mv_cursor(e, UP, 1); break;
		case 'h': editor_mv_cursor(e, LEFT, 1); break;
		case 'l': editor_mv_cursor(e, RIGHT, 1); break;
		case 'w': editor_mv_cursor(e, RIGHT, 2); break;
		case 'b': editor_mv_cursor(e, LEFT, 2); break;

		/* Moves at the end of the file */
		case 'G': 
			editor_scroll(e, e->data_len);
			editor_cursor_at_offset(e, e->data_len-1, &(e->cx), &(e->cy));
			break;
		
		/* Moves at the begging of the file */
		case 'g': 
			k = read_key();
			if (k == 'g') {
				e->ln = 0;
				editor_cursor_at_offset(e, 0, &(e->cx), &(e->cy));
				break;
			}
			break;
		/* Modes */
		case 'r': editor_setmode(e, REPLACE_MODE); return;
		case ':': editor_setmode(e, CMD_MODE);     return;
		case '/': editor_setmode(e, SEARCH_MODE);  return;
		case 'i': editor_setmode(e, INSERT_MODE);  return;

		/* Incrementing byte at cursor's position */
		case ']': editor_incr_b(e, 1);  break;
		case '[': editor_incr_b(e, -1); break;

		/* Scrolling */
		case CTRL_D: editor_scroll(e, (e->size[0] - 2));  break;
		case CTRL_U: editor_scroll(e, -(e->size[0] - 2)); break;
		}
	}
}

void
editor_mv_cursor(struct E* e, int dir, int amount)
{
	switch (dir) {
	case UP:    e->cy-=amount; break;
	case DOWN:  e->cy+=amount; break;
	case LEFT:  e->cx-=amount; break;
	case RIGHT: e->cx+=amount; break;
	}
	/* 
	 * check if cursor should wrap up a line
	 */
	if (e->cx < 1) {
		if (e->cy >= 1) {
			e->cy--;
			e->cx = e->oct_offset;
		}
	} else if (e->cx > e->oct_offset) {
		e->cy++;
		e->cx = 1;
	}

	/*
	 * Are we at the top of the file
	 * If so bind cx, cy to 1
	 */
	if (e->cy <= 0 && e->ln <=0) {
		e->cy = 1;
		e->cx = 1;
	}

	/*
	 * Are we trying to scroll because we hit the bottom/top
	 * of the page, then scroll down/up
	 */
	if (e->cy >= e->size[0]) {
		e->cy--;
		editor_scroll(e, 1);
	} else if (e->cy < 1 && e->ln > 0) {
		e->cy++;
		editor_scroll(e, -1);
	}


	/*
	 * Are we at the end of the file?
	 * position cursor at the last byte
	 */
	unsigned int offset = editor_offset_at_cursor(e);
	unsigned int end = e->data_len - 1;
	if (offset >= end) {
		editor_cursor_at_offset(e, end, &(e->cx), &(e->cy));
	}
	
}

unsigned int
editor_offset_at_cursor(struct E* e)
{
	unsigned int offset = (e->cy - 1 + e->ln) * e->oct_offset + (e->cx - 1);

	if (offset <= 0)
		return 0;
	if (offset >= e->data_len)
		return e->data_len - 1;

	return offset;
}

void
editor_cursor_at_offset(struct E* e, int offset, int *x, int *y)
{
	*x = offset % e->oct_offset + 1;
	*y = offset / e->oct_offset - e->ln + 1;
}

void
editor_scroll(struct E* e, int amount)
{
	e->ln += amount;
	int limit = (e->data_len / e->oct_offset) - (e->size[0] - 2);
	if (e->ln >= limit)
		e->ln = limit;

	if (e->ln <= 0)
		e->ln = 0;

}

void
editor_exit()
{
	editor_free(ge);
	clear_screen();
	disable_raw_mode();
	term_state_restore();
}

void
term_resize() {
	clear_screen();
	get_term_size(&(ge->size[0]), &(ge->size[1]));
}


/* File signature detection */
char *
term_file_sig_detect(struct E* e, char* header) {


}


/* Entry */
int
main(int argc, char *argv[])
{
	/* Initializing the file*/
	if (argc < 2) {
		fprintf(stderr, "Not enough files\n");
		exit(1);
	}


	/* If window changes dimension resize automatically */
	struct sigaction act;
	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = term_resize;
	sigaction(SIGWINCH, &act, NULL);

	ge = editor_create();
	editor_readfile(ge, argv[1]);

	term_state_save();
	enable_raw_mode();
	/* Callback to clean things up */
	atexit(editor_exit); /* Cleaning up after exit */ 


	clear_screen();

	/* Open signatures file reads header, prints to status screen */
	SIGNATURES = fopen("signatures.txt", "r");
	term_file_sig_detect(ge, SIGNATURES);
	
	/* Main loop */
	for (;;) {
		editor_refresh_loop(ge);
		editor_keypress(ge);
	}
}
