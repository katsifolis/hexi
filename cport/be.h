struct buffer {
	unsigned char *data;
	long len;
	long cap;
};

struct E {
	char* flname;       /* Filename */
	char* data;         /* Data from file */
	char* s_buffer[20]; /* search or commmand buffer */
	long data_len;      /* buffer length */
	int size[2];        /* Size of the terminal */
	int cx,cy;          /* cursor x, y */
	int oct_offset;     /* octet offset */
	int ln;           /* current line cursor */
	int grouping;       /* grouping of data */
};

static struct termios orig_termios;

enum k_codes {
	CTRL_D = 0x04,
	CTRL_H = 0x08,
	CTRL_Q = 0x11, /* DC1, to exit the program.*/
	CTRL_R = 0x12, /* DC2, to redo an action.*/
	CTRL_S = 0x13, /* DC3, to save the current buffer.*/
	CTRL_U = 0x15,
	ENTER = 0x0d,
	ESC = 0x1b,
	BACKSPACE = 0x7f,
	/* virtual returns not corresponding to any true value */
	UP = 1000,      /* [A */
	DOWN,           /* [B */
	RIGHT,          /* [C */
	LEFT,           /* [D */
	DEL,            /* . = 1b, [ = 5b, 3 = 33, ~ = 7e, */
	HOME,           /* [H */
	END,            /* [F */
	PAGEUP,         /* ?? */
	PAGEDOWN,       /* ?? */
};


/* Buffer routines */
struct buffer* buf_create();
void buf_append(struct buffer*, const char* what, size_t l);
int buf_appendf(struct buffer*, const char* fmt, ...);
void buf_draw(struct buffer*);
/* Editor routines */
struct E* editor_create();
void editor_free(struct E*);
void editor_render(struct E*);
void editor_exit();
void editor_readfile(struct E*, char*);
void editor_keypress(struct E*);
/* util routines */
int get_term_size(int*, int*);
void clear_screen();
void disable_raw_mode();
void enable_raw_mode();
void term_state_restore();
void term_state_save();
