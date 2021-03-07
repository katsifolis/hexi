struct buffer {
	unsigned char *data;
	long          len;
	long          cap;
};

/* bit flag mode for the editor */
enum e_mode {
	INSERT_MODE    = 1 << 0,
	NORMAL_MODE  = 1 << 1,
	REPLACE_MODE = 1 << 2,
	CMD_MODE     = 1 << 3,
	SEARCH_MODE  = 1 << 4,
};


struct E {
	char*        flname;          /* Filename */
	char*        data;            /* Data from file */
	char         status_msg[256]; /* Buffer for custom strings */
	char         search_str[20];  /* Search string buffer */
	long         data_len;        /* buffer length */
	int          size[2];         /* Size of the terminal */
	int          cx,cy;           /* cursor x, y */
	int          oct_offset;      /* octet offset */
	int          ln;              /* current line cursor */
	int          grouping;        /* grouping of data */
	int          dirty;           /* is it modified */
	enum e_mode  mode;
};

static struct termios orig_termios;

enum k_codes {
	CTRL_D    = 0x04,
	CTRL_H    = 0x08,
	CTRL_Q    = 0x11, /* DC1, to exit the program.*/
	CTRL_R    = 0x12, /* DC2, to redo an action.*/
	CTRL_S    = 0x13, /* DC3, to save the current buffer.*/
	CTRL_U    = 0x15,
	ENTER     = 0x0d,
	ESC       = 0x1b,
	BACKSPACE = 0x7f,
	/* virtual returns not corresponding to any true value */
	UP        = 1000,      /* [A */
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
void           buf_free(struct buffer*);
void           buf_append(struct buffer*, const char*, size_t);
int            buf_appendf(struct buffer*, const char*, ...);
void           buf_draw(struct buffer*);
/* Editor routines */
struct E*      editor_create();
void           editor_refresh_loop(struct E*);
void           editor_free(struct E*);
void           editor_render(struct E*, struct buffer*);
void           editor_render_asc(struct E*, int, unsigned int, struct buffer*);
void           editor_render_status(struct E*, struct buffer*);
void           editor_render_coords(struct E*, struct buffer*);
/*
* Indication of each mode will be drawn for us in the status bar with a switch statement.
*/
int            editor_statusmsg(struct E*, const char*, ...);
void           editor_setmode(struct E*, enum e_mode);
void           editor_replace_b(struct E*, char);
void           editor_incr_b(struct E*, int);
void           editor_insert_b(struct E*, char);
void           editor_exit();
void           editor_writefile(struct E*);
void           editor_readfile(struct E*, char*);
void           editor_keypress(struct E*);
void           editor_mv_cursor(struct E*, int, int);
unsigned int   editor_offset_at_cursor(struct E*);
void           editor_cursor_at_offset(struct E*, int, int*, int*);
void           editor_scroll(struct E*, int);
/* util routines */
int            get_term_size(int*, int*);
void           clear_screen();
void           disable_raw_mode();
void           enable_raw_mode();
void           term_state_restore();
void           term_state_save();
void           term_resize();
