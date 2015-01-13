#define GBLBUF 100000
#define KEYBUF 256
typedef struct gbl_t {
	struct gbl_t *prev, *next;
	char *one, *two, **regex;
	int regexc;
} gbl;
