#include "all.h"

enum {
	SecText,
	SecData,
	SecBss,
};

void
emitlnk(char *n, Lnk *l, int s, FILE *f)
{
	static char *sec[2][3] = {
		[0][SecText] = ".text",
		[0][SecData] = ".data",
		[0][SecBss] = ".bss",
		[1][SecText] = ".abort \"unreachable\"",
		[1][SecData] = ".section .tdata,\"awT\"",
		[1][SecBss] = ".section .tbss,\"awT\"",
	};
	char *pfx, *sfx;

	pfx = n[0] == '"' ? "" : T.assym;
	sfx = "";
	if (T.windows && l->thread)
		die("thread-local storage is not supported on windows targets");
	if (T.apple && l->thread) {
		l->sec = "__DATA";
		l->secf = "__thread_data,thread_local_regular";
		sfx = "$tlv$init";
		fputs(
			".section __DATA,__thread_vars,"
			"thread_local_variables\n",
			f
		);
		fprintf(f, "%s%s:\n", pfx, n);
		fprintf(f,
			"\t.quad __tlv_bootstrap\n"
			"\t.quad 0\n"
			"\t.quad %s%s%s\n\n",
			pfx, n, sfx
		);
	}
	if (l->sec) {
		fprintf(f, ".section %s", l->sec);
		if (l->secf)
			fprintf(f, ",%s", l->secf);
	} else
		fputs(sec[l->thread != 0][s], f);
	fputc('\n', f);
	if (l->align)
		fprintf(f, ".balign %d\n", l->align);
	if (l->export)
		fprintf(f, ".globl %s%s\n", pfx, n);
	fprintf(f, "%s%s%s:\n", pfx, n, sfx);
}

static void emitdbgfnstart(char *, FILE *);

void
emitfnlnk(char *n, Lnk *l, FILE *f)
{
	emitlnk(n, l, SecText, f);
	emitdbgfnstart(n, f);
}

void
emitdat(Dat *d, FILE *f)
{
	static struct {
		char decl[8];
		int64_t mask;
	} di[] = {
		[DB] = {"\t.byte", 0xffL},
		[DH] = {"\t.short", 0xffffL},
		[DW] = {"\t.int", 0xffffffffL},
		[DL] = {"\t.quad", -1L},
	};
	static int64_t zero;
	char *p;

	switch (d->type) {
	case DStart:
		zero = 0;
		break;
	case DEnd:
		if (d->lnk->common) {
			int lg;
			if (zero == -1)
				die("invalid common data definition");
			p = d->name[0] == '"' ? "" : T.assym;
			fprintf(f, ".comm %s%s,%"PRId64,
				p, d->name, zero);
			if (d->lnk->align) {
				if (T.windows) {
					/* COFF takes a log2 alignment and
					 * refuses values above 32 bytes */
					for (lg=0; (1<<lg) < d->lnk->align && lg < 5; lg++)
						;
					fprintf(f, ",%d", lg);
				} else
					fprintf(f, ",%d", d->lnk->align);
			}
			fputc('\n', f);
		}
		else if (zero != -1) {
			emitlnk(d->name, d->lnk, SecBss, f);
			fprintf(f, "\t.fill %"PRId64",1,0\n", zero);
		}
		break;
	case DZ:
		if (zero != -1)
			zero += d->u.num;
		else
			fprintf(f, "\t.fill %"PRId64",1,0\n", d->u.num);
		break;
	default:
		if (zero != -1) {
			emitlnk(d->name, d->lnk, SecData, f);
			if (zero > 0)
				fprintf(f, "\t.fill %"PRId64",1,0\n", zero);
			zero = -1;
		}
		if (d->isstr) {
			if (d->type != DB)
				err("strings only supported for 'b' currently");
			fprintf(f, "\t.ascii %s\n", d->u.str);
		}
		else if (d->isref) {
			p = d->u.ref.name[0] == '"' ? "" : T.assym;
			fprintf(f, "%s %s%s%+"PRId64"\n",
				di[d->type].decl, p, d->u.ref.name,
				d->u.ref.off);
		}
		else {
			fprintf(f, "%s %"PRId64"\n",
				di[d->type].decl,
				d->u.num & di[d->type].mask);
		}
		break;
	}
}

typedef struct Asmbits Asmbits;

struct Asmbits {
	bits n;
	int size;
	Asmbits *link;
};

static Asmbits *stash;

int
stashbits(bits n, int size)
{
	Asmbits **pb, *b;
	int i;

	assert(size == 4 || size == 8 || size == 16);
	for (pb=&stash, i=0; (b=*pb); pb=&b->link, i++)
		if (size <= b->size && b->n == n)
			return i;
	b = emalloc(sizeof *b);
	b->n = n;
	b->size = size;
	b->link = 0;
	*pb = b;
	return i;
}

static void
emitfin(FILE *f, char *sec[3])
{
	Asmbits *b;
	int lg, i;
	union { int32_t i; float f; } u;
	union { int64_t i; double f; } uu;

	if (!stash)
		return;
	fprintf(f, "/* floating point constants */\n");
	for (lg=4; lg>=2; lg--)
		for (b=stash, i=0; b; b=b->link, i++) {
			if (b->size == (1<<lg)) {
				fprintf(f,
					".section %s\n"
					".p2align %d\n"
					"%sfp%d:",
					sec[lg-2], lg, T.asloc, i
				);
				if (lg == 4)
					fprintf(f,
						"\n\t.quad %"PRId64
						"\n\t.quad 0\n\n",
						(int64_t)b->n);
				else if (lg == 3) {
					uu.i = b->n;
					fprintf(f,
						"\n\t.quad %"PRId64
						" /* %f */\n\n",
						uu.i, uu.f);
				} else if (lg == 2) {
					u.i = b->n;
					fprintf(f,
						"\n\t.int %"PRId32
						" /* %f */\n\n",
						u.i, (double)u.f);
				}
			}
		}
	while ((b=stash)) {
		stash = b->link;
		free(b);
	}
}

void
elf_emitfin(FILE *f)
{
	static char *sec[3] = { ".rodata", ".rodata", ".rodata" };

	emitfin(f ,sec);
	fprintf(f, ".section .note.GNU-stack,\"\",@progbits\n");
}

void
elf_emitfnfin(char *fn, FILE *f)
{
	fprintf(f, ".type %s, @function\n", fn);
	fprintf(f, ".size %s, .-%s\n", fn, fn);
}

void
macho_emitfin(FILE *f)
{
	static char *sec[3] = {
		"__TEXT,__literal4,4byte_literals",
		"__TEXT,__literal8,8byte_literals",
		"__TEXT,__literal16,16byte_literals",
	};

	emitfin(f, sec);
}

void
pe_emitfin(FILE *f)
{
	static char *sec[3] = { ".rdata", ".rdata", ".rdata" };

	emitfin(f, sec);
}

static uint32_t *file;
static char **files;
static uint nfile;
static uint curfile;

typedef struct DbgLine DbgLine;
typedef struct DbgFn DbgFn;

struct DbgLine {
	uint fn;
	uint label;
	uint file;
	uint line;
};

struct DbgFn {
	char *name;
	uint start;
	uint end;
	uint file;
	char hasline;
};

static DbgLine *dlines;
static uint ndline;
static DbgFn *dfns;
static uint ndfn;
static uint curfn;
static uint nlabel;

static char *
dbgstrdup(char *s)
{
	char *r;

	r = emalloc(strlen(s) + 1);
	strcpy(r, s);
	return r;
}

static char *
dbgunquote(char *s)
{
	char *r, *p;
	size_t i, n;

	n = strlen(s);
	if (n >= 2 && s[0] == '"' && s[n-1] == '"') {
		s++;
		n -= 2;
	}
	r = emalloc(n + 1);
	p = r;
	for (i=0; i<n; i++) {
		if (s[i] == '\\' && i+1 < n
		&& (s[i+1] == '\\' || s[i+1] == '"'))
			i++;
		*p++ = s[i];
	}
	*p = 0;
	return r;
}

static uint
dbglabel(void)
{
	return nlabel++;
}

static void
dbgsec(FILE *f, char *elf, char *macho)
{
	if (T.apple)
		fprintf(f, ".section __DWARF,%s,regular,debug\n", macho);
	else
		fprintf(f, ".section %s,\"\",@progbits\n", elf);
}

static void
dbguleb(FILE *f, uint v)
{
	fprintf(f, "\t.uleb128 %u\n", v);
}

static void
dbgsleb(FILE *f, int v)
{
	fprintf(f, "\t.sleb128 %d\n", v);
}

static void
dbgref(FILE *f, char *kind, uint id)
{
	fprintf(f, "\t.quad %s%s%u\n", T.asloc, kind, id);
}

static void
dbgsetaddr(FILE *f, char *kind, uint id)
{
	fprintf(f, "\t.byte 0\n");
	fprintf(f, "\t.uleb128 9\n");
	fprintf(f, "\t.byte 2\n");
	dbgref(f, kind, id);
}

void
emitdbgfile(char *fn, FILE *f)
{
	uint32_t id;
	uint n;

	id = intern(fn);
	for (n=0; n<nfile; n++)
		if (file[n] == id) {
			/* gas requires positive
			 * file numbers */
			curfile = n + 1;
			return;
		}
	if (!file)
		file = vnew(0, sizeof *file, PHeap);
	if (!files)
		files = vnew(0, sizeof *files, PHeap);
	vgrow(&file, nfile + 1);
	vgrow(&files, nfile + 1);
	file[nfile] = id;
	files[nfile] = dbgunquote(fn);
	nfile++;
	curfile = nfile;
	if (!emitdbg)
		fprintf(f, ".file %u %s\n", curfile, fn);
	else if (T.windows)
		fprintf(f, "\t.cv_file %u %s\n", curfile, fn);
}

void
emitdbgloc(uint line, uint col, FILE *f)
{
	uint fid, lab;
	DbgLine *d;

	if (!emitdbg) {
		if (col != 0)
			fprintf(f, "\t.loc %u %u %u\n", curfile, line, col);
		else
			fprintf(f, "\t.loc %u %u\n", curfile, line);
		return;
	}

	if (T.windows) {
		if (curfile == 0)
			return;
		fprintf(f, "\t.cv_loc %u %u %u", curfn, curfile, line);
		if (col != 0)
			fprintf(f, " %u", col);
		fputc('\n', f);
		if (curfn < ndfn)
			dfns[curfn].hasline = 1;
		return;
	}

	fid = curfile;
	if (fid == 0)
		fid = nfile != 0;
	if (fid == 0)
		return;
	lab = dbglabel();
	fprintf(f, "\t%sdbgline%u:\n", T.asloc, lab);
	if (!dlines)
		dlines = vnew(0, sizeof *dlines, PHeap);
	vgrow(&dlines, ndline + 1);
	d = &dlines[ndline++];
	d->fn = curfn;
	d->label = lab;
	d->file = fid;
	d->line = line;
}

static void
emitdbgfnstart(char *n, FILE *f)
{
	DbgFn *d;
	uint lab;

	if (!emitdbg)
		return;
	if (!dfns)
		dfns = vnew(0, sizeof *dfns, PHeap);
	vgrow(&dfns, ndfn + 1);
	d = &dfns[ndfn];
	d->name = dbgstrdup(n);
	d->start = dbglabel();
	d->end = 0;
	d->file = curfile;
	d->hasline = 0;
	curfn = ndfn++;
	lab = d->start;
	fprintf(f, "\t%sdbgfn_begin%u:\n", T.asloc, lab);
	if (T.windows)
		fprintf(f, "\t.cv_func_id %u\n", curfn);
}

void
emitdbgfnfin(char *fn, FILE *f)
{
	DbgFn *d;
	uint lab;

	(void)fn;
	if (!emitdbg || ndfn == 0 || curfn >= ndfn)
		return;
	d = &dfns[curfn];
	if (d->end != 0)
		return;
	lab = dbglabel();
	d->end = lab;
	fprintf(f, "\t%sdbgfn_end%u:\n", T.asloc, lab);
}

static void
emitdwarffin(FILE *f)
{
	uint i, k, ninc, first, last;

	ninc = 0;
	first = 0;
	last = 0;
	for (i=0; i<ndfn; i++)
		if (dfns[i].file != 0 && dfns[i].end != 0) {
			if (ninc == 0)
				first = i;
			last = i;
			ninc++;
		}
	if (nfile == 0 || ninc == 0)
		return;

	dbgsec(f, ".debug_abbrev", "__debug_abbrev");
	fprintf(f, "%sdebug_abbrev_start:\n", T.asloc);
	fputs("\t.byte 1, 0x11, 1\n", f);
	fputs("\t.byte 0x25, 0x08\n", f);
	fputs("\t.byte 0x13, 0x05\n", f);
	fputs("\t.byte 0x03, 0x08\n", f);
	fputs("\t.byte 0x11, 0x01\n", f);
	fputs("\t.byte 0x12, 0x01\n", f);
	fputs("\t.byte 0x10, 0x17\n", f);
	fputs("\t.byte 0, 0\n", f);
	fputs("\t.byte 2, 0x2e, 0\n", f);
	fputs("\t.byte 0x03, 0x08\n", f);
	fputs("\t.byte 0x11, 0x01\n", f);
	fputs("\t.byte 0x12, 0x01\n", f);
	fputs("\t.byte 0x3f, 0x19\n", f);
	fputs("\t.byte 0, 0\n", f);
	fputs("\t.byte 0\n", f);

	dbgsec(f, ".debug_line", "__debug_line");
	fprintf(f, "%sdebug_line_start:\n", T.asloc);
	fprintf(f, "\t.long %sdebug_line_end - %sdebug_line_body\n",
		T.asloc, T.asloc);
	fprintf(f, "%sdebug_line_body:\n", T.asloc);
	fputs("\t.short 4\n", f);
	fprintf(f, "\t.long %sdebug_line_header_end - %sdebug_line_header_start\n",
		T.asloc, T.asloc);
	fprintf(f, "%sdebug_line_header_start:\n", T.asloc);
	fputs("\t.byte 1, 1, 1\n", f);
	fputs("\t.byte 0xfb, 14, 13\n", f);
	fputs("\t.byte 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1\n", f);
	fputs("\t.byte 0\n", f);
	for (i=0; i<nfile; i++) {
		fprintf(f, "\t.asciz \"%s\"\n", files[i]);
		fputs("\t.uleb128 0\n\t.uleb128 0\n\t.uleb128 0\n", f);
	}
	fputs("\t.byte 0\n", f);
	fprintf(f, "%sdebug_line_header_end:\n", T.asloc);

	for (i=0; i<ndfn; i++) {
		uint cline, cfile;
		DbgLine *dl;

		if (dfns[i].file == 0 || dfns[i].end == 0)
			continue;
		cline = 1;
		cfile = 1;
		dl = 0;
		for (k=0; k<ndline; k++)
			if (dlines[k].fn == i) {
				dl = &dlines[k];
				break;
			}
		dbgsetaddr(f, "dbgfn_begin", dfns[i].start);
		fputs("\t.byte 4\n", f);
		dbguleb(f, dfns[i].file);
		cfile = dfns[i].file;
		if (dl != 0) {
			fputs("\t.byte 3\n", f);
			dbgsleb(f, (int)dl->line - (int)cline);
			cline = dl->line;
		}
		fputs("\t.byte 1\n", f);
		for (k=0; k<ndline; k++) {
			if (dlines[k].fn != i)
				continue;
			dbgsetaddr(f, "dbgline", dlines[k].label);
			if (dlines[k].file != cfile) {
				fputs("\t.byte 4\n", f);
				dbguleb(f, dlines[k].file);
				cfile = dlines[k].file;
			}
			if (dlines[k].line != cline) {
				fputs("\t.byte 3\n", f);
				dbgsleb(f, (int)dlines[k].line - (int)cline);
				cline = dlines[k].line;
			}
			fputs("\t.byte 1\n", f);
		}
		dbgsetaddr(f, "dbgfn_end", dfns[i].end);
		fputs("\t.byte 0\n\t.uleb128 1\n\t.byte 1\n", f);
	}
	fprintf(f, "%sdebug_line_end:\n", T.asloc);

	dbgsec(f, ".debug_info", "__debug_info");
	fprintf(f, "%sdebug_info_start:\n", T.asloc);
	fprintf(f, "\t.long %sdebug_info_end - %sdebug_info_body\n",
		T.asloc, T.asloc);
	fprintf(f, "%sdebug_info_body:\n", T.asloc);
	fputs("\t.short 4\n", f);
	if (T.apple)
		fputs("\t.long 0\n", f);
	else
		fprintf(f, "\t.long %sdebug_abbrev_start\n", T.asloc);
	fputs("\t.byte 8\n", f);
	fputs("\t.byte 1\n", f);
	fputs("\t.asciz \"uqbe (spectre)\"\n", f);
	fputs("\t.short 0x000c\n", f);
	fprintf(f, "\t.asciz \"%s\"\n", files[dfns[first].file - 1]);
	dbgref(f, "dbgfn_begin", dfns[first].start);
	dbgref(f, "dbgfn_end", dfns[last].end);
	if (T.apple)
		fputs("\t.long 0\n", f);
	else
		fprintf(f, "\t.long %sdebug_line_start\n", T.asloc);
	for (i=0; i<ndfn; i++) {
		if (dfns[i].file == 0 || dfns[i].end == 0)
			continue;
		fputs("\t.byte 2\n", f);
		fprintf(f, "\t.asciz \"%s\"\n", dfns[i].name);
		dbgref(f, "dbgfn_begin", dfns[i].start);
		dbgref(f, "dbgfn_end", dfns[i].end);
	}
	fputs("\t.byte 0\n", f);
	fprintf(f, "%sdebug_info_end:\n", T.asloc);
}

void
emitdbgfin(FILE *f)
{
	if (!emitdbg)
		return;
	if (T.windows) {
		uint i;

		if (nfile == 0)
			return;
		fputs("\t.section .debug$S,\"dr\"\n", f);
		fputs("\t.p2align 2, 0x0\n", f);
		fputs("\t.long 4\n", f);
		fputs("\t.long 241\n", f);
		fprintf(f, "\t.long %sdbgsym_end - %sdbgsym_start\n",
			T.asloc, T.asloc);
		fprintf(f, "%sdbgsym_start:\n", T.asloc);
		for (i=0; i<ndfn; i++) {
			if (!dfns[i].hasline || dfns[i].end == 0)
				continue;
			fprintf(f, "\t.short %sdbgrec_end%u - %sdbgrec_start%u\n",
				T.asloc, i, T.asloc, i);
			fprintf(f, "%sdbgrec_start%u:\n", T.asloc, i);
			fputs("\t.short 0x1110\n", f);
			fputs("\t.long 0\n\t.long 0\n\t.long 0\n", f);
			fprintf(f, "\t.long %sdbgfn_end%u - %sdbgfn_begin%u\n",
				T.asloc, dfns[i].end, T.asloc, dfns[i].start);
			fputs("\t.long 0\n\t.long 0\n\t.long 0\n", f);
			fprintf(f, "\t.secrel32 %s\n", dfns[i].name);
			fprintf(f, "\t.secidx %s\n", dfns[i].name);
			fputs("\t.byte 0\n", f);
			fprintf(f, "\t.asciz \"%s\"\n", dfns[i].name);
			fputs("\t.p2align 2, 0x0\n", f);
			fprintf(f, "%sdbgrec_end%u:\n", T.asloc, i);
			fputs("\t.short 2\n\t.short 0x114f\n", f);
		}
		fprintf(f, "%sdbgsym_end:\n", T.asloc);
		for (i=0; i<ndfn; i++) {
			if (!dfns[i].hasline || dfns[i].end == 0)
				continue;
			fprintf(f, "\t.cv_linetable %u, %s, %sdbgfn_end%u\n",
				i, dfns[i].name, T.asloc, dfns[i].end);
		}
		fputs("\t.cv_filechecksums\n", f);
		fputs("\t.cv_stringtable\n", f);
		return;
	}
	emitdwarffin(f);
}
