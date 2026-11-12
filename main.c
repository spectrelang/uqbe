#include "all.h"
#include "config.h"
#include <ctype.h>
#ifdef _WIN32
#include "getopt.h"
#else
#include <getopt.h>
#endif

#ifndef GIT_COMMIT
#define GIT_COMMIT "unknown"
#endif

Target T;

char debug['Z'+1] = {
	['P'] = 0, /* parsing */
	['M'] = 0, /* memory optimization */
	['N'] = 0, /* ssa construction */
	['C'] = 0, /* copy elimination */
	['G'] = 0, /* gvn/gcm */
	['K'] = 0, /* if-conversion */
	['A'] = 0, /* abi lowering */
	['I'] = 0, /* instruction selection */
	['L'] = 0, /* liveness */
	['S'] = 0, /* spilling */
	['R'] = 0, /* reg. allocation */
};

extern Target T_amd64_sysv;
extern Target T_amd64_apple;
extern Target T_amd64_win;
extern Target T_arm64;
extern Target T_arm64_apple;
extern Target T_arm64_win;
extern Target T_rv64;

static Target *tlist[] = {
	&T_amd64_sysv,
	&T_amd64_apple,
	&T_amd64_win,
	&T_arm64,
	&T_arm64_apple,
	&T_arm64_win,
	&T_rv64,
	0
};
static FILE *outf;
static int dbg;

static void
data(Dat *d)
{
	if (dbg)
		return;
	emitdat(d, outf);
	if (d->type == DEnd) {
		fputs("/* end data */\n\n", outf);
		freeall();
	}
}

static void
func(Fn *fn)
{
	uint n;

	if (dbg)
		fprintf(stderr, "**** Function %s ****", fn->name);
	if (debug['P']) {
		fprintf(stderr, "\n> After parsing:\n");
		printfn(fn, stderr);
	}
	T.abi0(fn);
	fillcfg(fn);
	filluse(fn);
	promote(fn);
	filluse(fn);
	ssa(fn);
	filluse(fn);
	ssacheck(fn);
	fillalias(fn);
	loadopt(fn);
	filluse(fn);
	fillalias(fn);
	coalesce(fn);
	filluse(fn);
	filldom(fn);
	ssacheck(fn);
	gvn(fn);
	fillcfg(fn);
	simplcfg(fn);
	filluse(fn);
	filldom(fn);
	gcm(fn);
	filluse(fn);
	ssacheck(fn);
	if (T.cansel) {
		ifconvert(fn);
		fillcfg(fn);
		filluse(fn);
		filldom(fn);
		ssacheck(fn);
	}
	T.abi1(fn);
	simpl(fn);
	fillcfg(fn);
	filluse(fn);
	T.isel(fn);
	fillcfg(fn);
	filllive(fn);
	fillloop(fn);
	fillcost(fn);
	spill(fn);
	rega(fn);
	fillcfg(fn);
	simpljmp(fn);
	fillcfg(fn);
	assert(fn->rpo[0] == fn->start);
	for (n=0;; n++)
		if (n == fn->nblk-1) {
			fn->rpo[n]->link = 0;
			break;
		} else
			fn->rpo[n]->link = fn->rpo[n+1];
	if (!dbg) {
		T.emitfn(fn, outf);
		fprintf(outf, "/* end function %s */\n\n", fn->name);
	} else
		fprintf(stderr, "\n");
	freeall();
}

static void
dbgfile(char *fn)
{
	emitdbgfile(fn, outf);
}

/* Windows shells sometimes write redirected text as UTF-16.  Accept the
 * common BOMs so generated IL can be fed back without a separate conversion
 * step.  IL itself is ASCII, so keeping the low byte of each UTF-16 unit is
 * sufficient. */
static FILE *
openinput(char *path)
{
	FILE *f, *tmp;
	int c0, c1, c2, lo, hi;

	f = fopen(path, "rb");
	if (!f)
		return 0;

	c0 = fgetc(f);
	c1 = fgetc(f);

	if (c0 == 0xff && c1 == 0xfe) {
		tmp = tmpfile();
		if (!tmp) {
			fclose(f);
			return 0;
		}
		while ((lo = fgetc(f)) != EOF) {
			hi = fgetc(f);
			if (hi == EOF)
				break;
			fputc(lo, tmp);
		}
		fclose(f);
		rewind(tmp);
		return tmp;
	}

	if (c0 == 0xfe && c1 == 0xff) {
		tmp = tmpfile();
		if (!tmp) {
			fclose(f);
			return 0;
		}
		while ((hi = fgetc(f)) != EOF) {
			lo = fgetc(f);
			if (lo == EOF)
				break;
			fputc(lo, tmp);
		}
		fclose(f);
		rewind(tmp);
		return tmp;
	}

	if (c0 == 0xef && c1 == 0xbb) {
		c2 = fgetc(f);
		if (c2 == 0xbf) {
			rewind(f);
			fseek(f, 3, SEEK_SET);
			return f;
		}
	}

	rewind(f);
	return f;
}

int
main(int ac, char *av[])
{
	Target **t;
	FILE *inf, *hf;
	char *f, *sep;
	int c;

	for (c=1; c<ac; c++)
		if (strcmp(av[c], "-spectre-check") == 0) {
			puts("qbe (spectre)");
			exit(0);
		}

	T = Deftgt;
	outf = stdout;
	while ((c = getopt(ac, av, "hd:o:t:v")) != -1)
		switch (c) {
		case 'd':
			for (; *optarg; optarg++)
				if (isalpha(*optarg)) {
					debug[toupper(*optarg)] = 1;
					dbg = 1;
				}
			break;
		case 'o':
			if (strcmp(optarg, "-") != 0) {
				outf = fopen(optarg, "w");
				if (!outf) {
					fprintf(stderr, "cannot open '%s'\n", optarg);
					exit(1);
				}
			}
			break;
		case 't':
			if (strcmp(optarg, "?") == 0) {
				puts(T.name);
				exit(0);
			}
			for (t=tlist;; t++) {
				if (!*t) {
					fprintf(stderr, "unknown target '%s'\n", optarg);
					exit(1);
				}
				if (strcmp(optarg, (*t)->name) == 0) {
					T = **t;
					break;
				}
			}
			break;
		case 'v':
			printf("uqbe (spectre) %s\n", GIT_COMMIT);
			exit(0);
		case 'h':
		default:
			hf = c != 'h' ? stderr : stdout;
			fprintf(hf, "%s [OPTIONS] {file.ssa, -}\n", av[0]);
			fprintf(hf, "\t%-11s prints this help\n", "-h");
			fprintf(hf, "\t%-11s output to file\n", "-o file");
			fprintf(hf, "\t%-11s generate for a target among:\n", "-t <target>");
			fprintf(hf, "\t%-11s ", "");
			for (t=tlist, sep=""; *t; t++, sep=", ") {
				fprintf(hf, "%s%s", sep, (*t)->name);
				if (*t == &Deftgt)
					fputs(" (default)", hf);
			}
			fprintf(hf, "\n");
			fprintf(hf, "\t%-11s dump debug information\n", "-d <flags>");
			fprintf(hf, "\t%-11s print version and commit\n", "-v");
			fprintf(hf, "\t%-11s confirm the Spectre QBE variant\n", "-spectre-check");
			exit(c != 'h');
		}

	do {
		f = av[optind];
		if (!f || strcmp(f, "-") == 0) {
			inf = stdin;
			f = "-";
		} else {
			inf = openinput(f);
			if (!inf) {
				fprintf(stderr, "cannot open '%s'\n", f);
				exit(1);
			}
		}
		parse(inf, f, dbgfile, data, func);
		fclose(inf);
	} while (++optind < ac);

	if (!dbg)
		T.emitfin(outf);

	exit(0);
}
