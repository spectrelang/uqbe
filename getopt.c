#ifdef _WIN32

#include "getopt.h"

#include <stdio.h>
#include <string.h>

char *optarg;
int optind = 1;
int opterr = 1;
int optopt;

static char *nextchar;

int
getopt(int argc, char *const argv[], const char *optstring)
{
	char *arg;
	char c;
	const char *spec;

	if (optind >= argc || argv[optind] == NULL)
		return -1;

	arg = argv[optind];
	if (nextchar == NULL || *nextchar == '\0') {
		if (arg[0] != '-' || arg[1] == '\0')
			return -1;
		if (strcmp(arg, "--") == 0) {
			optind++;
			return -1;
		}
		nextchar = arg + 1;
	}

	c = *nextchar++;
	spec = strchr(optstring, c);
	if (c == ':' || spec == NULL) {
		if (opterr)
			fprintf(stderr, "%s: invalid option -- '%c'\n", argv[0], c);
		optopt = (unsigned char)c;
		if (*nextchar == '\0') {
			nextchar = NULL;
			optind++;
		}
		return '?';
	}

	if (spec[1] == ':') {
		if (*nextchar != '\0') {
			optarg = nextchar;
			nextchar = NULL;
			optind++;
		} else {
			optind++;
			if (optind >= argc) {
				if (opterr)
					fprintf(stderr,
						"%s: option requires an argument -- '%c'\n",
						argv[0], c);
				optopt = (unsigned char)c;
				return '?';
			}
			optarg = argv[optind++];
		}
	} else {
		optarg = NULL;
		if (*nextchar == '\0') {
			nextchar = NULL;
			optind++;
		}
	}

	return (unsigned char)c;
}

#else

typedef int getopt_unused_translation_unit;

#endif
