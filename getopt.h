#ifndef QBE_GETOPT_H
#define QBE_GETOPT_H

#ifdef _WIN32

extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;

int getopt(int argc, char *const argv[], const char *optstring);

#endif

#endif
