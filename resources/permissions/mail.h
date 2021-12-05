#ifndef _MAIL_H_
#define _MAIL_H_
#include "list.h"
#include <ctype.h>
#include <string.h>

char *strupper(char *str)
{
	int i = 0;

	while (i < strlen(str)) {
		str[i] = toupper(str[i]);
		i++;
	}

	return NULL;
}

char *strlower(char *str)
{
	int i = 0;

	while (i < strlen(str)) {
		str[i] = tolower(str[i]);
		i++;
	}

	return NULL;
}

int strmal(char *str) {
	int i = 0;

	while (i < strlen(str)) {
		if (i == 0 && !isprint(str[i])) {
			return 1;
		}

		if (!isprint(str[i]) && !isdigit(str[i]) &&
			str[i] != '+' && str[i] != '-' &&
			str[i] != '_') {
			return 1;
		}

		i++;
	}

	return 0;
}

FILE * init_scratch_paper(FILE **tmp);

int clean_up(FILE **tmp, struct Rcpt queue);

int send_to_rcpts(struct Rcpt *queue, FILE **tmp);

int parse_line(char *lineptr, FILE *out);

int parse_msg(FILE *out, struct Rcpt *autoSugg);

#endif

