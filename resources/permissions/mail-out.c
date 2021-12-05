#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <regex.h>
#include <sys/stat.h>
#include <dirent.h>
#include "mail.h"

int err(void *p1, regex_t *regex)
{
	return 0;
}

int cleanup(void *p1, regex_t *regex)
{
	return 0;
}

int main(int argc, char **argv)
{
	struct stat statbuf;
	char *prepath = "mail/";
	int r;
	struct dirent *de;


	char *lineptr = NULL;
	int len = 0;
	size_t n = 0;


	if (argc != 2)
		exit(1);

	/* Check if recipient is valid */
	r = strlen(argv[1]);
	char path[r + strlen(prepath) + 1 + 6];

	strncpy(path, prepath, strlen(prepath) + 1);
	strncat(path, argv[1], strlen(argv[1]) + 1);

	strlower(path);
	stat(path, &statbuf);
	if (stat(path, &statbuf) == -1) {
		while ((len = getline(&lineptr, &n, stdin)) != EOF)
			continue;
		exit(EINVAL);
	}

	if (!S_ISDIR(statbuf.st_mode)) {
		while ((len = getline(&lineptr, &n, stdin)) != EOF)
			continue;

		exit(EINVAL);
	}

	DIR * dr = opendir(path);

	/* Get tail in current directory */
	int count = -1;

	while ((de = readdir(dr)) != NULL)
		count++;

	char newfile[7];

	sprintf(newfile, "/%05d", count);
	strncat(path, newfile, 7);
	FILE *saveme = fopen(path, "wb");

	if (!saveme) {
		perror("fopen failed:");
		exit(1);
	}

	while ((len = getline(&lineptr, &n, stdin)) != EOF)
		fwrite(lineptr, 1, len, saveme);

	exit(0);
}
