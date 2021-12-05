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
#include "mail.h"
#include "list.h"

int parse_line_err(char *lineptr, FILE *out)
{
	char msgbuf[strlen(lineptr) + 1];

	/* Message end of single period */
	if (strncmp(lineptr, ".", strlen(".")) == 0) {
		if (strlen(lineptr) == strlen(".\n"))
			return 1;

		sprintf(msgbuf, "%s", lineptr + 1);
	} else {
		sprintf(msgbuf, "%s", lineptr);
	}

	return 0;
}

int err(void *p1, regex_t *regex, FILE *fd, struct Rcpt *queue)
{
	size_t n = 0;
	int res;

	free(p1);

	/* Read up until the next message */
	while (getline((char **)&p1, &n, stdin) != EOF) {
		res = parse_line_err((char *)p1, fd);
		if (res)
			goto next;
	}

	free(p1);
	regfree(regex);
	fclose(fd);
	removeAllNodes(queue);
	exit(1);

next:

	free(p1);
	regfree(regex);
	removeAllNodes(queue);
	init_scratch_paper(&fd);
	initRcpt(queue);

	/* Parse all incoming messages in file */
	while (parse_msg(fd, queue) != EOF)
		send_to_rcpts(queue, &fd);

	regfree(regex);

	clean_up(&fd, *queue);
	exit(0);
}

int cleanup(void *p1, regex_t *regex)
{
	free(p1);
	regfree(regex);
	return 0;
}

int check_sender(char *sender, void *p1, regex_t *regex, FILE *fd,
		struct Rcpt *queue, int r)
{
	/* Check if sender is valid */
	struct stat statbuf;
	char *prepath = "mail/";
	char path[r + strlen(prepath) + 1 + 6];
	char sub[strlen(sender) + 1];

	strncpy(sub, sender, strlen(sender) + 1);

	if (strchr(sub, '/') != NULL || strmal(sub)) {
		fprintf(stderr, "Invalid sender\n");
		err(p1, regex, fd, queue);
	}

	strncpy(path, prepath, strlen(prepath) + 1);
	strncat(path, sender, strlen(sender) + 1);

	strlower(path);
	stat(path, &statbuf);
	if (stat(path, &statbuf) == -1) {
		fprintf(stderr, "Invalid sender\n");
		err(p1, regex, fd, queue);
	}

	if (!S_ISDIR(statbuf.st_mode)) {
		fprintf(stderr, "Invalid sender\n");
		err(p1, regex, fd, queue);
	}

	return 0;
}

int parse_validate_sender(FILE *out, struct Rcpt *queue,
		char *lineptr, int n, regex_t *regex)
{
	char sender[n];
	char buf[n + strlen("From: ") + 1];
	char *from = "MAIL FROM:";
	int start, end, r;
	regmatch_t match[1];

	/* Message consists of a MAIL FROM as first line */
	strupper(lineptr);
	if (strncmp(lineptr, from, strlen(from)) != 0) {
		fprintf(stderr, "Invalid message headers.\n");
		err(lineptr, regex, out, queue);
	}

	r = regexec(regex, lineptr + strlen(from), 1, match, 0);
	if (r) {
		fprintf(stderr, "Invalid sender.\n");
		err(lineptr, regex, out, queue);
	}

	start = match[0].rm_so;
	end = match[0].rm_eo;

	/* Message does not have trailing chars before opening bracket */
	if (start != 0) {
		fprintf(stderr, "Invalid sender.\n");
		err(lineptr, regex, out, queue);
	}

	/* Message does not have trailing chars after the closing bracket */
	if (strlen(lineptr) > end + strlen(from) + 1) {
		fprintf(stderr, "Invalid sender.\n");
		err(lineptr, regex, out, queue);
	}

	strncpy(sender, lineptr + strlen(from) + start + 1,
			end - start - 2);
	sender[end - start - 2] = 0;

	strlower(sender);
	sprintf(buf, "From: %s\n", sender);

	r = strlen(sender);
	strlower(sender);
	check_sender(sender, lineptr, regex, out, queue, r);

	fwrite(buf, 1, strlen(buf), out);
	return 0;
}

int parse_line(char *lineptr, FILE *out)
{
	char msgbuf[strlen(lineptr) + 1];

	/* Message end of single period */
	if (strncmp(lineptr, ".", strlen(".")) == 0) {
		if (strlen(lineptr) == strlen(".\n"))
			return 1;


		sprintf(msgbuf, "%s", lineptr + 1);
		fwrite(msgbuf, 1, strlen(msgbuf), out);
	} else {
		sprintf(msgbuf, "%s", lineptr);
		fwrite(msgbuf, 1, strlen(msgbuf), out);
	}

	return 0;
}

int parse_msg(FILE *out, struct Rcpt *autoSugg)
{
	regex_t regex;
	regmatch_t match[1];

	char *to = "RCPT TO:";
	char *data = "DATA\n";
	char *usr = "<([^>]+)>";
	int rcpt = 0;

	char *lineptr = NULL;
	size_t n = 0;
	int r, res;

	/* Check if parsed all messages in given file / stdin */
	regcomp(&regex, usr, REG_ICASE | REG_EXTENDED);
	if (getline(&lineptr, &n, stdin) == EOF) {
		cleanup(lineptr, &regex);
		return EOF;
	}

	parse_validate_sender(out, autoSugg, lineptr, n, &regex);

	/* Message consists of one or more RCPT TO */
	fwrite("To: ", 1, strlen("To: "), out);

	while (getline(&lineptr, &n, stdin) != EOF) {

		char buf[200];
		/* Control lines ended by DATA */
		strupper(lineptr);
		if (!(strncmp(lineptr, data, strlen(data)))) {
			if (strlen(lineptr) != strlen(data) || !rcpt) {
				perror("Invalid message headers");
				err(lineptr, &regex, out, autoSugg);
			}
			sprintf(buf, "\n");
			fwrite(buf, 1, strlen(buf), out);
			goto msg;
		}

		if (strncmp(lineptr, to, strlen(to)) != 0) {
			perror("Invalid message headers");
			err(lineptr, &regex, out, autoSugg);
		}

		rcpt = 1;
		/* parse each name */
		char rcpt[n];
		char bufr[n + strlen(", ") + 1];
		char *newstr = (char *)malloc(n*sizeof(char));

		if (newstr == NULL) {
			perror("error");
			err(lineptr, &regex, out, autoSugg);
		}

		r = regexec(&regex, lineptr + strlen(to), 1, match, 0);
		if (r != 0) {
			free(newstr);
			perror("Invalid message headers");
			err(lineptr, &regex, out, autoSugg);
		}

		strncpy(rcpt, lineptr + strlen(to) + match[0].rm_so + 1,
				match[0].rm_eo - match[0].rm_so - 2);
		rcpt[match[0].rm_eo - match[0].rm_so - 2] = 0;


		/* check invalidity after the closing angular bracket */
		if (match[0].rm_so != 0) {
			free(newstr);
			perror("Invalid message headers");
			err(lineptr, &regex, out, autoSugg);
		}

		if (strlen(lineptr) > match[0].rm_eo + strlen(to) + 1 ||
				strmal(rcpt)) {
			free(newstr);
			perror("Invalid message headers");
			err(lineptr, &regex, out, autoSugg);
		}

		strlower(rcpt);
		sprintf(bufr, "%s, ", rcpt);
		strcpy(newstr, rcpt);
		strlower(newstr);
		addFront(autoSugg, newstr);
		fwrite(bufr, 1, strlen(bufr), out);
	}

	fprintf(stderr, "Invalid message headers");
	err(lineptr, &regex, out, autoSugg);

msg:
	/* message body */
	while (getline(&lineptr, &n, stdin) != EOF) {
		res = parse_line(lineptr, out);
		if (res)
			goto out;
	}

	fprintf(stderr, "Invalid message body");
	err(lineptr, &regex, out, autoSugg);

out:
	free(lineptr);
	regfree(&regex);
	return 0;
}

int recycle_scratch_paper(FILE **tmp)
{
	if (*tmp != NULL)
		fclose(*tmp);

	remove("tmp/tmp.txt");
	return 0;
}

FILE *init_scratch_paper(FILE **tmp)
{

	recycle_scratch_paper(tmp);
	*tmp = fopen("tmp/tmp.txt", "w+b");

	if (*tmp == NULL) {
		perror("Temporary memory allocations failed");
		exit(1);
	}

	return NULL;
}

int send_to_rcpts(struct Rcpt *queue, FILE **tmp)
{
	struct Node *node = queue->head;
	int fd[2];
	int status;
	int n;
	char buf[4096];
	pid_t pid;

	if (queue->size <= 0)
		goto out;

	while (node) {
		if (!node->data)
			goto out;

		pipe(fd);
		pid = fork();

		if (!pid) {
			/* Close writing side of pipe */
			close(fd[1]);
			close(STDIN_FILENO);
			dup2(fd[0], STDIN_FILENO);

			strlower((char *)node->data);
			execl("bin/mail-out", "bin/mail-out",
					(char *)node->data, NULL);

			perror("Connection to mail-out failed");
			exit(1);

		} else {

			/* Close reading end of pipe */
			close(fd[0]);

			/* Go back to beginning of tmp file */
			fseek(*tmp, SEEK_SET, 0);
			while ((n = fread(&buf, 1, 4096, *tmp)))
				write(fd[1], buf, n);

			close(fd[1]);
			pid = wait(&status);

			/* Check status */
			if (WEXITSTATUS(status) == EINVAL)
				fprintf(stderr, "Invalid recipient: %s\n",
						(char *)node->data);

			node = node->next;
		}
	}
out:
	init_scratch_paper(tmp);
	removeAllNodes(queue);
	initRcpt(queue);

	return 0;
}

int clean_up(FILE **tmp, struct Rcpt queue)
{
	recycle_scratch_paper(tmp);
	removeAllNodes(&queue);

	return 0;
}

int main(int argc, char **argv)
{
	struct Rcpt queue;
	FILE *tmp = NULL;

	init_scratch_paper(&tmp);
	initRcpt(&queue);

	/* Parse all incoming messages in file */
	while (parse_msg(tmp, &queue) != EOF)
		send_to_rcpts(&queue, &tmp);

	clean_up(&tmp, queue);
	return 0;
}
