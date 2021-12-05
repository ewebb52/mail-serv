/*
 * obfuscate-password.c
 * 
 * @file: file to read salt and hashed password
 * @user: username for password
 * @pass: inputted password to authenticate
 *
 * Performs user authentication
 * Reads an existing salt from file, hashes given password
 * And ensures that the hashed password matches the stored password
 * Returns EINVAL on failure to authenticate
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <assert.h>
#include "crypto-algorithms/aes.h"
#include "crypto-algorithms/sha256.h"
#include <sys/mman.h>

typedef unsigned char BYTE;
typedef unsigned int WORD;

void print_usage(void)
{
	fprintf(stderr, "usage: check-password <filename> <username> <password>\n");
}

int hash(char *file, char *buf, BYTE *out)
{
	SHA256_CTX ctx;
	BYTE iv_buf[AES_BLOCK_SIZE + strlen(buf)];
	BYTE in[SHA256_BLOCK_SIZE];
	int n, i = 0, err = 0;
	FILE *fd = NULL;

	/* Read the salt bytes from file */
	fd = fopen(file, "r");
	if (!fd) {
		perror("Failed to access password file");
		return -1;
	}

	BYTE salt[AES_BLOCK_SIZE];
	if (fread(salt, 1, sizeof(salt), fd) != sizeof(salt)) {
		perror("Failed to obtain salt");
		goto out;
	}

	/* Prepend IV to the buf */
	n = strlen(buf);
	memcpy(iv_buf, salt, AES_BLOCK_SIZE);
	memcpy(iv_buf + AES_BLOCK_SIZE, buf, n);

	/* First iteration to standardize buf size */
	sha256_init(&ctx);
	sha256_update(&ctx, iv_buf, AES_BLOCK_SIZE + strlen(buf));
	sha256_final(&ctx, out);

	memcpy(in, out, SHA256_BLOCK_SIZE);

	/* Iteratively apply SHA2-256 at least 10,000 additional times */
	for (i = 0; i < 10000; i ++) {
		sha256_init(&ctx);
		sha256_update(&ctx, in, SHA256_BLOCK_SIZE);
		sha256_final(&ctx, out);

		memcpy(in, out, SHA256_BLOCK_SIZE);
	}

	memcpy(out, in, SHA256_BLOCK_SIZE);

out:

	fclose(fd);
	return err;
}

int cmp_password(char *file, BYTE *computed_pass)
{

	FILE *fd = NULL;
	int err = 0;
	BYTE salt[AES_BLOCK_SIZE];
	BYTE hashed_pass[SHA256_BLOCK_SIZE];

	fd = fopen(file, "r");
	if (!fd) {
		perror("Failed to access password file");
		return -1;
	}

	if (fread(salt, 1, sizeof(salt), fd) != sizeof(salt)) {
		err = -1;
		perror("Failed to obtain salt");
		goto out;
	}

	if (fread(hashed_pass, 1, sizeof(hashed_pass), fd) != sizeof(hashed_pass)) {
		err = -1;
		perror("Failed to obtain password");
		goto out;
	}

	err = memcmp(hashed_pass, computed_pass, sizeof(BYTE) * SHA256_BLOCK_SIZE);
        fprintf(stderr, "%d\n", err);

out:
	fclose(fd);
	return err;

}

int main(int argc, char **argv)
{
	int i, r;
	BYTE hashed_pass[SHA256_BLOCK_SIZE];
        char *pass;

	if (argc != 4) {
		print_usage();
		exit(EINVAL);
	}

	for (i = 0; i < argc; i++) {
		if (strlen(argv[i]) > 100) {
			fprintf(stderr, "Invalid user input.\n");    
			exit(EINVAL);
		}
	}

	/* TODO Prevent pages from being swapped out of memory */
	//if (mlockall(MCL_CURRENT | MCL_FUTURE )) {
	//    perror("mlock() failed");
	//    exit(EINVAL);  
	//}

	/* Remove potential new line from password if it was user input */
	for (i = 0; i < strlen(argv[3]); i++) {
		if (argv[3][i] == '\n' || argv[3][i] == '\r')
			argv[3][i] = '\0';
	}

	r = strlen(argv[1]);
	char path[2*r + strlen("message-sys/priv//pass/-hash.txt")];
        pass = argv[3];

	r = sprintf(path, "message-sys/priv/%s/pass/%s-hash.txt", argv[1], argv[1]);
        path[r] = '\0';

	/* Hash the password */
	hash(path, pass, hashed_pass);

	/* When a key (or the password it is derived from) is no longer needed
	 * zero the memory */

	/* Compare the new password with the hashed password
	 * Return error if they do not match 
	 */
//        fprintf(stderr, "the password: %s\npath: %s\n", argv[3], path);
        
	if (cmp_password(path, hashed_pass))
		exit(EINVAL);

	fprintf(stderr, "Valid password: %s\n", argv[1]);
	// munlockall();
	return 0;
}
