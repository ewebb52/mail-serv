/*
 * obfuscate-password.c
 * 
 * @file: file in which to store the salt + password
 * @user: username for password
 * @pass: password to hash
 * Writes the salted and hashed password to stdout
 * Prevent the same password from hashing to the same value on different
 * machines or for different users
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
	fprintf(stderr, "usage: hash-password <file-name> <username> <password>\n");
}

/*
 * Read cryptographically strong random bytes from /dev/urandom
 */
int get_rand(BYTE *buf)
{
	FILE *fd = NULL;
	int err = 0;

	fd = fopen("/dev/urandom", "r");
	if (!fd) {
		perror("Failed to open /dev/urandom");
		return -1;
	}

	if (fread(buf, 1, sizeof(buf), fd) != sizeof(buf)) {
		err = -1;
		perror("Failed to obtain cryptographically strong random bytes");
		goto out;
	}

out:
	fclose(fd);
	return err;
}

int hash(char *buf, BYTE *iv, BYTE *out)
{
	SHA256_CTX ctx;
	BYTE iv_buf[AES_BLOCK_SIZE + strlen(buf)];
	BYTE in[SHA256_BLOCK_SIZE];
	int n, i = 0;

	/* Prepend IV to the buf */
	n = strlen(buf);
	memcpy(iv_buf, iv, AES_BLOCK_SIZE);
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
	return 0;
}

int main(int argc, char **argv)
{
	int i, r;
	FILE *fd;
	BYTE hashed_pass[SHA256_BLOCK_SIZE];

	if (argc != 4) {
		print_usage();
		exit(-1);
	}

	for (i = 0; i < argc; i++) {
		if (strlen(argv[i]) > 100) {
			fprintf(stderr, "Invalid user input.\n");
			exit(-1);
		}
	}

	/* Prevent pages from being swapped out of memory */
	//if (mlockall(MCL_CURRENT | MCL_FUTURE )) {
	//    perror("mlock() failed");
	//    exit(-1);  
	//}

        for (i = 0; i < strlen(argv[3]); i++) {
                if (argv[3][i] == '\n' || argv[3][i] == '\r')
                        argv[3][i] = '\0';
        }

	/* 
	 * The salt is a 128-bit or longer random number
	 * Two uses of the same password will produce different keys
	 */
	BYTE salt[AES_BLOCK_SIZE];
	if (get_rand(salt))
		exit(-1);

	/* Hash the password */
        hash(argv[3], salt, hashed_pass);


	/* When a key (or the password it is derived from) is no longer needed
	 * zero the memory */

	/* Store the salt (unprotected) with the hashed password */
	r = strlen(argv[1]);
	char path[2*r + strlen("message-sys/priv//pass/-hash.txt")];

	sprintf(path, "message-sys/priv/%s/pass/%s-hash.txt", argv[1], argv[1]);
        fprintf(stderr, "%s\n", path);

	fd = fopen(path, "wb");
	if (!fd) {
		perror("Failed to open tmp file");
		exit(-1);
	}

	fwrite(salt, 1, sizeof(salt), fd);
	fwrite(hashed_pass, 1, sizeof(hashed_pass), fd);

	//munlockall();
	return 0;
}
