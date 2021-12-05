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
#include "cstore.h"
#include <sys/mman.h>

#ifdef MALICIOUS
#include "maliciousmalloc.h"
#endif

typedef unsigned char BYTE;
typedef unsigned int WORD;

char *mallerr = "Malloc returned null. Aborting action. Archive may be compromised.\n";
char *hmacerr = "HMAC procedure failed. Aborting action. Archive may be compromised.\n";
char *ferr    = "File operation failed. Aborting action. Archive may be compromised.\n";

void die(char *msg)
{
	perror(msg);
	exit(1);
}

void print_usage(void)
{
	fprintf(stderr, "usage: %s\n%s\n%s\n%s\n",
			"cstore list <archivename>",
			"cstore add [-p password] archivename file",
			"cstore extract [-p password] archivename file",
			"cstore delete [-p password] archivename file");
}

BYTE *hash_iv(BYTE *cipher, int clen)
{
	int i, first = 1;
	SHA256_CTX ctx;
	BYTE *in = NULL, *out = NULL;

	in = (BYTE *)malloc(clen);
	if (!in) {
		fprintf(stderr, "%s", mallerr);
		goto out;
	}
	out = (BYTE *)malloc(SHA256_BLOCK_SIZE);
	if (!out) {	
		fprintf(stderr, "%s", mallerr);
		free(in);
		in = NULL;
		goto out;
	}

	memcpy(in, cipher, clen);


	/* Iteratively apply SHA2-256 at least 10,000 times */
	for (i = 0; i < 10001; i ++) {
		sha256_init(&ctx);
		sha256_update(&ctx, in, clen);
		sha256_final(&ctx, out);
		clen = SHA256_BLOCK_SIZE;

		if (first) {
			free(in);
			in = (BYTE *)malloc(SHA256_BLOCK_SIZE);
			if (!in) {
				fprintf(stderr, "%s", mallerr);
				free(out);
				goto out;
			}
			first = 0;
		}
		memcpy(in, out, SHA256_BLOCK_SIZE);
	}

	free(out);	
	free(in);

out:
	return in;
}

BYTE *convert_pass(BYTE *cipher, int clen)
{
	int i, first = 1;
	SHA256_CTX ctx;
	BYTE *in = NULL, *out = NULL;

	in = (BYTE *)malloc(clen);
	if (!in) {
		fprintf(stderr, "%s", mallerr);
		goto out;
	}
	out = (BYTE *)malloc(SHA256_BLOCK_SIZE);
	if (!out) {	
		fprintf(stderr, "%s", mallerr);
		free(in);
		in = NULL;
		goto out;
	}

	memcpy(in, cipher, clen);

	/* Iteratively apply SHA2-256 at least 10,000 times */
	for (i = 0; i < 10000; i ++) {
		sha256_init(&ctx);
		sha256_update(&ctx, in, clen);
		sha256_final(&ctx, out);
		clen = SHA256_BLOCK_SIZE;

		if (first) {
			free(in);
			in = (BYTE *)malloc(SHA256_BLOCK_SIZE);
			if (!in) {
				fprintf(stderr, "%s", mallerr);
				free(out);
				goto out;
			}
			first = 0;
		}
		memcpy(in, out, SHA256_BLOCK_SIZE);
	}

	free(out);	
out:
	return in;
}

int hmac(BYTE *K, int Klen, BYTE *text, int tlen, BYTE *chash)
{
	int i, ret = 0;
	int B = SHA256_BLOCK_SIZE;
	BYTE ipad[B]; /* Byte 0x36 repeated B times */
	BYTE opad[B]; /* Byte 0x5C repeated B times */
	SHA256_CTX ctx1, ctx2;

	BYTE t_buf[B];
	BYTE paddedK[B];
	BYTE paddedK_ipad[B];
	BYTE paddedK_opad[B];
	BYTE text_opad[2 * B];
	BYTE *paddedK_text = NULL;

	paddedK_text = malloc(B + tlen);
	if (!paddedK_text) {
		fprintf(stderr, "%s", mallerr);
		ret = 1;
		goto out;
	}


	/* keys longer than B bytes are first hashed using H */
	if (Klen > B) {
		sha256_init(&ctx1);
		sha256_update(&ctx1, K, Klen);
		sha256_final(&ctx1, paddedK);
	}

	/* (1) append zeros to the end of K to create a B byte string
	 * (e.g., if K is of length 20 bytes and B=64, then K will be
	 * appended with 44 zero bytes 0x00)
	 */
	else if (Klen <= B) {
		for (i = 0; i < Klen; i++) 
			paddedK[i] = K[i];

		for (i = Klen; i < B; i++)
			paddedK[i] = 0x00;
	}

	for (i = 0; i < B; i++) {
		ipad[i] = 0x36; 
		opad[i] = 0x5C; 
	}

	/* (2) XOR (bitwise exclusive-OR) the B byte string computed in step
	 * (1) with ipad
	 */
	for (i = 0; i < B; i++)
		paddedK_ipad[i] = paddedK[i] ^ ipad[i];

	/* (3) append the stream of data 'text' to the B byte string resulting
	 * from step (2)
	 */  
	memcpy(paddedK_text, paddedK_ipad, B);
	memcpy(paddedK_text + B, text, tlen);

	/* (4) apply H to the stream generated in step (3) */
	sha256_init(&ctx2);
	sha256_update(&ctx2, paddedK_text, B + tlen);
	sha256_final(&ctx2, t_buf);

	/* (5) XOR (bitwise exclusive-OR) the B byte string computed in
	 * step (1) with opad
	 */
	for (i = 0; i < Klen; i++) 
		paddedK_opad[i] = paddedK[i] ^ opad[i];

	/* (6) append the H result from step (4) to the B byte string
	 * resulting from step (5)
	 */
	memcpy(text_opad, paddedK_opad, B);
	memcpy(text_opad + B, t_buf, B);

	/* (7) apply H to the stream generated in step (6) and output
	 * the result
	 */
	sha256_init(&ctx2);
	sha256_update(&ctx2, text_opad, 2 * B);
	sha256_final(&ctx2, chash);

	free(paddedK_text);

out:
	return ret;
}

int update_meta(FILE *archive, BYTE *key, int Klen)
{
	/* Read in entire file */
	struct Archive *ainfo = NULL; 
	BYTE *crypto_file = NULL;
	int n = 0, ret = 0;
	BYTE *hash = NULL;
	long fstart, fend, fsize;
	int err;

	if ((err = fseek(archive, 0, SEEK_END)) < 0) {
		ret = 1;
		fprintf(stderr, "%s", ferr);
		goto out;
	}

	fend = ftell(archive);
	if (fend == -1) {
		ret = 1;
		fprintf(stderr, "%s", ferr);
		goto out;
	}

	if ((err = fseek(archive, sizeof(struct Archive), SEEK_SET)) < 0) {
		ret = 1;
		fprintf(stderr, "%s", ferr);
		goto out;
	}

	fstart = ftell(archive);
	if (fstart == -1) {
		ret = 1;
		fprintf(stderr, "%s", ferr);
		goto out;
	}	

	fsize = fend - fstart;

	ainfo = (struct Archive *)malloc(sizeof(struct Archive));
	if (!ainfo) {
		fprintf(stderr, "%s", mallerr);
		ret = 1;
		goto out;
	}

	hash = (BYTE *)malloc(SHA256_BLOCK_SIZE);
	if (!hash) {
		fprintf(stderr, "%s", mallerr);
		ret = 1;
		free(ainfo);
		goto out;
	}

	crypto_file = (BYTE *)malloc(fsize);
	if (!crypto_file) {
		fprintf(stderr, "%s", mallerr);
		free(hash);
		free(ainfo);
		ret = 1;
		goto out;
	}

	n = fread(crypto_file, 1, fsize, archive);
	if (n != fsize) {
		fprintf(stderr, "%s", ferr);
		ret = 1;
		free(hash);
		free(ainfo);
		free(crypto_file);
		goto out;
	}

	ret = hmac(key, Klen, crypto_file, n, hash);
	if (ret) {
		fprintf(stderr, "%s", hmacerr);
		goto out;
	}

	memcpy(ainfo->hash, hash, SHA256_BLOCK_SIZE);
	ainfo->clen = fsize;

	if ((err = fseek(archive, 0, SEEK_SET)) < 0) {
		fprintf(stderr, "%s", ferr);
		ret = 1;
		free(hash);
		free(ainfo);
		free(crypto_file);
		goto out;   
	}

	err = fwrite(ainfo, 1, sizeof(struct Archive), archive);
	if (err != sizeof(struct Archive)) {
		fprintf(stderr, "%s", ferr);
		ret = 1;
		free(hash);
		free(ainfo);
		free(crypto_file);

	}

	free(hash);
	free(crypto_file);
	free(ainfo);

out:
	return ret;
}

int validate_hash(BYTE *K, int Klen, FILE *archive)
{
	/* Read in entire file */
	struct Archive *ainfo = NULL; 
	BYTE *crypto_file = NULL;
	int clen = 0, n = 0, ret = 0;
	long fend, fstart, fsize;
	BYTE *chash = NULL;
	BYTE buf[1024];
	int err;

	chash = (BYTE *)malloc(SHA256_BLOCK_SIZE);
	if (!chash) {
		fprintf(stderr, "%s", mallerr);
		ret = 1;
		goto abort;
	}

	ainfo = (struct Archive *)malloc(sizeof(struct Archive));
	if (!ainfo) {
		fprintf(stderr, "%s", mallerr);
		free(chash);
		ret = 1;
		goto abort;
	}

	memset(chash, 0, SHA256_BLOCK_SIZE);
	memset(ainfo, 0, sizeof(struct Archive));

	if ((err = fseek(archive, 0, SEEK_SET)) < 0) {
		fprintf(stderr, "%s", ferr);
		free(chash);
		free(ainfo);
		ret = 1;
		goto abort;
	}

	err = fread(ainfo, 1, sizeof(struct Archive), archive);
	if (err != sizeof(struct Archive)) {
		fprintf(stderr, "%s", ferr);
		free(chash);
		free(ainfo);
		ret = 1;
		goto abort; 
	}

	/* Read in encrypted (crypto) file */
	while((n = fread(&buf, 1, AES_BLOCK_SIZE, archive))) {
		clen += n;
	}

	/* fread returns 0 on feof and error indistinguishably... */
	if (ferror(archive)) { 
		fprintf(stderr, "Error reading in archive, \
				please try again.\n");
	}

	if ((err = fseek(archive, 0, SEEK_END)) < 0) {
		fprintf(stderr, "%s", ferr);
		free(chash);
		free(ainfo);
		ret = 1;
		goto abort;        
	}

	fend = ftell(archive);
	if (fend == -1) {
		fprintf(stderr, "%s", ferr);
		free(chash);
		free(ainfo);
		ret = 1;
		goto abort;
	}

	if ((err = fseek(archive, sizeof(struct Archive), SEEK_SET) < 0)) {
		fprintf(stderr, "%s", ferr);
		free(chash);
		free(ainfo);
		ret = 1;
		goto abort;        

	}

	fstart = ftell(archive);
	if (fstart == -1) {
		fprintf(stderr, "%s", ferr);
		free(chash);
		free(ainfo);
		ret = 1;
		goto abort;
	}

	fsize = fend - fstart;

	crypto_file = (BYTE *)malloc(fsize);
	if (!crypto_file) {
		fprintf(stderr, "%s", mallerr);
		free(chash);
		free(ainfo);
		ret = 1;
		goto abort;
	}

	n = fread(crypto_file, 1, fsize, archive);
	if (n != fsize) { 
		fprintf(stderr, "%s", ferr);
		free(chash);
		free(ainfo);
		free(crypto_file);
		ret = 1;
		goto abort;
	}

	ret = hmac(K, Klen, crypto_file, n, chash);
	if (ret) {
		fprintf(stderr, "%s", hmacerr);
		goto out;
	}

	if (memcmp(chash, ainfo->hash, SHA256_BLOCK_SIZE)) {
		fprintf(stderr, "Error: Integrity of archive has been %s",
				"compromised. Aborting action.\n");
		ret = 1;
		goto out;
	}
out:
	free(crypto_file);
	free(ainfo);
	free(chash);

abort:
	return ret;
}

void *init_vector(BYTE *iv, int size)
{
	FILE *fd = NULL;

	fd = fopen("/dev/urandom", "r");
	if (!fd) {
		fprintf(stderr, "Failed to obtain cryptographically strong random bytes");
		return NULL;
	}
	if (fread(iv, size, 1, fd) < 0) {
		fclose(fd);
		fprintf(stderr, "Failed to obtain cryptographically strong random bytes");
		return NULL;
	}
	/* hash (or HMAC) a counter initialized from random val */
	iv = hash_iv(iv, size);

	fclose(fd);

	return iv;

}

int aes_decrypt_cbc_block(BYTE in[], size_t in_len, BYTE out[], const WORD key[],
		int keysize, const BYTE iv[])
{
	int i = 0;

	aes_decrypt(in, out, key, keysize);

	/* Combine output of plaintext block with encryption of previous block */
	for (i = 0; i < AES_BLOCK_SIZE; i++)
		out[i] ^= iv[i]; 
	return 0;
}

int aes_encrypt_cbc_block(BYTE in[], size_t in_len, BYTE out[], const WORD key[],
		int keysize, const BYTE iv[])
{

	int i = 0;
	BYTE *padding = (BYTE *)malloc(AES_BLOCK_SIZE);
	if (padding == NULL) {
		fprintf(stderr, "%s", mallerr);
		return -1;
	}

	if (!init_vector(padding, AES_BLOCK_SIZE)) {
		fprintf(stderr, "%s", ferr);
		free(padding);
		return -1;
	}


	/* CBC mode requires the input to be a multiple of
	 * the cipher’s block size
	 */ 
	if (in_len % keysize != 0) {
		memcpy((void *)(in + in_len), (void *)padding, in_len % keysize);
	}

	/* combine output of previous encryption block with
	 * the plaintext of the next block
	 */
	for (i = 0; i < AES_BLOCK_SIZE; i++)
		in[i] ^= iv[i];

	aes_encrypt(in, out, key, keysize);

	free(padding);

	return in_len % keysize;
}

#define strequal(s0, s1) strcmp(s0, s1) == 0
int is_dup(FILE *archive, char *fpath)
{
	int n = 0, found = 0, err;
	struct File *finfo = (struct File *)malloc(sizeof(struct File));
	if (!finfo) {
		fprintf(stderr, "%s", mallerr);
		goto abort;
	}

	if ((err = fseek(archive, sizeof(struct Archive), SEEK_SET)) < 0) {
		fprintf(stderr, "%s", ferr);
		free(finfo);
		goto abort;
	}

	while((n = fread(finfo, 1, sizeof(struct File), archive))) {
		if (n != sizeof(struct File)) {
			fprintf(stderr, "%s", ferr);
			free(finfo);
			goto abort;
		}
		if (strequal(finfo->name, fpath) && finfo->exist == '1') {
			found = 1;
			goto out;
		}

		if ((err = fseek(archive, finfo->size, SEEK_CUR)) < 0) {
			fprintf(stderr, "%s", ferr);
			free(finfo);
			goto abort;
		}
	}

out:
	free(finfo);

abort:
	return found;
}

/**
 * Only allow regular files, fifos do not
 * follow fseek behaviors ...
 */
FILE *validate_path(char* path)
{
	struct stat statbuf;
	FILE *fd;

	if(stat(path, &statbuf) == -1) {
		errno = ENOENT;
		return NULL;
	}

	if (!S_ISREG(statbuf.st_mode)) {
		errno = EPERM;
		return NULL;
	}

	fd = fopen(path, "r+b");
	if (fd == NULL) {
		return NULL;
	}

	return fd;
}

FILE *finit(char *path) {
	FILE *fd;

	fd = fopen(path, "wr+b");
	if (fd == NULL) 
		perror("error: ");

	return fd;
}

int add_to_archive(char *apath, char *fpath, BYTE *keye, BYTE *keyi)
{
	int fsize = 0;
	int padding = 0, uncrypt_size = 0, plen = 0;
	char stat = '1';
	int new = 1;
	int err;

	FILE *archive = NULL, *file = NULL;
	struct File *finfo = NULL; 
	struct Archive *ainfo = NULL; 

	/* CHANGE LATER */
	int keysize = 256;

	BYTE plaintext[AES_BLOCK_SIZE]; 
	BYTE enc_buf[AES_BLOCK_SIZE];
	BYTE *iv = NULL;
	WORD key_schedulei[60];
	WORD key_schedulee[60];

	finfo = (struct File *)malloc(sizeof(struct File));
	if (!finfo) {
		fprintf(stderr, "%s", mallerr);
		goto abort;
	}

	ainfo = (struct Archive *)malloc(sizeof(struct Archive));
	if (!ainfo) {
		fprintf(stderr, "%s", mallerr);
		free(finfo);
		goto abort;
	}

	iv = (BYTE *)malloc(AES_BLOCK_SIZE * sizeof(BYTE));
	if (!iv) {
		fprintf(stderr, "%s", mallerr);
		free(ainfo);
		free(finfo);
		goto abort;
	}

	file = validate_path(fpath); 
	if (!file) {
		fprintf(stderr, "%s: No such file or directory.\n", fpath);
		free(finfo);
		free(ainfo);
		free(iv);
		goto abort;
	}

	archive = validate_path(apath);
	if (!archive)
		archive = finit(apath);
	else
		new = 0;

	if (!archive) {
		fprintf(stderr, "Could not initialize archive. Aborting...\n");
		free(finfo);
		free(ainfo);
		free(iv);
		fclose(file);
		goto abort;
	}

	if(is_dup(archive, fpath)) {
		fprintf(stderr, "File already exists in archive. %s",
				"Cannot store duplicates.\n");
		goto out;
	}

	/* Initialization for encryption- write empty placeholder struct 
	 * Set up key, & create initialization vector
	 */
	if ((err = fseek(archive, 0, SEEK_SET)) < 0) {
		fprintf(stderr, "%s", ferr); 
		goto out;
	}

	if (!init_vector(iv, AES_BLOCK_SIZE)) {
		fprintf(stderr, "%s", ferr);
		goto out;
	}

	aes_key_setup(keye, key_schedulee, keysize);
	aes_key_setup(keyi, key_schedulei, keysize);
	int res = 0;

	if (new) {
		memset(ainfo, 0, sizeof(struct Archive));
		err = fwrite(ainfo, 1, sizeof(struct Archive), archive);
		if (err != sizeof(struct Archive)) {
			fprintf(stderr, "%s", ferr);
			goto out;        
		}

		if ((err = fseek(archive, sizeof(struct Archive), SEEK_SET)) < 0) {
			fprintf(stderr, "%s", ferr);
			goto out;    
		}
	} else
		res = validate_hash(keyi, SHA256_BLOCK_SIZE, archive);

	if (res) {
		goto out;
	}

	/* Append to end of archive */
	if ((err = fseek(archive, 0, SEEK_END)) < 0) {
		fprintf(stderr, "%s", ferr);
		goto out;
	}

	long int rewrite = ftell(archive);
	if (rewrite < 0) {
		fprintf(stderr, "%s", ferr);
		goto out; 
	}

	memset(finfo, 0, sizeof(struct File));
	err = fwrite(finfo, 1, sizeof(struct File), archive);
	if (err != sizeof(struct File)) {
		fprintf(stderr, "%s", ferr);
		goto out;
	}    

	err = fwrite(iv, 1, AES_BLOCK_SIZE, archive);
	if (err != AES_BLOCK_SIZE) {
		fprintf(stderr, "%s", ferr);
		goto out;
	}    

	fsize += AES_BLOCK_SIZE;

	memset(plaintext, 0, AES_BLOCK_SIZE);
	while((plen = fread(&plaintext, 1, AES_BLOCK_SIZE, file))) {
		uncrypt_size += plen;
		fsize += AES_BLOCK_SIZE;
		padding = aes_encrypt_cbc_block(plaintext, plen, enc_buf,
				key_schedulee, keysize, iv);

		if (padding < 0) {
			stat = '0';
			fprintf(stderr, "%s: Error reading in file, %s", fpath,
					"please try again.\n");
			break;
		}

		memset(iv, 0, AES_BLOCK_SIZE);
		memcpy(iv, enc_buf, AES_BLOCK_SIZE);

		err = fwrite(enc_buf, 1, AES_BLOCK_SIZE, archive);
		if (err != AES_BLOCK_SIZE) {
			fprintf(stderr, "%s", ferr);
			goto out;        
		}

		memset(enc_buf, 0, AES_BLOCK_SIZE);
		memset(plaintext, 0, AES_BLOCK_SIZE);
	}

	/* fread returns 0 on feof and error indistinguishably... */
	if (ferror(file)) { 
		fprintf(stderr, "%s: Error reading in file, %s", fpath,
				"please try again.\n");
		stat = '0';
	}


	memset(finfo, 0, sizeof(struct File));
	strcpy(finfo->name, fpath);
	finfo->exist = stat; /* If the read-in succeeded or failed */
	finfo->size = fsize;
	finfo->unpadded = AES_BLOCK_SIZE - padding; 
	finfo->uncrypt_size = uncrypt_size;

	if ((err = fseek(archive, rewrite, SEEK_SET)) < 0) {
		fprintf(stderr, "%s", ferr);
		goto out;
	}

	if (fwrite(finfo, 1, sizeof(struct File), archive) != sizeof(struct File)) {
		fprintf(stderr, "%s", ferr);
		goto out;
	}

	/* Update the integrity hash of the archive */
	update_meta(archive, keyi, SHA256_BLOCK_SIZE);

	fprintf(stderr, "%s: Added to archive\n", fpath);

out:
	fclose(file);
	fclose(archive);
	free(iv);
	free(finfo);
	free(ainfo);

abort:
	return 0;
}

int extract_from_archive(char *apath, char *fpath, BYTE *keye, BYTE *keyi)
{
	int first, rem, elen, compromised, err;
	int  n = 0, found = 0, size = 0;
	FILE *archive = NULL, *file = NULL;
	struct File *finfo = NULL;
	int keysize = 256;
	WORD key_schedulee[60];
	WORD key_schedulei[60];

	BYTE enc_buf[AES_BLOCK_SIZE];
	BYTE *iv = NULL;
	BYTE *zero_buf = NULL;
	BYTE *plaintext = NULL;

	finfo = (struct File *)malloc(sizeof(struct File));
	if (!finfo) {
		fprintf(stderr, "%s", mallerr);
		goto abort;
	}

	iv = (BYTE *)malloc(AES_BLOCK_SIZE * sizeof(BYTE));
	if (!iv) {
		fprintf(stderr, "%s", mallerr);
		free(finfo);
		goto abort;
	}

	zero_buf = (BYTE *)malloc(1024);
	if (!zero_buf) {
		fprintf(stderr, "%s", mallerr);
		free(iv);
		free(finfo);
		goto abort;
	}

	plaintext = (BYTE *)malloc(AES_BLOCK_SIZE * sizeof(BYTE));
	if (!plaintext) {
		fprintf(stderr, "%s", mallerr);
		free(zero_buf);
		free(iv);
		free(finfo);
		goto abort;
	}

	archive = validate_path(apath);
	if (!archive) {
		fprintf(stderr, "%s: Archive does not exist.\n", apath);
		goto out;	
	}

	file = validate_path(fpath);
	if (file) {
		fclose(archive);
		fprintf(stderr, "%s: File exists. Cannot extract to specified path.\n", fpath);
		goto fclose;
	}

	aes_key_setup(keye, key_schedulee, 256);
	aes_key_setup(keyi, key_schedulei, 256);

	compromised = validate_hash(keyi, SHA256_BLOCK_SIZE, archive);
	if (compromised) {
		fclose(archive);
		goto out;
	}

	/* Locate file for extraction... */
	if ((err = fseek(archive, sizeof(struct Archive), SEEK_SET))) {
		fprintf(stderr, "%s", ferr);
		fclose(archive);
		goto out;
	}

	memset((char *)zero_buf, 0, 1024);

	while((n = fread(finfo, 1, sizeof(struct File), archive))) {
		if (n != sizeof(struct File)) {
			fprintf(stderr, "%s", ferr);
			fclose(archive);
			goto out;
		}

		if (strequal(finfo->name, fpath) && finfo->exist == '1') {
			found = 1;
			break;  
		}
		if ((err = fseek(archive, finfo->size, SEEK_CUR)) < 0) {
			fprintf(stderr, "%s", ferr);
			fclose(archive);
			goto out;
		}

		if (!found) {
			fprintf(stderr, "%s: No such file in archive.\n", fpath);
			fclose(archive);
			goto out;
		}
	}
	/* Make zero padded file for decrypting in reverse */   
	file = finit(fpath);
	if (!file) {
		fprintf(stderr, "%s: Failed to create file for extracting.\n", fpath);
		fclose(archive);
		goto out;
	}

	rem = finfo->uncrypt_size;
	while(rem > 0) {
		size = (rem < AES_BLOCK_SIZE) ? rem : AES_BLOCK_SIZE;
		err = fwrite(zero_buf, size, 1, file); 
		if (err != 1) {
			fprintf(stderr, "%s", ferr);
			fclose(archive);
			goto out;
		}
		rem -= AES_BLOCK_SIZE;
	}

	rem = finfo->size - AES_BLOCK_SIZE; /* discount 16 bytes for iv.. */

	/* Decrypt in reverse: begin with nth IV and cipher */
	if ((err = fseek(file, finfo->uncrypt_size - (AES_BLOCK_SIZE - finfo->unpadded),
					SEEK_SET)) < 0) {
		fprintf(stderr, "%s", ferr);
		fclose(archive);
		fclose(file);
	}

	if ((err = fseek(archive, finfo->size, SEEK_CUR)) < 0) {
		fprintf(stderr, "%s", ferr);
		fclose(archive);
		fclose(file);
		goto out;
	}

	if ((err = fseek(archive, -2 * sizeof(enc_buf), SEEK_CUR)) < 0) {
		fprintf(stderr, "%s", ferr);
		fclose(archive);
		fclose(file);
		goto out;

	}

	first = 1;
	while((elen = fread(iv, 1, AES_BLOCK_SIZE, archive))) {
		err = fread(&enc_buf, 1, AES_BLOCK_SIZE, archive);
		if (elen != AES_BLOCK_SIZE || err != AES_BLOCK_SIZE) {
			fprintf(stderr, "%s", ferr);
			fclose(archive);
			fclose(file);
			goto out;
		}

		aes_decrypt_cbc_block(enc_buf, elen, plaintext, key_schedulee, keysize, iv);

		size = first ? AES_BLOCK_SIZE - finfo->unpadded : AES_BLOCK_SIZE;
		first = 0;

		err = fwrite(plaintext, size, 1, file);
		if (err != 1) {
			fprintf(stderr, "%s", ferr);
			fclose(archive);
			fclose(file);
			goto out;

		}

		rem -= AES_BLOCK_SIZE;
		if (rem <= 0)
			break; 

		/* Walk back to decrypt + write preceding blocks */
		if (( err = fseek(file, -1 * (AES_BLOCK_SIZE + size), SEEK_CUR)) < 0) {
			fprintf(stderr, "%s", ferr);
			fclose(archive);
			fclose(file);
			goto out;
		}
		if (( err = fseek(archive, -3 * AES_BLOCK_SIZE, SEEK_CUR)) < 0) {
			fprintf(stderr, "%s", ferr);
			fclose(archive);
			fclose(file);
			goto out; 
		}

		/* Clear all buffers */
		memset(enc_buf, 0, AES_BLOCK_SIZE);
		memset(plaintext, 0, AES_BLOCK_SIZE);
	}   

	if (found)
		fprintf(stderr, "%s: Extracted from archive.\n", fpath);


	fclose(archive);

fclose:
	fclose(file);

out:
	free(plaintext);
	free(zero_buf);
	free(iv);
	free(finfo);

abort:
	return 0;
}

/**
 * Iterate through the archive (fseek size of each file) 
 * and if the struct indicates "not deleted" return element
 */
int list_archive(char *apath)
{

	int n, err;
	FILE *archive = NULL;
	struct File *finfo = (struct File *)malloc(sizeof(struct File));

	if (!finfo) {
		fprintf(stderr, "%s", mallerr);
		goto abort;
	}
	archive = validate_path(apath);
	if (!archive) {
		fprintf(stderr, "%s: Archive does not exist.\n", apath);
		free(finfo);
		goto abort;
	}

	if ((err = fseek(archive, sizeof(struct Archive), SEEK_SET)) < 0) {
		fprintf(stderr, "%s", ferr);
		goto out;
	}

	while((n = fread(finfo, 1, sizeof(struct File), archive))) {
		if (n !=  sizeof(struct File)) {
			fprintf(stderr, "%s", ferr);
			goto out;
		}    
		if (finfo->exist == '1')
			printf("%s\n", finfo->name);

		if ((err = fseek(archive, finfo->size, SEEK_CUR)) < 0) {
			fprintf(stderr, "%s", ferr);
			goto out;
		}
	}

out:
	free(finfo);
	fclose(archive);

abort:
	return 0;
}

/**
 * Following the standards of existing databases
 * Only soft-delete is implemented
 */
int delete_from_archive(char *apath, char *fpath, BYTE *keye, BYTE *keyi)
{ 
	int n = 0, found = 0, err;
	FILE *archive = NULL;
	struct File *finfo = NULL;
	int compromised;
	WORD key_schedulee[60];
	WORD key_schedulei[60];

	finfo = (struct File *)malloc(sizeof(struct File));
	if (!finfo) {
		fprintf(stderr, "%s", mallerr);
		goto abort;
	}

	archive = validate_path(apath);
	if (!archive) {
		fprintf(stderr, "%s: Archive does not exist.\n", apath);
		free(finfo);
		goto abort;
	}


	aes_key_setup(keye, key_schedulee, 256);
	aes_key_setup(keyi, key_schedulei, 256);

	compromised = validate_hash(keyi, SHA256_BLOCK_SIZE, archive);
	if (compromised)
		goto out;

	if ((err = fseek(archive, sizeof(struct Archive), SEEK_SET)) < 0) {
		fprintf(stderr, "%s", ferr);
		goto out;
	}

	while((n = fread(finfo, 1, sizeof(struct File), archive))) {
		if (n != sizeof(struct File)) {
			fprintf(stderr, "%s", ferr);
			goto out;
		}

		if (strequal(finfo->name, fpath) && finfo->exist == '1') {
			finfo->exist = '0';
			found = 1;
			if ((err = fseek(archive, -1 *  sizeof(struct File), SEEK_CUR)) < 0) {
				fprintf(stderr, "%s", ferr);
				goto out;
			}

			err = fwrite(finfo, 1, sizeof(struct File), archive);
			if (err != sizeof(struct File)) {
				fprintf(stderr, "%s", ferr);
				goto out;
			}
			break;
		}

		if ((err = fseek(archive, finfo->size, SEEK_CUR)) < 0) {
			fprintf(stderr, "%s", ferr);
			goto out;
		}
	}

	if (found) {
		fprintf(stderr, "%s: Deleted from archive.\n", fpath);

		/* Update the integrity hash of the archive */
		update_meta(archive, keyi, SHA256_BLOCK_SIZE);

	} else
		fprintf(stderr, "%s: File not found in archive.\n", fpath);

out:
	free(finfo);
	fclose(archive);

abort:
	return 0;
}

int main(int argc, char **argv)
{
	char *command = NULL;
	char *archive = NULL;
	char *file = NULL;
	char *password = NULL;
	BYTE *ciphere = NULL;
	BYTE *cipheri = NULL;
	BYTE *cipher2 = NULL;
	BYTE *cipher3 = NULL;

	char add[] = "add";
	char list[] = "list";
	char extract[] = "extract";
	char delete[] = "delete";
	char pflag[] = "-p";
	int fc = 0, i = 0;

	if (argc < 2)
		goto abort;

	for (i = 0; i < argc; i++) {
		if (strlen(argv[i]) > 100) {
			fprintf(stderr, "The maximum accepted argument size is 100 per argument.\n");
			print_usage();
			goto abort;
		}    
	}    

	command = argv[1];

	/**
	  if (mlockall(MCL_CURRENT | MCL_FUTURE )) {
	  fprintf(stderr, "mlock failed. Archive is in an %s",
	  "insecure environemnt. Aborting...");
	  goto abort;
	  }
	 **/

	/* Not secure commands parsed */	
	if (strequal(command, list)) { 
		if (argc != 3) {
			print_usage();
			goto out;
		}
		archive = argv[2];
		list_archive(archive);
		goto out;
	}

	/* parse password */
	if (argc < 4) {
		print_usage();
		goto out;
	}

	if (!(strequal(pflag, argv[2]))) {
		archive = argv[2];
		file = argv[3];
		fc = 3;
		password = getpass("Enter passphrase: ");	
	} else if (strequal(pflag, argv[2]) && argc > 5) {
		password = argv[3];
		archive = argv[4];
		/* files = argv[5] onward... */
		file = argv[5];
		fc = 5;
	} else {
		print_usage();
		goto out;
	}

	ciphere = (BYTE *)malloc(strlen(password) + 2);
	cipheri = (BYTE *)malloc(strlen(password) + 2);
	if (!ciphere) {
		fprintf(stderr, "%s", mallerr);
		/* Zero out the password ASAP
		 * force compiler to perform action by printing 
		 */
		for (i = 0; i < strlen(password); i++)
			password[i] = 0;

		fprintf(stderr, "Aborting Encrypted File Store%s\n", password);

		if (!(strequal(pflag, argv[2])))
			free(password);
		goto abort;
	}
	if (!cipheri) {
		free(ciphere);
		fprintf(stderr, "%s", mallerr);
		/* Zero out the password ASAP
		 * force compiler to perform 
		 * action by printing 
		 */
		for (i = 0; i < strlen(password); i++)
			password[i] = 0;

		fprintf(stderr, "Aborting Encrypted File Store%s\n", password);

		if (!(strequal(pflag, argv[2])))
			free(password);
		goto abort;
	}

	cipher2 = ciphere;
	cipher3 = cipheri;

	memcpy(ciphere, password, strlen(password) + 1);
	memcpy(cipheri, password, strlen(password) + 1);

	strncat((char *)ciphere, "e", 2);
	strncat((char *)cipheri, "i", 2);

	ciphere = convert_pass(ciphere, strlen(password) + 1);
	cipheri = convert_pass(cipheri, strlen(password) + 1);
	if (!ciphere || !cipheri) {
		free(cipher2);
		free(cipher3);

		/* Zero out the password ASAP
		 * force compiler to perform action by printing 
		 */
		for (i = 0; i < strlen(password); i++)
			password[i] = 0;

		fprintf(stderr, "Aborting Encrypted File Store%s\n", password);

		if (!(strequal(pflag, argv[2])))
			free(password);

		goto out;
	}


	free(cipher2);
	free(cipher3);

	/* Zero out the password ASAP, force compiler to perform action by printing */
	for (i = 0; i < strlen(password); i++)
		password[i] = 0;

	fprintf(stderr, "Welcome to your Encrypted File Store%s\n", password);

	if (!(strequal(pflag, argv[2])))
		free(password);

	while (fc < argc) {

		if (strequal(command, add))
			add_to_archive(archive, file, ciphere, cipheri);
		else if (strequal(command, list))
			list_archive(archive);
		else if (strequal(command, extract))
			extract_from_archive(archive, file, ciphere, cipheri);
		else if (strequal(command, delete))
			delete_from_archive(archive, file, ciphere, cipheri);
		else {
			print_usage();
		}

		fc ++;
		file = argv[fc];
	}

out:
	free(ciphere);
	free(cipheri);

abort:

	/**
	  munlockall();
	 **/
	return 0;
}
