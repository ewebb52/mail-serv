#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "sha256.h"
#include "aes.h"

const int blocksize = 16;
const int keysize = SHA256_BLOCK_SIZE * 8;
	
// sizeof struct 50 bytes
struct filemeta {
	char filename[40];
	long int filesize;
	short padsize;
};
// sizeof struct 56 bytes
struct ivrec {
	char filename[40];
	int iv_block[16];
};

void hash(SHA256_CTX *ctx, BYTE *password, BYTE *key, int count) {
	sha256_init(ctx);
	for (int i = 0; i < count; i++) {
		sha256_update(ctx, password, strlen((char *) password));
	}
	sha256_final(ctx, key);
}

int findfile(FILE *archive, char *filename) {
        struct filemeta *metadata = malloc(sizeof(struct filemeta));
        int itemsread = fread(metadata, sizeof(struct filemeta), 1, archive);
        while (strcmp(metadata->filename, filename) && itemsread != 0) {
                fseek(archive, metadata->filesize + metadata->padsize, SEEK_CUR);
       //       (*bytesread) += sizeof(struct filemeta) + metadata->filesize + metadata->padsize;
                free(metadata);
                metadata = malloc(sizeof(struct filemeta));
                itemsread = fread(metadata, sizeof(struct filemeta), 1, archive);
        }
	free(metadata);
        if (!itemsread) {
                return 0;
        }
        return 1;
}

void authenticate(FILE *archive, long int archivesize, BYTE *key_hmac) {
	SHA256_CTX aux;
	SHA256_CTX hmac;
	BYTE ipad[SHA256_BLOCK_SIZE];
	BYTE opad[SHA256_BLOCK_SIZE];
	for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
		ipad[i] = 0x36;
		opad[i] = 0x5C;
	}
	BYTE *ciphertext = malloc(archivesize);
	fread(ciphertext, archivesize, 1, archive);
	BYTE ipadxorkey[SHA256_BLOCK_SIZE];
	BYTE opadxorkey[SHA256_BLOCK_SIZE];
	for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
		ipadxorkey[i] = ipad[i] ^ key_hmac[i];
		opadxorkey[i] = opad[i] ^ key_hmac[i];
	}
	BYTE *keycatcipher = malloc(archivesize + SHA256_BLOCK_SIZE + 1);
	memcpy(keycatcipher, ipadxorkey, SHA256_BLOCK_SIZE);
	memcpy(keycatcipher + SHA256_BLOCK_SIZE, ciphertext, archivesize);
	keycatcipher[archivesize + SHA256_BLOCK_SIZE] = '\0';
	BYTE auxhash[SHA256_BLOCK_SIZE];
	hash(&aux, keycatcipher, auxhash, 1000);

	BYTE *tohash = malloc(2*SHA256_BLOCK_SIZE + 1);
	memcpy(tohash, opadxorkey, SHA256_BLOCK_SIZE);
	memcpy(tohash + SHA256_BLOCK_SIZE, auxhash, SHA256_BLOCK_SIZE);
	tohash[2*SHA256_BLOCK_SIZE] = '\0';
	BYTE hmac_code[SHA256_BLOCK_SIZE];
	hash(&hmac, tohash, hmac_code, 1000);
	
	fwrite(hmac_code, sizeof(hmac_code), 1, archive);
	
	free(ciphertext);
	free(keycatcipher);
	free(tohash);
}

short integrity_check(FILE *archive, long int archivesize, BYTE *key_hmac, BYTE *goodhash) {
	// code = MAC(k, ciphertext)
	SHA256_CTX aux;
	SHA256_CTX hmac;
	BYTE ipad[SHA256_BLOCK_SIZE];
	BYTE opad[SHA256_BLOCK_SIZE];
	for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
		ipad[i] = 0x36;
		opad[i] = 0x5C;
	}
	BYTE *ciphertext = malloc(archivesize);
	fread(ciphertext, archivesize, 1, archive);
	BYTE ipadxorkey[SHA256_BLOCK_SIZE];
	BYTE opadxorkey[SHA256_BLOCK_SIZE];
	for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
		ipadxorkey[i] = ipad[i] ^ key_hmac[i];
		opadxorkey[i] = opad[i] ^ key_hmac[i];
	}
	BYTE *keycatcipher = malloc(archivesize + SHA256_BLOCK_SIZE + 1);
	keycatcipher[archivesize + SHA256_BLOCK_SIZE] = '\0';
	memcpy(keycatcipher, ipadxorkey, SHA256_BLOCK_SIZE);
	memcpy(keycatcipher + SHA256_BLOCK_SIZE, ciphertext, archivesize);
	BYTE auxhash[SHA256_BLOCK_SIZE];
	hash(&aux, keycatcipher, auxhash, 1000);

	BYTE *tohash = malloc(2*SHA256_BLOCK_SIZE + 1);
	memcpy(tohash, opadxorkey, SHA256_BLOCK_SIZE);
	memcpy(tohash + SHA256_BLOCK_SIZE, auxhash, SHA256_BLOCK_SIZE);
	tohash[2*SHA256_BLOCK_SIZE] = '\0';
	BYTE hmac_code[SHA256_BLOCK_SIZE];
	hash(&hmac, tohash, hmac_code, 1000);
	
	// if corrupted
	// if goodhash != currhash return authentication failed 
	if (memcmp(goodhash, hmac_code, SHA256_BLOCK_SIZE)) {
		free(ciphertext);
		free(keycatcipher);
		free(tohash);
		return 0;
	}
	else {
		free(ciphertext);
		free(keycatcipher);
		free(tohash);
		return 1;
	}
}

void cstore_encrypt(FILE *archive, FILE *fp, char *filename, int filesize, short padsize, WORD *key_schedule, BYTE *iv) {
	BYTE *block = malloc(blocksize);
	BYTE *prevblock = malloc(blocksize);
	BYTE *xorblock;
	BYTE *cblock;
	for (int i = 0; i < blocksize; i++) {
		prevblock[i] = iv[i];
	}
	int bytesread = 0;
	while ((bytesread = fread(block, 1, blocksize, fp)) != 0) {
		xorblock = malloc(blocksize);
		for (int i = 0; i < bytesread; i++) {
			xorblock[i] = block[i] ^ prevblock[i];
		}
		int j = bytesread;
		while (j < blocksize) {
			xorblock[j] = 0;
			j++;
		}
		free(prevblock);
		cblock = calloc(1, blocksize);
		if (cblock == NULL) {
			perror("malloc returned null");
			exit(1);
		}		
		aes_encrypt(xorblock, cblock, key_schedule, keysize);

		free(xorblock);
		fwrite(cblock, blocksize, 1, archive);	

		prevblock = malloc(blocksize);
		for (int i = 0; i < bytesread; i++) {
			prevblock[i] = cblock[i];
		}
		free(cblock);
		free(block);
		block = malloc(blocksize);
		if (block == NULL) {
			perror("malloc returned null");
        		exit(1);
		}
	}
	free(prevblock);
	free(block);
}
		
void cstore_decrypt(FILE *archive, FILE *fp, char *filename, int filesize, short padsize, WORD *key_schedule, BYTE *iv) {
	BYTE *cblock = malloc(blocksize);

	BYTE *prevblock = malloc(blocksize);
	for (int i = 0; i < blocksize; i++) {
		prevblock[i] = iv[i];
	}
	BYTE *xorblock;
	BYTE *block = malloc(blocksize);
			
	int bytesread = 0;
	FILE *newfile = fopen("newfile", "wb");
	int itemsread = fread(cblock, blocksize, 1, archive);
	while (itemsread < (filesize + padsize)/blocksize) {
		aes_decrypt(cblock, block, key_schedule, keysize);
		xorblock = malloc(blocksize);
		for (int i = 0; i < blocksize; i++) {
			xorblock[i] = block[i] ^ prevblock[i];
		}
		fwrite(xorblock, blocksize, 1, newfile);
		free(xorblock);
		free(block);
		free(prevblock);
		prevblock = malloc(blocksize);
		for (int i = 0; i < blocksize; i++) {
			prevblock[i] = cblock[i];
		}
		free(cblock);	
	
		cblock = malloc(blocksize);
		block = malloc(blocksize);
		itemsread += fread(cblock, blocksize, 1, archive);
	}
	aes_decrypt(cblock, block, key_schedule, keysize);
	xorblock = malloc(blocksize);
	for (int i = 0; i < blocksize; i++) {
		xorblock[i] = block[i] ^ prevblock[i];
	}
	fwrite(xorblock, blocksize, 1, newfile);
	free(xorblock);

	fclose(newfile);
	free(block);
	free(cblock);
	free(prevblock);
	newfile = fopen("newfile", "rb");
	BYTE *newblock = malloc(blocksize);
	bytesread += fread(newblock, blocksize, 1, newfile);
	fwrite(newblock, blocksize, 1, fp);
	free(newblock);
	newblock = malloc(blocksize);
	while (bytesread < filesize/blocksize) {
		bytesread += fread(newblock, blocksize, 1, newfile);
		fwrite(newblock, blocksize, 1, fp);
		free(newblock);
		newblock = malloc(blocksize);
	}
	fread(newblock, blocksize, 1, newfile);
	fwrite(newblock, blocksize - padsize, 1, fp);
	free(newblock);
	fclose(newfile);
}

int main(int argc, char **argv) {
	if (argc < 3) {
		return 1;
	}
	if (argc == 3) {
		if (strcmp(argv[1], "list")) {
			printf("please enter a valid command");
		}
		else {
			const char *archivename = argv[2];
			FILE *archive = fopen(archivename, "rb");
			struct filemeta *metadata = malloc(sizeof(struct filemeta));

			printf("Files in archive %s:\n", archivename);
			while (fread(metadata, sizeof(struct filemeta), 1, archive)) {
				printf("%s, %lu bytes\n", metadata->filename, metadata->filesize);
				fseek(archive, metadata->filesize + metadata->padsize, SEEK_CUR);
				free(metadata);
				metadata = malloc(sizeof(struct filemeta));
			}
			free(metadata);
			fclose(archive);
		}
		return 0;
	}
	else {
		const char *command = argv[1];
		char password[64];
		char *archivename;
		char *filename;
	
		SHA256_CTX ctx;
		SHA256_CTX ctx_hmac;
		BYTE key[SHA256_BLOCK_SIZE];
		BYTE key_hmac[SHA256_BLOCK_SIZE];
		WORD key_schedule[60];
		WORD key_schedule_hmac[60];

		if (!strcmp(argv[2], "-p")) {
			strcpy(password, argv[3]);
			archivename = argv[4];
			argv += 5;
		}
		else {
			printf("Enter password:\n");
			scanf("%s", password);	
			archivename = argv[2];
			argv += 3;
		}
		// convert password to cryptographic key
		hash(&ctx, (BYTE *) password, key, 10000);
		hash(&ctx_hmac, (BYTE *) password, key_hmac, 10050);

		aes_key_setup(key, key_schedule, keysize);
		aes_key_setup(key_hmac, key_schedule_hmac, keysize);
		
		while (*argv != NULL) {
			filename = *argv;
			if (!strcmp(command, "add")) {
				if (access(filename, F_OK) == -1) {
                                        printf("file not present\n");
					return 0;
                                }
				
				// if new archive, don't need to authenticate.
				// else, authenticate password first
				FILE *archive;
				long int archivesize;
				if (access(archivename, F_OK) == -1) {
					archivesize = 0;
				}
				else {
					archive = fopen(archivename, "rb");
					fseek(archive, 0L, SEEK_END);
					archivesize = ftell(archive);
					fclose(archive);
				}	
				if (archivesize != 0) {
					archive = fopen(archivename, "rb");
					fseek(archive, archivesize - SHA256_BLOCK_SIZE, SEEK_SET);
					BYTE *goodhash = malloc(SHA256_BLOCK_SIZE);
					fread(goodhash, SHA256_BLOCK_SIZE, 1, archive);
					fseek(archive, 0L, SEEK_SET);
					// authenticate
					if (!integrity_check(archive, archivesize - SHA256_BLOCK_SIZE, key_hmac, goodhash)) {
						fclose(archive);
						free(goodhash);
						printf("Your archive has no integrity.\n");
						return 0;
					}
					fclose(archive);
					free(goodhash);
				//	printf("Your archive has integrity. It will bring honour to us all!\n");
				}
				char padsize;
				FILE *fp = fopen(filename, "r+b");	
				fseek(fp, 0L, SEEK_END);
				// get filesize 
				long int filesize = ftell(fp);
				if (!(filesize % blocksize)) {
					padsize = 0;
				}
				else {
					padsize = blocksize - filesize % blocksize;
				}
				FILE *random = fopen("/dev/urandom", "rb");
				int k = padsize;
				while (k > 0) {
					char randomchar;
					fread(&randomchar, sizeof(char), 1, random);
					fwrite(&randomchar, sizeof(char), 1, fp);
					k--;
				}
				fclose(random);
				fseek(fp, 0L, SEEK_SET);
				fclose(fp);
				FILE *iv = fopen("iv", "ab");
				random = fopen("/dev/urandom", "rb");
				struct ivrec *curiv = calloc(1, sizeof(struct ivrec));
				strcpy(curiv->filename, filename);	
				BYTE *ivblock = malloc(blocksize);
		
				for (int i = 0; i < blocksize; i++) {
					char randomchar;
					fread(&randomchar, sizeof(char), 1, random);
					curiv->iv_block[i] = randomchar;
					ivblock[i] = randomchar;
				}
				fwrite(curiv, sizeof(struct ivrec), 1, iv);
				fclose(random);
				fclose(iv);
				free(curiv);
				struct filemeta *metadata = calloc(1, sizeof(struct filemeta));
				strcpy(metadata->filename, filename);
				metadata->filesize = filesize;
				metadata->padsize = padsize;
				
				if (archivesize) {
					archive = fopen(archivename, "rb");
					if (findfile(archive, filename)) {
						printf("file already present.\n");
						free(metadata);
						free(ivblock);
						return 0;
					}
					fclose(archive);
					archive = fopen(archivename, "rb");
					fseek(archive, 0L, SEEK_END);
					archivesize = ftell(archive);
					fclose(archive);

					FILE *copy = fopen("archivecopy", "wb");
					BYTE  *temp = malloc(archivesize - SHA256_BLOCK_SIZE);				
					
					archive = fopen(archivename, "rb");			
					fread(temp, archivesize - SHA256_BLOCK_SIZE, 1, archive);
					fwrite(temp, archivesize - SHA256_BLOCK_SIZE, 1, copy);
					fclose(copy);				
					fclose(archive);
					free(temp);

					archive = fopen(archivename, "wb");
					temp = malloc(archivesize - SHA256_BLOCK_SIZE);				
					
					copy = fopen("archivecopy", "rb");			
					fread(temp, archivesize - SHA256_BLOCK_SIZE, 1, copy);
					fwrite(temp, archivesize - SHA256_BLOCK_SIZE, 1, archive);
					fclose(archive);				
					fclose(copy);
					free(temp);				
				}

				archive = fopen(archivename, "ab");
				fwrite(metadata, sizeof(struct filemeta), 1, archive);
				free(metadata);
			
				fp = fopen(filename, "rb");
				cstore_encrypt(archive, fp, filename, filesize, padsize, key_schedule, ivblock);
				free(ivblock);
				fclose(fp);
				fclose(archive);
				// authenticate

				archive = fopen(archivename, "rb");
                                fseek(archive, 0L, SEEK_END);
                                archivesize = ftell(archive);
                                fclose(archive);
                        	
				archive = fopen(archivename, "r+b");
				authenticate(archive, archivesize, key_hmac);
				fclose(archive);

			}

			if (!strcmp(command, "extract")) {
				FILE *archive;
				long int archivesize;
				if (access(archivename, F_OK) == -1) {
					printf("the archive you are asking for doesn't exist");
					return 0;
				}
				else {
					archive = fopen(archivename, "rb");
					fseek(archive, 0L, SEEK_END);
					archivesize = ftell(archive);
					fclose(archive);

					archive = fopen(archivename, "r+b");
					fseek(archive, archivesize - SHA256_BLOCK_SIZE, SEEK_SET);
					BYTE *goodhash = malloc(SHA256_BLOCK_SIZE);
					fread(goodhash, SHA256_BLOCK_SIZE, 1, archive);
					fseek(archive, 0L, SEEK_SET);
					// authenticate
					if (!integrity_check(archive, archivesize, key_hmac, goodhash)) {
						fclose(archive);
						free(goodhash);
					//	printf("No archive-password integrity! You shall not pass.\n");
						return 0;
					}
					fclose(archive);
					free(goodhash);
					printf("your archive and password passed the integrity check. Good job.\n");
				}

				archive = fopen(archivename, "rb");
				if (!findfile(archive, filename)) {
					printf("file not present.\n");
					return 0;
				}
				fclose(archive);

				struct ivrec *curiv = malloc(sizeof(struct ivrec));
				FILE *iv = fopen("iv", "rb");

				int itemsread = fread(curiv, sizeof(struct ivrec), 1, iv);
				while (strcmp(curiv->filename, filename) && itemsread != 0) {
					free(curiv);
					curiv = malloc(sizeof(struct ivrec));
					itemsread = fread(curiv, sizeof(struct ivrec), 1, iv);
				}
				fclose(iv);

				BYTE *ivblock = malloc(blocksize);
				for (int i = 0; i < blocksize; i++) {
					ivblock[i] = (curiv->iv_block)[i];
				}
				free(curiv);
			
			
				archive = fopen(archivename, "rb");			
				FILE *fp = fopen(filename, "wb");
			
				struct filemeta *metadata = malloc(sizeof(struct filemeta));
				itemsread = fread(metadata, sizeof(struct filemeta), 1, archive);
				while (strcmp(metadata->filename, filename) && itemsread != 0) {
					fseek(archive, metadata->filesize + metadata->padsize, SEEK_CUR);
					free(metadata);
					metadata = malloc(sizeof(struct filemeta));
					itemsread = fread(metadata, sizeof(struct filemeta), 1, archive);
				}			
				cstore_decrypt(archive, fp, filename, metadata->filesize, metadata->padsize, key_schedule, ivblock);
				free(metadata);
				free(ivblock);
				fclose(fp);
				fclose(archive);
			}

			if (!strcmp(command, "delete")) {
		               if (access(archivename, F_OK) == -1) {
                                        printf("the archive you are asking for doesn't exist");
                                        return 0;
                                }

				FILE *archive = fopen(archivename, "rb");
				if (!findfile(archive, filename)) {
					printf("file not present.\n");
					return 0;
				}
				fclose(archive);

				archive = fopen(archivename, "rb");
		                fseek(archive, 0L, SEEK_END);
                                long int archivesize = ftell(archive);
				fclose(archive);

				archive = fopen(archivename, "rb");
				fseek(archive, archivesize - SHA256_BLOCK_SIZE, SEEK_SET);
				BYTE *goodhash = malloc(SHA256_BLOCK_SIZE);
				fread(goodhash, SHA256_BLOCK_SIZE, 1, archive);
				fseek(archive, 0L, SEEK_SET);
				// authenticate
				if (!integrity_check(archive, archivesize - SHA256_BLOCK_SIZE, key_hmac, goodhash)) {
					fclose(archive);
					free(goodhash);
					printf("Your archive has no integrity.\n");
					return 0;
				}
				fclose(archive);
				free(goodhash);
			//	printf("authentication accepted. proceeding to delete file\n");

				archive = fopen(archivename, "rb");
                                FILE *temparchive = fopen("temparchive", "wb");
				struct filemeta *metadata = malloc(sizeof(struct filemeta));
				int itemsread = fread(metadata, sizeof(struct filemeta), 1, archive);
				int bytesread = 0;
				while (strcmp(metadata->filename, filename) && itemsread != 0) {
					fseek(archive, metadata->filesize + metadata->padsize, SEEK_CUR);
					bytesread += sizeof(struct filemeta) + metadata->filesize + metadata->padsize;
					free(metadata);
					metadata = malloc(sizeof(struct filemeta));
					itemsread = fread(metadata, sizeof(struct filemeta), 1, archive);
				}
				fclose(archive);
				archive = fopen(archivename, "rb");
				BYTE *buffer = malloc(bytesread);
				fread(buffer, bytesread, 1, archive);
				fwrite(buffer, bytesread, 1, temparchive);
				free(buffer);
				fseek(archive, sizeof(struct filemeta) + metadata->filesize + metadata->padsize, SEEK_CUR);
				buffer = malloc(archivesize - bytesread - (metadata->filesize + metadata->padsize) - sizeof(struct filemeta));
				fread(buffer, archivesize - bytesread - (metadata->filesize + metadata->padsize) - sizeof(struct filemeta), 1, archive);
				fwrite(buffer, archivesize - bytesread - (metadata->filesize + metadata->padsize) - sizeof(struct filemeta), 1, temparchive);
				fclose(archive);
				fclose(temparchive);
				free(metadata);
				free(buffer);

				temparchive = fopen("temparchive", "rb");
                                fseek(temparchive, 0L, SEEK_END);
                                long int temparchivesize = ftell(temparchive);
                                fclose(temparchive);

				archive = fopen(archivename, "wb");
				temparchive= fopen("temparchive", "rb");
				buffer = malloc(temparchivesize - SHA256_BLOCK_SIZE);
				fread(buffer, temparchivesize - SHA256_BLOCK_SIZE, 1, temparchive);
				fwrite(buffer, temparchivesize - SHA256_BLOCK_SIZE, 1, archive);
				fclose(archive);
				fclose(temparchive);
				free(buffer);

				temparchive = fopen("temparchive", "wb");
				fclose(temparchive);

				archive = fopen(archivename, "rb");
                                fseek(archive, 0L, SEEK_END);
                                archivesize = ftell(archive);
                                fclose(archive);

				archive = fopen(archivename, "r+b");
                                authenticate(archive, archivesize, key_hmac);
                                fclose(archive);
			}

			argv++;
		}
		return 0;
	}
	return 0;
}

