#ifndef _CSTORE_H_
#define _CSTORE_H_

#include "../crypto-algorithms/aes.h"
#include "../crypto-algorithms/sha256.h"

struct Archive {
        BYTE hash[SHA256_BLOCK_SIZE]; 
        int clen;
};

struct File {
        char name[155];
        char exist; /* we only perform soft deletes */
        int alias; /* alias file name */
        int size; /* should this be.... u64 ? */
        int unpadded;
        int uncrypt_size;
        /* integrity check */

        /* encrypt check */
};

#endif
