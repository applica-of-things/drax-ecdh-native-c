#ifndef MD5_H
#define MD5_H

#include <stddef.h>

#define MD5_BLOCK_SIZE 16 

typedef unsigned char BYTE;
typedef unsigned int  WORD;

typedef struct {
   BYTE data[64];
   WORD datalen;
   unsigned long long bitlen;
   WORD state[4];
} MD5_CTX;

void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const BYTE data[], size_t len);
void md5_final(MD5_CTX *ctx, BYTE hash[]);

#endif
