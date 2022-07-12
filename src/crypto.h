#ifndef _CRYPTO_H__
#define _CRYPTO_H__

#include <stdio.h>
#include <stdint.h>

#define ECC_CURVE NIST_B163

#include "ecdh.h"
#include "md5.h"

#define CRYPTO_PUB_KEY_SIZE ECC_PUB_KEY_SIZE
#define CRYPTO_SHARED_SECRET_SIZE ECC_PUB_KEY_SIZE
#define CRYPTO_PRV_KEY_SIZE ECC_PRV_KEY_SIZE
#define CRYPTO_ID_SIZE 4
#define CRYPTO_MD5_SIZE 32
#define AES_CHUNK_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

int crypto_generateKeyPair(uint8_t* public_key, uint8_t* private_key);
int crypto_sharedSecret(uint8_t* my_private_key, uint8_t* other_public_key, uint8_t* output);
void crypto_MD5(uint8_t* data, size_t len, char* out);
void crypto_basicEncrypt(uint8_t* data, size_t len, uint8_t* key, size_t key_size, uint8_t* out);
void crypto_basicDecrypt(uint8_t* encrypted_data, size_t len, uint8_t* key, size_t key_size, uint8_t* out);
void crypto_aesEncrypt(uint8_t* data, size_t len, uint8_t* key, size_t key_size, uint8_t* out);
void crypto_aesDecrypt(uint8_t* encrypted_data, size_t len, uint8_t* key, size_t key_size, uint8_t* out);
void crypto_bytesToHex(uint8_t *bytes, size_t len, char* dest);
size_t crypto_pkcs7CalculatePaddedSize(uint8_t* data, size_t data_size);
size_t crypto_pkcs7CalculateUnpaddedSize(uint8_t* data, size_t data_size);
size_t crypto_pkcs7pad(uint8_t* data, size_t data_size, uint8_t* out);
size_t crypto_pkcs7unpad(uint8_t* data, size_t data_size, uint8_t* out);
size_t crypto_sign(uint8_t* my_private_key, uint8_t* cloud_public_key, uint8_t* data, size_t data_size, uint8_t* out);
size_t crypto_unsign(uint8_t* my_private_key, uint8_t* cloud_public_key, uint8_t* encrypted_data, size_t encrypted_data_size, uint8_t* out);
size_t crypto_hexToBytes(const char* hex, size_t len, uint8_t* dest);

#ifdef __cplusplus
}
#endif

#endif