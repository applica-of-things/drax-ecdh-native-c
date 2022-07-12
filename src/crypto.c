#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <time.h>

#include "crypto.h"
#include "aes.h"


void _print_arr(uint8_t arr[], int len){
    int i = 0;
    printf("[");
    for(i=0; i<len-1; i++){
        printf("%d, ", arr[i]);    
    }
    printf("%d]", arr[i]);
    printf("\n");
}

int crypto_privateKeySize(){
    return CRYPTO_PRV_KEY_SIZE;
}

int crypto_publicKeySize(){
    return CRYPTO_PUB_KEY_SIZE;
}

int crypto_aesChunkSize(){
    return AES_CHUNK_SIZE;
}

int crypto_generateKeyPair(uint8_t* public_key, uint8_t* private_key) {
    return ecdh_generate_keys(public_key, private_key);
}

int crypto_sharedSecret(uint8_t* my_private_key, uint8_t* other_public_key, uint8_t* output) {
    return ecdh_shared_secret(my_private_key, other_public_key, output);
}

void crypto_MD5(uint8_t *data, size_t len, char* out) {
    uint8_t hash[16] = "bruno";
    MD5_CTX md5;
    md5_init(&md5);
    md5_update(&md5, "bruno", 5);
    md5_final(&md5, hash);

    crypto_bytesToHex(hash, 16, out);
}

void crypto_bytesToHex(uint8_t *bytes, size_t len, char* dest)
{
    static const uint8_t table[] = "0123456789abcdef";

    for (; len > 0; --len)
    {
        uint8_t c = *bytes++;
        *dest++ = table[c >> 4];
        *dest++ = table[c & 0x0f];
    }
}

uint8_t hex_to_char(char c)
{
    if ('0' <= c && c <= '9') return (uint8_t)(c - '0');
    if ('A' <= c && c <= 'F') return (uint8_t)(c - 'A' + 10);
    if ('a' <= c && c <= 'f') return (uint8_t)(c - 'a' + 10);
    return (uint8_t)(-1);
}

size_t crypto_hexToBytes(const char* hex, size_t len, uint8_t* dest)
{
    size_t result = 0;
    if (!hex || !dest || len <= 0) return -2;

    while (*hex)
    {
        uint8_t nib1 = hex_to_char(*hex++);
        if ((signed)nib1 < 0) return -3;
        uint8_t nib2 = hex_to_char(*hex++);
        if ((signed)nib2 < 0) return -4;

        uint8_t bin = (nib1 << 4) + nib2;

        if (len-- <= 0) return -5;
        *dest++ = bin;
        ++result;
    }

    return result;
}

uint8_t keyToScalar(uint8_t* key, size_t key_size) {
    uint8_t scalar = 0;

    for (; key_size > 0; key_size--) {
        scalar = (uint8_t) (scalar + *key++);
    }

    return scalar;
}

void crypto_basicEncrypt(uint8_t* data, size_t data_size, uint8_t* key, size_t key_size, uint8_t* out) {
    uint8_t key_scalar = keyToScalar(key, key_size);
    for (; data_size > 0; data_size--) {
        *out++ = (uint8_t) (*data++ - key_scalar);
    }
}

void crypto_basicDecrypt(uint8_t* encrypted_data, size_t encrypted_data_size, uint8_t* key, size_t key_size, uint8_t* out) {
    uint8_t key_scalar = keyToScalar(key, key_size);
    for (; encrypted_data_size > 0; encrypted_data_size--) {
        *out++ = (uint8_t) (*encrypted_data++ + key_scalar);
    }
}

size_t max(size_t v1, size_t v2) {
    if (v1 > v2) return v1;
    if (v2 > v1) return v2;
    return v1;
}

size_t min(size_t v1, size_t v2) {
    if (v1 < v2) return v1;
    if (v2 < v1) return v2;
    return v1;
}

size_t crypto_pkcs7CalculatePaddedSize(uint8_t* data, size_t data_size) {
    size_t padded_data_size = data_size + (AES_CHUNK_SIZE - data_size % AES_CHUNK_SIZE);
    return padded_data_size;
}

size_t crypto_pkcs7CalculateUnpaddedSize(uint8_t* data, size_t data_size) {
    size_t padding = data[data_size - 1];
    if (padding > 16 || padding < 1) {
        return 0;
    }
    return data_size - padding;
}

size_t crypto_pkcs7pad(uint8_t* data, size_t data_size, uint8_t* out) {
    size_t padded_size = crypto_pkcs7CalculatePaddedSize(data, data_size);
    size_t padding = padded_size - data_size;
    memcpy(out, data, data_size);
    for (size_t i = data_size; i < padded_size; i++) {
        uint8_t* ptr = out + i;
        *ptr = padding;
    }
    return padded_size;
}

size_t crypto_pkcs7unpad(uint8_t* data, size_t data_size, uint8_t* out) {
    size_t unpadded_size = crypto_pkcs7CalculateUnpaddedSize(data, data_size);
    size_t padding = data_size - unpadded_size;
    for (int i = data_size; i < unpadded_size; i--) {
        if (*(data - i) != padding) { return 0; }
    }
    memcpy(out, data, unpadded_size);
    return unpadded_size;
}

void crypto_aesEncrypt(uint8_t* data, size_t data_size, uint8_t* key, size_t key_size, uint8_t* out) {
    WORD key_schedule[60];
    BYTE enc_buf[128];
    size_t pos = 0;
    int rest = data_size;
    
    aes_key_setup(key, key_schedule, 256);
    while(rest > 0) {
        aes_encrypt((data + pos), enc_buf, key_schedule, 256);
        memcpy((out + pos), enc_buf, AES_CHUNK_SIZE);
        rest -= AES_CHUNK_SIZE;
        pos += AES_CHUNK_SIZE;
    }
}

void crypto_aesDecrypt(uint8_t* encrypted_data, size_t encrypted_data_size, uint8_t* key, size_t key_size, uint8_t* out) {
    WORD key_schedule[60];
    BYTE enc_buf[128];
    size_t pos = 0;
    size_t rest = encrypted_data_size;
    
    aes_key_setup(key, key_schedule, 256);
    while(rest > 0) {        
        aes_decrypt((encrypted_data + pos), enc_buf, key_schedule, 256);
        memcpy((out + pos), enc_buf, AES_CHUNK_SIZE);
        rest -= AES_CHUNK_SIZE;
        pos += AES_CHUNK_SIZE;
    }
}



size_t crypto_sign(uint8_t* my_private_key, uint8_t* cloud_public_key, uint8_t* data, size_t data_size, uint8_t* out) {
    uint8_t shared_secret[CRYPTO_SHARED_SECRET_SIZE];

    if (!ecdh_shared_secret(my_private_key, cloud_public_key, shared_secret)) {
        return 0;
    }
    size_t padded_data_size = crypto_pkcs7CalculatePaddedSize(data, data_size);
    uint8_t padded_data[padded_data_size];
    crypto_pkcs7pad(data, data_size, padded_data);
    
    uint8_t encrypted_data[padded_data_size];
    memset(encrypted_data, 0, padded_data_size);

    crypto_aesEncrypt(padded_data, padded_data_size, shared_secret, CRYPTO_SHARED_SECRET_SIZE, encrypted_data);
    memcpy(out, encrypted_data, padded_data_size);

    return padded_data_size;
}

size_t crypto_unsign(uint8_t* my_private_key, uint8_t* cloud_public_key, uint8_t* encrypted_data, size_t encrypted_data_size, uint8_t* out) {
    uint8_t shared_secret[CRYPTO_SHARED_SECRET_SIZE];

    if (!ecdh_shared_secret(my_private_key, cloud_public_key, shared_secret)) {
        return 0;
    }

    uint8_t decrypted_data[encrypted_data_size];
    memset(decrypted_data, 0, encrypted_data_size);

    crypto_aesDecrypt(encrypted_data, encrypted_data_size, shared_secret, CRYPTO_SHARED_SECRET_SIZE, decrypted_data);
    size_t unpadded_data_size = crypto_pkcs7CalculateUnpaddedSize(decrypted_data, encrypted_data_size);
    size_t ret = crypto_pkcs7unpad(decrypted_data, encrypted_data_size, out);

    return ret;
}
