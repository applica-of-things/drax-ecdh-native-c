#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "aes.h"
#include "crypto.h"

void _print_hex(const char* msg, uint8_t* data, size_t data_size) {
    char hex[data_size * 2 + 1];
    hex[data_size * 2] = '\0';
    crypto_bytesToHex(data, data_size, hex);
}

void createRandomData(uint8_t* data, size_t len) {
    srand(time(NULL));

    for (; len > 0; --len) {
        *data++ = rand() % 255;
    }
}

void test_crypt_decrypt() {
    printf("AES encryption - decryption test ... \n");

    uint8_t* data = "test";
    uint8_t decrypted_data[5];
    uint8_t encrypted_data[5];
    uint8_t key[8];
    createRandomData(key, 8);
    crypto_basicEncrypt(data, 4, key, 10, encrypted_data);
    encrypted_data[4] = '\0';

    crypto_basicDecrypt(encrypted_data, 4, key, 10, decrypted_data);
    decrypted_data[4] = '\0';

    assert(strcmp("test", decrypted_data) == 0);
}

void test_md5() {
    printf("md5 test...\n");

    const char* expected_hash = "e3928a3bc4be46516aa33a79bbdfdb08";

    char hash[CRYPTO_MD5_SIZE + 1];
    hash[CRYPTO_MD5_SIZE] = '\0';
    crypto_MD5("bruno", 5, hash);

    assert(strcmp(expected_hash, hash) == 0);
}

void test_padding() {
    printf("padding  test...\n");

    uint8_t* data = "Matera2019 la citta del futuro err";
    size_t data_size = 34;
    size_t padded_data_size = crypto_pkcs7CalculatePaddedSize(data, data_size);

    uint8_t out[padded_data_size];
    crypto_pkcs7pad(data, data_size, out);
}

void test_aes() {
    printf("aes test...\n");

    uint8_t* data = "bruno fortunato_";
    size_t padded_data_size = 16;
    uint8_t* padded_data[padded_data_size];
    size_t data_size = 16;
    memcpy(padded_data, data, data_size);
    uint8_t encrypted_data[padded_data_size];
    uint8_t decrypted_data[padded_data_size];

    uint8_t my_prv[CRYPTO_PRV_KEY_SIZE];
    uint8_t my_pub[CRYPTO_PUB_KEY_SIZE];
    uint8_t cloud_prv[CRYPTO_PRV_KEY_SIZE];
    uint8_t cloud_pub[CRYPTO_PUB_KEY_SIZE];
    uint8_t shared_secret[CRYPTO_SHARED_SECRET_SIZE] = "bruno fortunato_bruno fortunato_bruno fortunato_";


    createRandomData(my_prv, CRYPTO_PRV_KEY_SIZE);
    createRandomData(my_pub, CRYPTO_PUB_KEY_SIZE);
    createRandomData(cloud_prv, CRYPTO_PRV_KEY_SIZE);
    createRandomData(cloud_pub, CRYPTO_PUB_KEY_SIZE);
    
    crypto_generateKeyPair(my_pub, my_prv);
    crypto_generateKeyPair(cloud_pub, cloud_prv);

    crypto_aesEncrypt(data, padded_data_size, shared_secret, CRYPTO_SHARED_SECRET_SIZE, encrypted_data);    

    crypto_aesDecrypt(encrypted_data, padded_data_size, shared_secret, CRYPTO_SHARED_SECRET_SIZE, decrypted_data);  
    decrypted_data[data_size] = '\0';

    assert(memcmp(data, decrypted_data, data_size) == 0);
}

void test_raw_aes() {
    printf("Raw AES test ... \n");
    WORD key_schedule[60], idx;
	BYTE enc_buf[128];
	BYTE plaintext[2][16] = {
		{0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a},
		{0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}
	};
	BYTE ciphertext[2][16] = {
		{0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8},
		{0x59,0x1c,0xcb,0x10,0xd4,0x10,0xed,0x26,0xdc,0x5b,0xa7,0x4a,0x31,0x36,0x28,0x70}
	};
	BYTE key[1][32] = {
		{0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
	};
	int pass = 1;

	// Raw ECB mode.
	aes_key_setup(key[0], key_schedule, 256);

	for(idx = 0; idx < 2; idx++) {
		aes_encrypt(plaintext[idx], enc_buf, key_schedule, 256);
		pass = pass && !memcmp(enc_buf, ciphertext[idx], 16);

		aes_decrypt(ciphertext[idx], enc_buf, key_schedule, 256);

		pass = pass && !memcmp(enc_buf, plaintext[idx], 16);
	}
}

void test_key_gen() {
    printf("keygen test...\n");

    uint8_t my_prv[CRYPTO_PRV_KEY_SIZE];
    uint8_t my_pub[CRYPTO_PUB_KEY_SIZE];
    uint8_t cloud_prv[CRYPTO_PRV_KEY_SIZE];
    uint8_t cloud_pub[CRYPTO_PUB_KEY_SIZE];
    uint8_t prv_hex[CRYPTO_PRV_KEY_SIZE * 2 + 1];
    uint8_t pub_hex[CRYPTO_PUB_KEY_SIZE * 2 + 1];
    uint8_t cloud_prv_hex[CRYPTO_PRV_KEY_SIZE * 2 + 1];
    uint8_t cloud_pub_hex[CRYPTO_PUB_KEY_SIZE * 2 + 1];

    prv_hex[CRYPTO_PRV_KEY_SIZE * 2] = '\0';
    pub_hex[CRYPTO_PUB_KEY_SIZE * 2] = '\0';
    cloud_prv_hex[CRYPTO_PRV_KEY_SIZE * 2] = '\0';
    cloud_pub_hex[CRYPTO_PUB_KEY_SIZE * 2] = '\0';

    createRandomData(my_prv, CRYPTO_PRV_KEY_SIZE);
    createRandomData(my_pub, CRYPTO_PUB_KEY_SIZE);
    createRandomData(cloud_prv, CRYPTO_PRV_KEY_SIZE);
    createRandomData(cloud_pub, CRYPTO_PUB_KEY_SIZE);
    
    ecdh_generate_keys(my_pub, my_prv);
    ecdh_generate_keys(cloud_pub, cloud_prv);
        
    crypto_bytesToHex(my_prv, CRYPTO_PRV_KEY_SIZE, prv_hex);
    crypto_bytesToHex(my_pub, CRYPTO_PUB_KEY_SIZE, pub_hex);

}

void test_key_gen_fixed_private_key() {
    printf("keygen with fixed key test...\n");

    uint8_t my_pub[CRYPTO_PUB_KEY_SIZE];
    uint8_t prv_hex[CRYPTO_PRV_KEY_SIZE * 2 + 1];
    uint8_t pub_hex[CRYPTO_PUB_KEY_SIZE * 2 + 1];

    prv_hex[CRYPTO_PUB_KEY_SIZE * 2] = '\0';
    pub_hex[CRYPTO_PUB_KEY_SIZE * 2] = '\0';

    uint8_t my_prv[CRYPTO_PRV_KEY_SIZE] = {33, 21, 4, 250, 33, 21, 4, 250, 33, 21, 4, 250, 
    33, 21, 4, 250, 33, 21, 4, 250, 33, 21, 4, 250};
    createRandomData(my_pub, CRYPTO_PUB_KEY_SIZE);
    
    ecdh_generate_keys(my_pub, my_prv);
        
    crypto_bytesToHex(my_prv, CRYPTO_PRV_KEY_SIZE, prv_hex);
    crypto_bytesToHex(my_pub, CRYPTO_PUB_KEY_SIZE, pub_hex);
    
    uint8_t expected_my_pub_hex[CRYPTO_PUB_KEY_SIZE * 2 + 1] = "d279053f9faac837f641385939737e3056d0bffb07000000aaa09ded4e785b3287ae0e64cb40f473698ed6b506000000\0";
    int passed = 1;
    for(int i=0; i<CRYPTO_PUB_KEY_SIZE*2; i++){
        if(expected_my_pub_hex[i]!=pub_hex[i]){
            passed = 0;
        }
    }
    assert(passed);
}

void test_sign_unsign() {
    printf("ECDH sign - unsigned test ... \n");
    uint8_t* data = "bruno fortuto bruno fortunato ciao ciao cioa 1242556";
    size_t data_size = strlen(data) + 1;
    
    const char* my_prv_hex = "a7a81b6f2d4376cce2a37e1c2051ec3bf9e11d9603000000";
    const char* my_pub_hex = "72b708696a89ff49099b7d803221cdcec9c57f69070000004c25154fee44b60c83259b260180957c5f99459203000000";
    const char* cloud_prv_hex = "1be0a4ba29fad1398cf4260593626579986c830601000000";
    const char* cloud_pub_hex = "ddd18a4ef40a51504237e542935b919ea141e2d704000000b0fb60735125ff7adddc881494687ad6f0a12fd905000000";

    uint8_t my_prv[CRYPTO_PRV_KEY_SIZE];
    uint8_t my_pub[CRYPTO_PUB_KEY_SIZE];
    uint8_t cloud_prv[CRYPTO_PRV_KEY_SIZE];
    uint8_t cloud_pub[CRYPTO_PUB_KEY_SIZE];
    uint8_t criminal_prv[CRYPTO_PRV_KEY_SIZE];
    uint8_t criminal_pub[CRYPTO_PUB_KEY_SIZE];

    crypto_generateKeyPair(criminal_pub, criminal_prv);
    
    assert(crypto_hexToBytes(my_prv_hex, strlen(my_prv_hex), my_prv) == CRYPTO_PRV_KEY_SIZE);
    assert(crypto_hexToBytes(my_pub_hex, strlen(my_pub_hex), my_pub) == CRYPTO_PUB_KEY_SIZE);
    assert(crypto_hexToBytes(cloud_prv_hex, strlen(cloud_prv_hex), cloud_prv) == CRYPTO_PRV_KEY_SIZE);
    assert(crypto_hexToBytes(cloud_pub_hex, strlen(cloud_pub_hex), cloud_pub) == CRYPTO_PUB_KEY_SIZE);

    size_t padded_data_size = crypto_pkcs7CalculatePaddedSize(data, data_size);
    uint8_t signed_data[padded_data_size];
    uint8_t received_data[padded_data_size];

    size_t len = crypto_sign(my_prv, cloud_pub, data, data_size, signed_data);
    
    size_t original_len = crypto_unsign(cloud_prv, my_pub, signed_data, len, received_data);

    assert(memcmp(data, received_data, original_len) == 0);  

    len = crypto_unsign(cloud_prv, criminal_pub, signed_data, len, received_data);
    assert(len == 0);  

    uint8_t corrupted_data[2];
    createRandomData(corrupted_data, 2);
    //crypto_unsign(cloud_prv, 0, corrupted_data, len, received_data); //seg fault?
}

int main(int argc, char const *argv[]) {
    test_crypt_decrypt();
    test_md5();
    test_raw_aes();
    test_aes();
    test_key_gen_fixed_private_key();
    test_key_gen();    
    test_padding();
    test_sign_unsign();
}