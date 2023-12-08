#pragma once
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define AES_KEYLEN 256
#define AES_BLOCK_SIZE 16
#define SHA256_DIGEST_LENGTH 32
#define SHA512_DIGEST_LENGTH 64
#define AES_SHA256_KEYLEN 32
#define AES_SHA512_KEYLEN 64
#define IV_LEN 16

enum AES_CONFIGURATION{
    AES_256_CBC_HMAC_SHA256 = 1,
    AES_256_CBC_HMAC_SHA512 = 2,
    AES_256_GCM = 3,
    AES_256_CBC = 4
};

//////////////////////////////////////////
// handle errors
//////////////////////////////////////////
void handleErrors(void);

//////////////////////////////////////////
// print hex 
//////////////////////////////////////////
void print_hex(unsigned char *buf, int len);

//////////////////////////////////////////
// generate random iv
//////////////////////////////////////////
void generateRandomIV(unsigned char* iv);

//////////////////////////////////////////
//generate random key 
//////////////////////////////////////////
void generateRandomKey(unsigned char *key);

//////////////////////////////////////////
// sha256
//////////////////////////////////////////
void sha3_256(unsigned char *plaintext, unsigned long plaintextLen, unsigned char *digest);

//////////////////////////////////////////
// sha512
//////////////////////////////////////////
void sha3_512(unsigned char *plaintext, unsigned long plaintextLen, unsigned char *digest);


//////////////////////////////////////////
// aes 256 encryption
//////////////////////////////////////////
void Aes256encryption (unsigned char *plaintext , unsigned char* key, unsigned char* iv , unsigned long plaintextLen, int aesConf ,unsigned char* cipherText);

//////////////////////////////////////////
// aes 256 decryption
//////////////////////////////////////////
void Aes256decryption(unsigned char *cipherText, unsigned char* key, unsigned char* iv, unsigned long cipherTextLen, int aesConf, unsigned char* decryptedText);



