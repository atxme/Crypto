#pragma once

#include <oqs/oqs.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "crypto.h"
#include "pqsCtx.h"
#include "pqsError.h"

#define FALCON_PUBLIC_KEY_SIZE_512 768
#define FALCON_PUCLIC_KEY_SIZE_1024 1792
#define FALCON_PRIVATE_KEY_SIZE_1024 1280
#define FALCON_PRIVATE_KEY_SIZE_512 512


#define FALCON_SIGNATURE_SIZE_1024 2304
#define FALCON_SIGNATURE_SIZE_512 1024

#define KYBER_PUBLIC_KEY_SIZE_512 800
#define KYBER_PUBLIC_KEY_SIZE_768 1184
#define KYBER_PUBLIC_KEY_SIZE_1024 1568
#define KYBER_PUBLIC_KEY_SIZE_512_90S 736
#define KYBER_PUBLIC_KEY_SIZE_768_90S 1088
#define KYBER_PUBLIC_KEY_SIZE_1024_90S 1440


#define KYBER_PRIVATE_KEY_SIZE_512 1632
#define KYBER_PRIVATE_KEY_SIZE_768 2400
#define KYBER_PRIVATE_KEY_SIZE_1024 3168
#define KYBER_PRIVATE_KEY_SIZE_512_90S 1568
#define KYBER_PRIVATE_KEY_SIZE_768_90S 2288
#define KYBER_PRIVATE_KEY_SIZE_1024_90S 3008

#define KYBER_SIGNATURE_SIZE_512 736
#define KYBER_SIGNATURE_SIZE_768 1088
#define KYBER_SIGNATURE_SIZE_1024 1440
#define KYBER_SIGNATURE_SIZE_512_90S 736
#define KYBER_SIGNATURE_SIZE_768_90S 1088
#define KYBER_SIGNATURE_SIZE_1024_90S 1440


#define DILIITHIUM_PUBLIC_KEY_SIZE_2 1312
#define DILIITHIUM_PUBLIC_KEY_SIZE_3 1952
#define DILIITHIUM_PUBLIC_KEY_SIZE_5 2592
#define DILIITHIUM_PUBLIC_KEY_SIZE_2_AES 1184
#define DILIITHIUM_PUBLIC_KEY_SIZE_3_AES 1760
#define DILIITHIUM_PUBLIC_KEY_SIZE_5_AES 2336

#define DILIITHIUM_PRIVATE_KEY_SIZE_2 2544
#define DILIITHIUM_PRIVATE_KEY_SIZE_3 3888
#define DILIITHIUM_PRIVATE_KEY_SIZE_5 5568
#define DILIITHIUM_PRIVATE_KEY_SIZE_2_AES 2400
#define DILIITHIUM_PRIVATE_KEY_SIZE_3_AES 3648
#define DILIITHIUM_PRIVATE_KEY_SIZE_5_AES 5216

#define DILIITHIUM_SIGNATURE_SIZE_2 2420
#define DILIITHIUM_SIGNATURE_SIZE_3 3568
#define DILIITHIUM_SIGNATURE_SIZE_5 4928
#define DILIITHIUM_SIGNATURE_SIZE_2_AES 2304
#define DILIITHIUM_SIGNATURE_SIZE_3_AES 3392
#define DILIITHIUM_SIGNATURE_SIZE_5_AES 4688


enum PQS_ALGORITHM{
    FALCON_512 = 0,
    FALCON_1024 = 1,
    KYBER_512 = 3,
    KYBER_768 = 4,
    KYBER_1024 = 5,
    KYBER_512_90S = 6,
    KYBER_768_90S = 7,
    KYBER_1024_90S = 8,
    DILITHIUM_2 = 9,
    DILITHIUM_3 = 10,
    DILITHIUM_5 = 11,
    DILITHIUM_2_AES = 12,
    DILITHIUM_3_AES = 13,
    DILITHIUM_5_AES = 14,
};

enum PQS_ALGORITHM_TYPE{
    ENCRYPTION = 1,
    DECRYPTION = 2,
    SIGNATURE = 3,
    SIGNATURE_VERIFICATION= 4,
    KEY_GENERATION = 5,
};


//////////////////////////////////////////
// print hex 
//////////////////////////////////////////
void print_hex(unsigned char *buf, int len);


//////////////////////////////////////////////////////////////////////////////////////////
/// @brief: API FOR POST QUANTUM CRYPTOGRAPHY INTERACTION 
/// @brief: FOR KEY GENERATION you must put the public key size in the keySize parameter
/// @brief:  combine all the functions above to a single API
/// @brief:  you must define correctly the call off the API by defining all parameters
/// @brief:  if you don't need the parameter, just pass NULL and the API will accept the call 
//
/// @brief: thanks to edit saveFile flag and logFile path for file saving log 
//
/// @param algorithmetype: ENCRYPTION, DECRYPTION, SIGNATURE, KEY_GENERATION
/// @param algorithm: FALCON_1024,FALCON_2048, 
//                     KYBER_512, KYBER_768, KYBER_1024, KYBER_512_90S, KYBER_768_90S, KYBER_1024_90S, 
//                     DILITHIUM_2, DILITHIUM_3, DILITHIUM_5, DILITHIUM_2_AES, DILITHIUM_3_AES, DILITHIUM_5_AES
/// @param publicKey:       the public key for encryption and signature verification
/// @param  privateKey:      the private key for decryption and signature
/// @param message:         the message for encryption and signature
/// @param messageSize:     the size of the message
/// @param keySize:         the size of the key
/// @param API_CALL_RETURN: return the ctx regarding your call 
//
/// @return void 
//////////////////////////////////////////////////////////////////////////////////////////
void PQS_API(int algorithmetype, 
            int algorithm, 
            unsigned char* publicKey, 
            unsigned char* privateKey, 
            unsigned char* message,
            size_t messageSize ,
            int keySize,
            void* API_CALL_RETURN);
