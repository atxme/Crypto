#pragma once

////////////////////////////////////////////////////////////////////////////////////////
// Kyber integration for PQS API                                                      //     
//                                                                                    //                          
// Kyber is a C library that implements the algorithm described in                    //
// "Kyber: a CCA-secure module-lattice-based KEM" by Eike Kiltz,                     ,//
// Alex Kyber, and Peter Schwabe, published in the proceedings of                     //
// CRYPTO 2017.                                                                       //
//                                                                                    //                  
// Kyber will provide a shared secret bettween two parties for symetric encryption    //
//                                                                                    //
// Project : kyber PQS                                                                //                    
// File    : kyber.h                                                                  //                
// Author  : Benedetti Christophe                                                     //
//                                                                                    //
// This code is provided under the MIT license.                                       //
// Please refer to the LICENSE file for licensing information.                        //
//                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////

#ifndef DILIITHIUM_H
#define DILIITHIUM_H

#include "pqsCtx.h"
#include "pqsError.h"

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

#define KYBER_MAX_MESSAGE_SIZE 32

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus


////////////////////////////////////////////////////////////////////////////////////////
// Kyber KeyGeneration
//
/// @param:  ctx: key generation context
/// @param:  keySize: the size of the key to generate
//
/// @return: void
//
////////////////////////////////////////////////////////////////////////////////////////
void genKyberKeyPair(PQS_KEYGEN_CTX* ctx, int keySize);


////////////////////////////////////////////////////////////////////////////////////////
// Kyber Encryption
//
/// @param:  ctx: encryption context
//
/// @return: void
//
////////////////////////////////////////////////////////////////////////////////////////
void encryptKyber(PQS_ENCRYPT_CTX* ctx);

////////////////////////////////////////////////////////////////////////////////////////
// Kyber Decryption
//
/// @param:  ctx: decryption context
//
/// @return: int : 0 if the decryption is a success, 1 if the decryption failed
//
////////////////////////////////////////////////////////////////////////////////////////
int decryptKyber(PQS_DECRYPT_CTX* ctx);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // DILIITHIUM_H