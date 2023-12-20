#pragma once 

#include "pqsCtx.h"
#include "pqsError.h"

////////////////////////////////////////////////////////////////////////////////////////
// Dilithium integration for PQS API                                                  //     
//                                                                                    //                          
// Dilithium is a library for fast and accurate computation of                        //      
// the per-pixel atmospheric scattering integral.                                     //
//                                                                                    //                      
// Dilithium is a C library that implements the algorithm described in                //
// "A Practical Analytic Model for Daylight" by A. J. Preetham, Peter Shirley,        //
// and Brian Smits, published in ACM Transactions on Graphics 21, 3 (July 2002).      //
//                                                                                    //
// Project : Dilithium PQS                                                            //                    
// File    : dilithium.h                                                              //                
// Author  : Benedetti Christophe                                                     //
//                                                                                    //
// This code is provided under the MIT license.                                       //
// Please refer to the LICENSE file for licensing information.                        //
//                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////

#ifndef DILIITHIUM_H
#define DILIITHIUM_H

#define PQS_DILIITHIUM_SIGNATURE_VERIFICATION_SUCCESS 0
#define PQS_DILIITHIUM_SIGNATURE_VERIFICATION_FAILED  1

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
#define DILIITHIUM_SIGNATURE_SIZE_3 3293
#define DILIITHIUM_SIGNATURE_SIZE_5 4595
#define DILIITHIUM_SIGNATURE_SIZE_2_AES 2304
#define DILIITHIUM_SIGNATURE_SIZE_3_AES 3392
#define DILIITHIUM_SIGNATURE_SIZE_5_AES 4688


#ifdef __cplusplus
extern "C" {
#endif // __cplusplus


//////////////////////////////////////////////////////////////////////////
// Dilithium KeyGeneration
//
/// @brief Generate a new Dilithium keyPair
//
/// @param[in]  pqsCtx : The PQS context
/// @param[in]  keySize : The Publickey size 
//
/// @return void
//
//////////////////////////////////////////////////////////////////////////
void genDilithiumKeyPair(PQS_KEYGEN_CTX *ctx, unsigned int dilithiumKeySize);

//////////////////////////////////////////////////////////////////////////
// Dilithium Sign
//
/// @brief Sign a message with Dilithium
//
/// @param[in]  ctx : The PQS context for signature interaction which include:
//                    - The message to verify
//                    - The signature to verify
//                    - The public key to use for verification
//                    - The message size
//                    - The signature size
/// @return void
//
//////////////////////////////////////////////////////////////////////////
void dilithiumSign(PQS_SIGN_CTX *ctx);

//////////////////////////////////////////////////////////////////////////
// Dilithium Verify sign 
//
/// @brief Verify a Dilithium signature
//
/// @param[in]  ctx : The PQS context for signature interaction which include:
//                    - The message to verify
//                    - The signature to verify
//                    - The public key to use for verification
//                    - The message size
//                    - The signature size
//
/// @return int : PQS_DILIITHIUM_SIGNATURE_VERIFICATION_SUCCESS if the signature is valid, PQS_DILIITHIUM_SIGNATURE_VERIFICATION_FAILED otherwise
//
//////////////////////////////////////////////////////////////////////////
int dilithiumVerifySign(PQS_SIGN_CTX *ctx);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // DILIITHIUM_H