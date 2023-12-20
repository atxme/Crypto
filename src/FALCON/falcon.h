#pragma once

////////////////////////////////////////////////////////////////////////////////////////
// Falcon  integration for PQS API                                                    //     
//                                                                                    //                          
// This file is part of the Falcon library.                                           //
//                                                                                    //  
// The Falcon library is a library for the simulation of the dynamics of a rigid body.//
//                                                                                    //
// Falcon is a C library that implement a PQC algorithm.                              //
// Its based on euclidean geometry and quaternion algebra.                            //
//                                                                                    //
// Project : Falcon PQS                                                               //                    
// File    : falcon.h                                                                 //                
// Author  : Benedetti Christophe                                                     //
//                                                                                    //
// This code is provided under the MIT license.                                       //
// Please refer to the LICENSE file for licensing information.                        //
//                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////

#ifndef FALCON_H
#define FALCON_H

#include "pqsError.h"
#include "pqsCtx.h"


#define FALCON_PUBLIC_KEY_SIZE_512 897
#define FALCON_PUBLIC_KEY_SIZE_1024 1793
#define FALCON_PRIVATE_KEY_SIZE_512 1281
#define FALCON_PRIVATE_KEY_SIZE_1024 2305
#define FALCON_SIGNATURE_MAX_SIZE_512 690  
#define FALCON_SIGNATURE_MAX_SIZE_1024 1330 



#ifdef __cplusplus
extern "C" {
#endif

//////////////////////////////////////////////////////////////////////////
// Falcon KeyGeneration
//
/// @brief Generate a new Falcon keyPair
//
/// @param[in]  ctx : The PQS context for key generation
/// @param[in]  keySize : The Publickey size 
//
/// @return void
//
//////////////////////////////////////////////////////////////////////////
void falconKeyGen(PQS_KEYGEN_CTX *ctx, int keySize);


//////////////////////////////////////////////////////////////////////////
// Falcon Sign
//
/// @brief Sign a message with a Falcon private key
//
/// @param[in]  pqsCtx : The PQS sign context 
//
/// @return void
//
//////////////////////////////////////////////////////////////////////////
void falconSign(PQS_SIGN_CTX *ctx);

//////////////////////////////////////////////////////////////////////////
// Falcon Sign verification
//
/// @brief Verify a message with a Falcon public key
//
/// @param[in]  pqsCtx : The PQS sign context
//
/// @return int : 0 if the signature is valid, -1 otherwise
//
//////////////////////////////////////////////////////////////////////////
int falconVerifySign(PQS_SIGN_CTX *ctx);



#ifdef __cplusplus
}
#endif

#endif // FALCON_H