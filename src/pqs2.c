////////////////////////////////////////////////////////////////////////////////////////
// PQS API call interface                                                             //     
//                                                                                    //                          
// This file is a part of the "PQS" Post Quantum Security  project.                   //
// You can simply call 1 function with differents parameters to use the API           //
// You will be able to collect the output by casting it to the correct type           //
// The correct type is define by the algorithm type you want to use                   //
//                                                                                    //
// You will have to cast the output using the ctx you have define                     //
//                                                                                    //                                                                              
// Project : PQS API                                                                  //                    
// File    : pqs2.c                                                                    //                
// Author  : Benedetti Christophe                                                     //
//                                                                                    //
// This code is provided under the MIT license.                                       //
// Please refer to the LICENSE file for licensing information.                        //
//                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////

#include "pqs.h"
#include "FALCON/falcon.h"
#include "KYBER/kyber.h"
#include "DILITHIUM/dilithium.h"
#include "PQS_ERROR/pqsError.h"
#include "ctxAlloc/ctxAlloc.h"

#include <oqs/oqs.h>  
#include <string.h>


void PQS_API(PQS_API_PARAM* ctx)
{
    if (ctx == NULL){
        pqsError(CTX_IS_NULL, __LINE__,__FUNCTION__);
        return;
    }

    switch (ctx->mode)
    {
        case KEY_GENERATION :
        {

            PQS_KEYGEN_CTX *keygenCtx = createPqsKeygenCtx();

            if (keygenCtx == NULL){
                pqsError(CTX_IS_NULL, __LINE__,__FUNCTION__);
                return;
            }

            switch (ctx->algorithm)
            {
                
                case FALCON_512:
                {
                    falconKeyGen(keygenCtx, FALCON_PUBLIC_KEY_SIZE_512);
                    
                    // Copy the output to the ctx
                    memcpy(ctx->publicKey, keygenCtx->publicKey, FALCON_PUBLIC_KEY_SIZE_512);
                    memcpy(ctx->privateKey, keygenCtx->privateKey, FALCON_PRIVATE_KEY_SIZE_512);

                    freePqsKeygenCtx(keygenCtx);
                    break;
                }

                case FALCON_1024:
                {
                    falconKeyGen(keygenCtx, FALCON_PUBLIC_KEY_SIZE_1024);
                    printf("FALCON_1024\n");

                    printf("Public key: ");
                    print_hex(keygenCtx->publicKey, FALCON_PUBLIC_KEY_SIZE_1024);
                    // Copy the output to the ctx
                    memcpy(ctx->publicKey, keygenCtx->publicKey, FALCON_PUBLIC_KEY_SIZE_1024);
                    memcpy(ctx->privateKey, keygenCtx->privateKey, FALCON_PRIVATE_KEY_SIZE_1024);

                    freePqsKeygenCtx(keygenCtx);
                    break;
                }

                case KYBER_512 :
                {
                    genKyberKeyPair(keygenCtx, KYBER_PUBLIC_KEY_SIZE_512);

                    // Copy the output to the ctx
                    memcpy(ctx->publicKey, keygenCtx->publicKey, KYBER_PUBLIC_KEY_SIZE_512);
                    memcpy(ctx->privateKey, keygenCtx->privateKey, KYBER_PRIVATE_KEY_SIZE_512);

                    freePqsKeygenCtx(keygenCtx);
                    break;
                }

                case KYBER_768 :
                {
                    genKyberKeyPair(keygenCtx, KYBER_PUBLIC_KEY_SIZE_768);

                    // Copy the output to the ctx
                    memcpy(ctx->publicKey, keygenCtx->publicKey, KYBER_PUBLIC_KEY_SIZE_768);
                    memcpy(ctx->privateKey, keygenCtx->privateKey, KYBER_PRIVATE_KEY_SIZE_768);

                    freePqsKeygenCtx(keygenCtx);
                    break;
                }

                case KYBER_1024 :
                {
                    genKyberKeyPair(keygenCtx, KYBER_PUBLIC_KEY_SIZE_1024);

                    // Copy the output to the ctx
                    memcpy(ctx->publicKey, keygenCtx->publicKey, KYBER_PUBLIC_KEY_SIZE_1024);
                    memcpy(ctx->privateKey, keygenCtx->privateKey, KYBER_PRIVATE_KEY_SIZE_1024);

                    freePqsKeygenCtx(keygenCtx);
                    break;
                }

                case DILITHIUM_2 :
                {
                    genDilithiumKeyPair(keygenCtx, DILIITHIUM_PUBLIC_KEY_SIZE_2);

                    // Copy the output to the ctx
                    memcpy(ctx->publicKey, keygenCtx->publicKey, DILIITHIUM_PUBLIC_KEY_SIZE_2);
                    memcpy(ctx->privateKey, keygenCtx->privateKey, DILIITHIUM_PRIVATE_KEY_SIZE_2);

                    freePqsKeygenCtx(keygenCtx);
                    break;
                }

                case DILITHIUM_3 :
                {
                    genDilithiumKeyPair(keygenCtx, DILIITHIUM_PUBLIC_KEY_SIZE_3);

                    // Copy the output to the ctx
                    memcpy(ctx->publicKey, keygenCtx->publicKey, DILIITHIUM_PUBLIC_KEY_SIZE_3);
                    memcpy(ctx->privateKey, keygenCtx->privateKey, DILIITHIUM_PRIVATE_KEY_SIZE_3);

                    freePqsKeygenCtx(keygenCtx);
                    break;
                }

                case DILITHIUM_5 :
                {
                    genDilithiumKeyPair(keygenCtx, DILIITHIUM_PUBLIC_KEY_SIZE_5);

                    // Copy the output to the ctx
                    memcpy(ctx->publicKey, keygenCtx->publicKey, DILIITHIUM_PUBLIC_KEY_SIZE_5);
                    memcpy(ctx->privateKey, keygenCtx->privateKey, DILIITHIUM_PRIVATE_KEY_SIZE_5);

                    freePqsKeygenCtx(keygenCtx);
                    break;
                }

                default:
                    pqsError(KEY_SIZE_ERROR, __LINE__,__FUNCTION__);
                    return;

                break ;
            }
            
            break;
        }

        case SIGNATURE :
        {
            PQS_SIGN_CTX *signCtx = createPqsSignCtx();

            if (signCtx == NULL){
                pqsError(CTX_IS_NULL, __LINE__,__FUNCTION__);
                return;
            }

            switch(ctx->algorithm)
            {
                case FALCON_512 :
                {
                    signCtx->signature = malloc(FALCON_SIGNATURE_MAX_SIZE_512);
                    signCtx->message = malloc(ctx->messageSize);
                    signCtx->privateKey = malloc(FALCON_PRIVATE_KEY_SIZE_512);
                    signCtx->privateKeySize = FALCON_PRIVATE_KEY_SIZE_512;
                    signCtx->signatureSize = 0;
                    
                    if (signCtx->signature == NULL || signCtx->message == NULL){
                        pqsError(MALLOC_ERROR, __LINE__,__FUNCTION__);
                        return;
                    }

                    memcpy(signCtx->message, ctx->message, ctx->messageSize);
                    
                    memcpy(signCtx->privateKey, ctx->privateKey, FALCON_PRIVATE_KEY_SIZE_512);
                    
                    falconSign(signCtx);
                    
                    memcpy(ctx->signature, signCtx->signature, signCtx->signatureSize);

                    memcpy(&ctx->signatureSize, &signCtx->signatureSize, sizeof(size_t));
                    
                    freePqsSignCtx(signCtx);
                    break;
                }

                case FALCON_1024 :
                {
                    signCtx->signature = malloc(FALCON_SIGNATURE_MAX_SIZE_1024);
                    signCtx->message = malloc(ctx->messageSize);

                    if (signCtx->signature == NULL || signCtx->message == NULL){
                        pqsError(MALLOC_ERROR, __LINE__,__FUNCTION__);
                        return;
                    }

                    memcpy(signCtx->message, ctx->message, ctx->messageSize);
                    memcpy(signCtx->privateKey, ctx->privateKey, FALCON_PRIVATE_KEY_SIZE_1024);

                    falconSign(signCtx);

                    memcpy(ctx->signature, signCtx->signature, signCtx->signatureSize);

                    freePqsSignCtx(signCtx);
                    break;
                }

                case DILITHIUM_2 : 
                {
                    signCtx->message = malloc(ctx->messageSize);
                    signCtx->privateKey = malloc(DILITHIUM_PRIVATE_KEY_SIZE_2);
                    signCtx->privateKeySize = DILITHIUM_PRIVATE_KEY_SIZE_2;

                    if (signCtx->privateKey == NULL || signCtx->message == NULL){
                        pqsError(MALLOC_ERROR, __LINE__,__FUNCTION__);
                        return;
                    }

                    memcpy(signCtx->message, ctx->message, ctx->messageSize);
                    memcpy(signCtx->privateKey, ctx->privateKey, DILITHIUM_PRIVATE_KEY_SIZE_2);
                    
                    signCtx->messageSize = ctx->messageSize;

                    dilithiumSign(signCtx);

                    memcpy(ctx->signature, signCtx->signature, signCtx->signatureSize);

                    ctx->signatureSize = signCtx->signatureSize;

                    freePqsSignCtx(signCtx);
                    break;
                }

                case DILITHIUM_3 :
                {
                    signCtx->message = malloc(ctx->messageSize);
                    signCtx->privateKey = malloc(DILITHIUM_PRIVATE_KEY_SIZE_3);
                    signCtx->privateKeySize = DILITHIUM_PRIVATE_KEY_SIZE_3;

                    if (signCtx->privateKey == NULL || signCtx->message == NULL){
                        pqsError(MALLOC_ERROR, __LINE__,__FUNCTION__);
                        return;
                    }

                    memcpy(signCtx->message, ctx->message, ctx->messageSize);
                    memcpy(signCtx->privateKey, ctx->privateKey, DILITHIUM_PRIVATE_KEY_SIZE_3);
                    
                    signCtx->messageSize = ctx->messageSize;

                    dilithiumSign(signCtx);

                    memcpy(ctx->signature, signCtx->signature, signCtx->signatureSize);

                    ctx->signatureSize = signCtx->signatureSize;

                    freePqsSignCtx(signCtx);
                    break;
                }

                case DILITHIUM_5 :
                {
                    signCtx->message = malloc(ctx->messageSize);
                    signCtx->privateKey = malloc(DILITHIUM_PRIVATE_KEY_SIZE_5);
                    signCtx->privateKeySize = DILITHIUM_PRIVATE_KEY_SIZE_5;

                    if (signCtx->privateKey == NULL || signCtx->message == NULL){
                        pqsError(MALLOC_ERROR, __LINE__,__FUNCTION__);
                        return;
                    }

                    memcpy(signCtx->message, ctx->message, ctx->messageSize);
                    memcpy(signCtx->privateKey, ctx->privateKey, DILITHIUM_PRIVATE_KEY_SIZE_5);
                    
                    signCtx->messageSize = ctx->messageSize;

                    dilithiumSign(signCtx);

                    memcpy(ctx->signature, signCtx->signature, signCtx->signatureSize);

                    ctx->signatureSize = signCtx->signatureSize;

                    freePqsSignCtx(signCtx);
                    break;
                }

                default:
                    pqsError(KEY_SIZE_ERROR, __LINE__,__FUNCTION__);
                    return;

                break;
            }

            break;
        }

        case SIGNATURE_VERIFICATION :
        {
            PQS_SIGN_CTX *signCtx = createPqsSignCtx();
            if (signCtx == NULL){
                pqsError(CTX_IS_NULL, __LINE__,__FUNCTION__);
                return;
            }

            switch (ctx->algorithm){
                case FALCON_512 :
                {
                    signCtx->signature = malloc(FALCON_SIGNATURE_MAX_SIZE_512);
                    signCtx->message = malloc(ctx->messageSize);
                    signCtx->publicKey = malloc(FALCON_PUBLIC_KEY_SIZE_512);
                    signCtx->publicKeySize = FALCON_PUBLIC_KEY_SIZE_512;
                    signCtx->signatureSize = 0;

                    if (signCtx->signature == NULL || signCtx->message == NULL || signCtx->publicKey == NULL){
                        pqsError(MALLOC_ERROR, __LINE__,__FUNCTION__);
                        return;
                    }

                    memcpy(signCtx->message, ctx->message, ctx->messageSize);
                    memcpy(signCtx->publicKey, ctx->publicKey, FALCON_PUBLIC_KEY_SIZE_512);
                    memcpy(signCtx->signature, ctx->signature, ctx->signatureSize);

                    signCtx->messageSize = ctx->messageSize;
                    signCtx->signatureSize = ctx->signatureSize;

                    falconVerifySign(signCtx);

                    freePqsSignCtx(signCtx);
                    break;
                }
                
            }

            break ;
        }

        default:
            pqsError(MODE_ERROR, __LINE__,__FUNCTION__);
            return;

        break;
    }
}