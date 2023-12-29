#include "falcon.h"

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
// File    : falcon.c                                                                 //                
// Author  : Benedetti Christophe                                                     //
//                                                                                    //
// This code is provided under the MIT license.                                       //
// Please refer to the LICENSE file for licensing information.                        //
//                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////
// Falcon keyPair generation
////////////////////////////////////////
void falconKeyGen(PQS_KEYGEN_CTX *ctx, int keySize) {
    if (ctx == NULL) {
        pqsError(CTX_IS_NULL, __LINE__, __FUNCTION__);
        return;
    }

    if (keySize != FALCON_PUBLIC_KEY_SIZE_512 && keySize != FALCON_PUBLIC_KEY_SIZE_1024) {
        pqsError(KEY_SIZE_ERROR, __LINE__, __FUNCTION__);
        return;
    }
    
    const char *alg_name = (keySize == FALCON_PUBLIC_KEY_SIZE_512) ? OQS_SIG_alg_falcon_512 : OQS_SIG_alg_falcon_1024;
    OQS_SIG *sig = OQS_SIG_new(alg_name);

    if (sig == NULL) {
        pqsError(ERROR_SIG_KEYGEN, __LINE__, __FUNCTION__);
        return;
    }

    ctx->publicKey = malloc(sig->length_public_key * sizeof(unsigned char));
    ctx->privateKey = malloc(sig->length_secret_key * sizeof(unsigned char));

    if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
        free(ctx->publicKey);
        free(ctx->privateKey);
        OQS_SIG_free(sig);
        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
        return;
    }

    if (OQS_SIG_keypair(sig, ctx->publicKey, ctx->privateKey) != OQS_SUCCESS) {
        free(ctx->publicKey);
        free(ctx->privateKey);
        OQS_SIG_free(sig);
        pqsError(KEYGEN_ERROR, __LINE__, __FUNCTION__);
        return;
    }

    OQS_SIG_free(sig);
}


////////////////////////////////////////
// Falcon Sign
////////////////////////////////////////
void falconSign(PQS_SIGN_CTX *ctx){

    if (ctx == NULL){
        pqsError(CTX_IS_NULL, __LINE__, __FUNCTION__);
        return;
    }

    OQS_SIG *sig;

    switch (ctx->privateKeySize){
            
            case (FALCON_PRIVATE_KEY_SIZE_512):
    
                sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    
                if (sig == NULL) {
                    pqsError(ERROR_SIG_ALLOC,__LINE__,__FUNCTION__);
                    exit(EXIT_FAILURE);
                }
    
                ctx->signature = malloc(sig->length_signature * sizeof(unsigned char));
    
                if (ctx->signature == NULL) {
                    pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                    exit(EXIT_FAILURE);
                }
    
                OQS_SIG_sign(sig, ctx->signature, &ctx->signatureSize, ctx->message, ctx->messageSize, ctx->privateKey); //OQS API CALL
    
                break;
    
            case (FALCON_PRIVATE_KEY_SIZE_1024):
    
                sig = OQS_SIG_new(OQS_SIG_alg_falcon_1024);
    
                if (sig == NULL ){
                    pqsError(ERROR_SIG_ALLOC, __LINE__, __FUNCTION__);
                    exit(EXIT_FAILURE);
                }
    
                ctx->signature = malloc(sig->length_signature * sizeof(unsigned char));
    
                if (ctx->signature == NULL) {
                    pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                    exit(EXIT_FAILURE);
                }
    
                OQS_SIG_sign(sig, ctx->signature, &ctx->signatureSize, ctx->message, ctx->messageSize, ctx->privateKey); //OQS API CALL
    
                break;
    
            default:
                pqsError(KEY_SIZE_ERROR, __LINE__, __FUNCTION__);
                exit(0);
    }

    OQS_SIG_free(sig);
}

////////////////////////////////////////
// Falcon Sign verification
////////////////////////////////////////
int falconVerifySign(PQS_SIGN_CTX *ctx){

    if (ctx == NULL){
        pqsError(CTX_IS_NULL, __LINE__, __FUNCTION__);
        return -1;
    }

    if (ctx->signature == NULL){
        pqsError(SIGNATURE_ERROR, __LINE__, __FUNCTION__);
        return -1;
    }

    if (ctx->publicKey == NULL){
        pqsError(PUBLIC_KEY_ERROR, __LINE__, __FUNCTION__);
        return -1;
    }

    OQS_SIG *sig;

    switch (ctx->publicKeySize){

        case FALCON_PUBLIC_KEY_SIZE_512:
            sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
            break;

        case  FALCON_PUBLIC_KEY_SIZE_1024:
            sig = OQS_SIG_new(OQS_SIG_alg_falcon_1024);
            break;
        
        default:
            pqsError(SIGNATURE_SIZE_ERROR, __LINE__, __FUNCTION__);
            exit(0);
    }

    if (sig == NULL ){
        pqsError(ERROR_SIG_ALLOC, __LINE__, __FUNCTION__);
        exit(EXIT_FAILURE);
    }

    if (OQS_SIG_verify(sig, ctx->message, ctx->messageSize, ctx->signature, ctx->signatureSize, ctx->publicKey) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        pqsError(SIGNATURE_VERIFICATION_ERROR, __LINE__, __FUNCTION__);
        return -1;
    }

    OQS_SIG_free(sig);
    return 0;
}