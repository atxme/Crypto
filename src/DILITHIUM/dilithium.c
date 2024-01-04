#include "dilithium.h"
#include "crypto.h"

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
// File    : dilithium.c                                                              //                
// Author  : Benedetti Christophe                                                     //
//                                                                                    //
// This code is provided under the MIT license.                                       //
// Please refer to the LICENSE file for licensing information.                        //
//                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////
// dilithium keyPair generation
////////////////////////////////////////
void genDilithiumKeyPair(PQS_KEYGEN_CTX *ctx, unsigned int dilithiumKeySize){

    if (ctx == NULL){
        pqsError(CTX_IS_NULL, __LINE__,__FUNCTION__);
        return;
    }

    if(dilithiumKeySize != DILIITHIUM_PUBLIC_KEY_SIZE_2 && dilithiumKeySize != DILIITHIUM_PUBLIC_KEY_SIZE_3 && dilithiumKeySize != DILIITHIUM_PUBLIC_KEY_SIZE_5)
    {
        pqsError(KEY_SIZE_ERROR, __LINE__, __FUNCTION__);
        exit(0);
    }

    OQS_SIG *sig;

    switch (dilithiumKeySize){

        case (DILIITHIUM_PUBLIC_KEY_SIZE_2): {

            sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);

            if (sig == NULL) {
                pqsError(ERROR_SIG_KEYGEN,__LINE__,__FUNCTION__);
                exit(EXIT_FAILURE);
            }

            ctx->publicKey = malloc(DILIITHIUM_PUBLIC_KEY_SIZE_2);
            ctx->privateKey = malloc(DILIITHIUM_PRIVATE_KEY_SIZE_2);

            if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
                pqsError(MALLOC_ERROR, __LINE__,__FUNCTION__);
                exit(EXIT_FAILURE);
            }
            //OQS_SIG_dilithium_2_keypair
            OQS_SIG_keypair(sig, ctx->publicKey, ctx ->privateKey); //OQS API CALL

            break;
        }

        case (DILIITHIUM_PUBLIC_KEY_SIZE_3): {

            sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);

            if (sig == NULL ){
                pqsError(ERROR_SIG_KEYGEN, __LINE__, __FUNCTION__);
                exit(EXIT_FAILURE);
            }

            ctx->publicKey = malloc(DILIITHIUM_PUBLIC_KEY_SIZE_3);
            ctx->privateKey = malloc(DILIITHIUM_PRIVATE_KEY_SIZE_3);

            if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
                pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                exit(EXIT_FAILURE);
            }

            OQS_SIG_keypair(sig, ctx->publicKey, ctx->privateKey); //OQS API CALL

            break;
        }

        case (DILIITHIUM_PUBLIC_KEY_SIZE_5): {

            sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);

            if (sig == NULL ){
                pqsError(ERROR_SIG_KEYGEN, __LINE__, __FUNCTION__);
                exit(EXIT_FAILURE);
            }
            
            ctx->publicKey = malloc(DILIITHIUM_PUBLIC_KEY_SIZE_5);
            ctx->privateKey = malloc(DILIITHIUM_PRIVATE_KEY_SIZE_5);

            if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
                pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                exit(EXIT_FAILURE);
            }

            OQS_SIG_keypair(sig, ctx->publicKey, ctx->privateKey); //OQS API CALL

            break;
        }
    }

    OQS_SIG_free(sig);
}

////////////////////////////////////////
// dilithium sign
////////////////////////////////////////

void dilithiumSign(PQS_SIGN_CTX *ctx)
{
    if (ctx == NULL){
        pqsError(ERROR_POINTER_NOT_DEFINE,__LINE__,__FUNCTION__);
        return;
    }

    if (ctx->message == NULL){
        pqsError(MESSAGE_ERROR, __LINE__,__FUNCTION__);
        return ;
    }

    if (ctx->privateKey == NULL){
        pqsError(PRIVATE_KEY_ERROR,__LINE__, __FUNCTION__);
        return;
    }

    OQS_SIG *sig;

    switch (ctx->privateKeySize)
    {

        case DILIITHIUM_PRIVATE_KEY_SIZE_2 : {
                
            sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);

            ctx->signature = malloc(sig->length_signature * sizeof(unsigned char));

            break;
        }

        case DILIITHIUM_PRIVATE_KEY_SIZE_3 : {
                
            sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);

            ctx->signature = malloc(sig->length_signature * sizeof(unsigned char));

            break;
        }

        case DILIITHIUM_PRIVATE_KEY_SIZE_5 : {
                
            sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);

            ctx->signature = malloc(sig->length_signature * sizeof(unsigned char));

            break;
        }

        default: {
            pqsError(PRIVATE_KEY_SIZE_ERROR, __LINE__, __FUNCTION__);
            exit(EXIT_FAILURE);
        }
        
    }

    if (sig == NULL ){
            pqsError(ERROR_SIG_ALLOC, __LINE__, __FUNCTION__);
            exit(EXIT_FAILURE);
        }
    
    if (ctx->signature == NULL) {
                    pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                    exit(EXIT_FAILURE);
                }

    if (OQS_SIG_sign(sig, ctx->signature, &ctx->signatureSize, ctx->message, ctx->messageSize, ctx->privateKey) != OQS_SUCCESS) {
            pqsError(SIGNATURE_ERROR, __LINE__, __FUNCTION__);
            exit(EXIT_FAILURE);
        }

    OQS_SIG_free(sig);

}


////////////////////////////////////////
// dilithium verify sign
////////////////////////////////////////
int dilithiumVerifySign(PQS_SIGN_CTX *ctx) {
    if (ctx == NULL) {
        pqsError(ERROR_POINTER_NOT_DEFINE, __LINE__, __FUNCTION__);
        return 0;
    }

    if (ctx->message == NULL) {
        pqsError(MESSAGE_ERROR, __LINE__, __FUNCTION__);
        return 0;
    }

    if (ctx->publicKey == NULL) {
        pqsError(PUBLIC_KEY_ERROR, __LINE__, __FUNCTION__);
        return 0;
    }

    OQS_SIG *sig = NULL;

    switch (ctx->publicKeySize) {

        case DILIITHIUM_PUBLIC_KEY_SIZE_2: {
            sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
            break;
        }

        case DILIITHIUM_PUBLIC_KEY_SIZE_3: {
            sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
            break;
        }

        case DILIITHIUM_PUBLIC_KEY_SIZE_5: {
            sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
            break;
        }

        default: {
            pqsError(PUBLIC_KEY_SIZE_ERROR, __LINE__, __FUNCTION__);
            exit(EXIT_FAILURE);
        }
    }

    if (sig == NULL) {
        pqsError(ERROR_SIG_ALLOC, __LINE__, __FUNCTION__);
        exit(EXIT_FAILURE);
    }

    if (OQS_SIG_verify(sig, ctx->message, ctx->messageSize, ctx->signature, ctx->signatureSize, ctx->publicKey)!= OQS_SUCCESS) {
        pqsError(SIGNATURE_VERIFICATION_ERROR, __LINE__, __FUNCTION__);
        exit(EXIT_FAILURE);
    }

    OQS_SIG_free(sig);
    return PQS_DILIITHIUM_SIGNATURE_VERIFICATION_SUCCESS;
}