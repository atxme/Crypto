#include "dilithium.h"

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

//void pqsError(PQS_ERROR error_code, const char *file, int line, const char *function)

////////////////////////////////////////
// dilithium keyPair generation
////////////////////////////////////////
void genDilithiumKeyPair(PQS_KEYGEN_CTX *ctx, unsigned int dilithiumKeySize){

    if (ctx == NULL){
        pqsError(CTX_IS_NULL, __LINE__, "genDilithiumKeyPair");
        return;
    }

    if(dilithiumKeySize != DILIITHIUM_PUBLIC_KEY_SIZE_2 && dilithiumKeySize != DILIITHIUM_PUBLIC_KEY_SIZE_3 && dilithiumKeySize != DILIITHIUM_PUBLIC_KEY_SIZE_5)
    {
        pqsError(KEY_SIZE_ERROR, __LINE__, "genDilithiumKeyPair");
        exit(0);
    }

    OQS_SIG *sig;

    switch (dilithiumKeySize){

        case (DILIITHIUM_PUBLIC_KEY_SIZE_2):

            sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);

            if (sig == NULL) {
                pqsError(ERROR_SIG_KEYGEN,__LINE__,"genDilithiumKeyPair");
                exit(EXIT_FAILURE);
            }

            ctx->publicKey = malloc(sig->length_public_key * sizeof(unsigned char));
            ctx->privateKey = malloc(sig->length_secret_key * sizeof(unsigned char));

            if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
                pqsError(MALLOC_ERROR, __LINE__, "genDilithiumKeyPair");
                exit(EXIT_FAILURE);
            }

            OQS_SIG_keypair(sig, ctx->publicKey, ctx ->privateKey); //OQS API CALL

            break;

        case (DILIITHIUM_PUBLIC_KEY_SIZE_3):

            sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);

            if (sig == NULL ){
                pqsError(ERROR_SIG_KEYGEN, __LINE__, "genDilithiumKeyPair");
                exit(EXIT_FAILURE);
            }

            ctx->publicKey = malloc(sig->length_public_key * sizeof(unsigned char));
            ctx->privateKey = malloc(sig->length_secret_key * sizeof(unsigned char));

            if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
                pqsError(MALLOC_ERROR, __LINE__, "genDilithiumKeyPair");
                exit(EXIT_FAILURE);
            }

            OQS_SIG_keypair(sig, ctx->publicKey, ctx->privateKey); //OQS API CALL

            break;

        case (DILIITHIUM_PUBLIC_KEY_SIZE_5):

            sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);

            if (sig == NULL ){
                pqsError(ERROR_SIG_KEYGEN, __LINE__, "genDilithiumKeyPair");
                exit(EXIT_FAILURE);
            }

            ctx->publicKey = malloc(sig->length_public_key * sizeof(unsigned char));
            ctx->privateKey = malloc(sig->length_secret_key * sizeof(unsigned char));

            if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
                pqsError(MALLOC_ERROR, __LINE__, "genDilithiumKeyPair");
                exit(EXIT_FAILURE);
            }

            OQS_SIG_keypair(sig, ctx->publicKey, ctx->privateKey); //OQS API CALL

            break;

    }
}

////////////////////////////////////////
// dilithium sign
////////////////////////////////////////

void dilithiumSign(PQS_SIGN_CTX *ctx)
{
    if (ctx == NULL){
        pqsError(ERROR_POINTER_NOT_DEFINE,__LINE__,"dilithiumSign");
        return;
    }

    if (ctx->message == NULL){
        pqsError(MESSAGE_ERROR, __LINE__,"dilithiumSign");
        return ;
    }

    if (ctx->privateKey == NULL){
        pqsError(PRIVATE_KEY_ERROR,__LINE__, "dilithiumSign");
        return;
    }

    if (ctx->signatureSize != DILIITHIUM_SIGNATURE_SIZE_2 || ctx->signatureSize != DILIITHIUM_SIGNATURE_SIZE_3 || ctx->signatureSize != DILIITHIUM_SIGNATURE_SIZE_5 ){
        pqsError(SIGNATURE_ERROR,__LINE__, "dilithiumSign");
        return;
    }
}


////////////////////////////////////////
// dilithium verify sign
////////////////////////////////////////
int dilithiumVerifySign(PQS_SIGN_CTX *ctx)
{

}
