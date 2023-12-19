#include "kyber.h"

////////////////////////////////////////////////////////////////////////////////////////
// Kyber integration for PQS API                                                      //     
//                                                                                    //                          
// Kyber is a C library that implements the algorithm described in                    //
// "Kyber: a CCA-secure module-lattice-based KEM" by Eike Kiltz,                     ,//
// Alex Kyber, and Peter Schwabe, published in the proceedings of                     //
// CRYPTO 2017.                                                                       //
//                                                                                    //
// Project : kyber PQS                                                                //                    
// File    : kyber.c                                                                  //                
// Author  : Benedetti Christophe                                                     //
//                                                                                    //
// This code is provided under the MIT license.                                       //
// Please refer to the LICENSE file for licensing information.                        //
//                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////
// Kyber keygen
/////////////////////////////////////////////////////////
void genKyberKeyPair(PQS_KEYGEN_CTX* ctx, int keySize)
{
    if (ctx == NULL)
    {
        pqsError(CTX_IS_NULL, __LINE__, __FUNCTION__);
        return;
    }

    if (keySize != KYBER_PUBLIC_KEY_SIZE_512 && keySize != KYBER_PUBLIC_KEY_SIZE_768 && keySize != KYBER_PUBLIC_KEY_SIZE_1024 && keySize != KYBER_PUBLIC_KEY_SIZE_512_90S && keySize != KYBER_PUBLIC_KEY_SIZE_768_90S && keySize != KYBER_PUBLIC_KEY_SIZE_1024_90S)
    {
        pqsError(KEY_SIZE_ERROR, __LINE__, __FUNCTION__);
        return;
    }
    
    if (keySize == KYBER_PUBLIC_KEY_SIZE_512_90S || keySize == KYBER_PUBLIC_KEY_SIZE_768_90S || keySize == KYBER_PUBLIC_KEY_SIZE_1024_90S)
    {
        pqsError(CALL_FUNCTION_ERROR, __LINE__, __FUNCTION__);
    }
}

/////////////////////////////////////////////////////////
// Kyber encryption
/////////////////////////////////////////////////////////
void encryptKyber(PQS_ENCRYPT_CTX* ctx){

    if (ctx == NULL)
    {
        pqsError(CTX_IS_NULL, __LINE__, __FUNCTION__);
        return;
    }

    if (ctx->message == NULL)
    {
        pqsError(MESSAGE_ERROR, __LINE__, __FUNCTION__);
        return;
    }

    if (ctx->publicKey == NULL)
    {
        pqsError(PUBLIC_KEY_ERROR, __LINE__, __FUNCTION__);
        return;
    }

    if (ctx->keySize != KYBER_PUBLIC_KEY_SIZE_512 && ctx->keySize != KYBER_PUBLIC_KEY_SIZE_768 && ctx->keySize != KYBER_PUBLIC_KEY_SIZE_1024 && ctx->keySize != KYBER_PUBLIC_KEY_SIZE_512_90S && ctx->keySize != KYBER_PUBLIC_KEY_SIZE_768_90S && ctx->keySize != KYBER_PUBLIC_KEY_SIZE_1024_90S)
    {
        pqsError(KEY_SIZE_ERROR, __LINE__, __FUNCTION__);
        return;
    }

    if (ctx->keySize == KYBER_PUBLIC_KEY_SIZE_512_90S || ctx->keySize == KYBER_PUBLIC_KEY_SIZE_768_90S || ctx->keySize == KYBER_PUBLIC_KEY_SIZE_1024_90S)
    {
        pqsError(CALL_FUNCTION_ERROR, __LINE__, __FUNCTION__);
    }

    if (ctx->sharedSecret == NULL)
    {
        pqsError(SHARED_SECRET_ERROR, __LINE__, __FUNCTION__);
        return;
    }

    if (ctx->messageSize > KYBER_MAX_MESSAGE_SIZE)
    {
        pqsError(KYBER_MESSAGE_SIZE_ERROR, __LINE__, __FUNCTION__);
        return;
    }

    // Initialisation de l'objet KEM
    OQS_KEM *kem = NULL;

    switch (ctx->keySize) {

        case KYBER_PUBLIC_KEY_SIZE_512:
            kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
            break;

        case KYBER_PUBLIC_KEY_SIZE_768:
            kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
            break;

        case KYBER_PUBLIC_KEY_SIZE_1024:
            kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
            break;

        default:
            pqsError(KEY_SIZE_ERROR, __LINE__, __FUNCTION__);
            return;
    }

    if (kem == NULL) {
        pqsError(ERROR_SIG_ALLOC, __LINE__, __FUNCTION__);
        return;
    }

    // Encapsulation
    if (kem->encaps(ctx->keyExchangeToken, ctx->symetricKey, ctx->publicKey) != OQS_SUCCESS) {
        pqsError(ENCRYPTION_ERROR, __LINE__, __FUNCTION__);
        OQS_KEM_free(kem);
        return;
    }

    // Libération de la ressource
    OQS_KEM_free(kem);
}

////////////////////////////////////////////////////////////////////////////////////////
// Kyber decryption
////////////////////////////////////////////////////////////////////////////////////////
int decryptKyber(PQS_DECRYPT_CTX* ctx){

    if (ctx==NULL)
    {
        pqsError(CTX_IS_NULL, __LINE__, __FUNCTION__);
        return 1;
    }

    if (ctx->cipherText == NULL)
    {
        pqsError(MESSAGE_ERROR, __LINE__, __FUNCTION__);
        return 1;
    }

    if (ctx->privateKey == NULL)
    {
        pqsError(PRIVATE_KEY_ERROR, __LINE__, __FUNCTION__);
        return 1;
    }

    if (ctx->sharedSecret == NULL)
    {
        pqsError(SHARED_SECRET_ERROR, __LINE__, __FUNCTION__);
        return 1;
    }

    if (ctx->keySize != KYBER_PUBLIC_KEY_SIZE_512 && ctx->keySize != KYBER_PUBLIC_KEY_SIZE_768 && ctx->keySize != KYBER_PUBLIC_KEY_SIZE_1024 && ctx->keySize != KYBER_PUBLIC_KEY_SIZE_512_90S && ctx->keySize != KYBER_PUBLIC_KEY_SIZE_768_90S && ctx->keySize != KYBER_PUBLIC_KEY_SIZE_1024_90S)
    {
        pqsError(KEY_SIZE_ERROR, __LINE__, __FUNCTION__);
        return 1;
    }

    if (ctx->keySize == KYBER_PUBLIC_KEY_SIZE_512_90S || ctx->keySize == KYBER_PUBLIC_KEY_SIZE_768_90S || ctx->keySize == KYBER_PUBLIC_KEY_SIZE_1024_90S)
    {
        pqsError(CALL_FUNCTION_ERROR, __LINE__, __FUNCTION__);
    }

    OQS_KEM *kem ;

    switch (ctx-> keySize)
    {
        case KYBER_PUBLIC_KEY_SIZE_512:{
            
            kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
            break;
        }

        case KYBER_PUBLIC_KEY_SIZE_768: {
            kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
        }

        case KYBER_PUBLIC_KEY_SIZE_1024: {
            kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
        }

        default:
            pqsError(KEY_SIZE_ERROR, __LINE__, __FUNCTION__);
            break;
    }

    if (kem == NULL)
    {
        pqsError(ERROR_SIG_ALLOC, __LINE__, __FUNCTION__);
        return 1;
    }

    if (kem->decaps(ctx->symetricKey, ctx->keyExchangeToken, ctx->privateKey) != OQS_SUCCESS) {
        pqsError(DECRYPTION_ERROR, __LINE__, __FUNCTION__);
        OQS_KEM_free(kem);
        return 1;
    }

    OQS_KEM_free(kem);
    return 0;
}