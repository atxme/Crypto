#include "pqs.h"
#include "FALCON/falcon.h"
#include "KYBER/kyber.h"
#include "DILITHIUM/dilithium.h"
#include "PQS_ERROR/pqsError.h"
#include "ctxAlloc/ctxAlloc.h"

#include <oqs/oqs.h>


//////////////////////////////////////////////////////////////////////////////////////////
// VerifyParameters
//////////////////////////////////////////////////////////////////////////////////////////

void verifyParameter(int algorithmetype, 
                    int algorithm, 
                    unsigned char* publicKey, 
                    unsigned char* privateKey, 
                    unsigned char* message,
                    size_t messageSize,
                    int keySize) {
    
    // Vérification du type d'algorithme
    if (algorithmetype != ENCRYPTION && algorithmetype != DECRYPTION && algorithmetype != SIGNATURE && algorithmetype != KEY_GENERATION) {
        pqsError(ALGORITHME_TYPE_ERROR, __LINE__, __FUNCTION__);
        exit(0);
    }

    if (algorithm != FALCON_512 && 
        algorithm != FALCON_1024 && 
        algorithm != KYBER_512 && 
        algorithm != KYBER_768 && 
        algorithm != KYBER_1024 && 
        algorithm != KYBER_512_90S && 
        algorithm != KYBER_768_90S && 
        algorithm != KYBER_1024_90S && 
        algorithm != DILITHIUM_2 && 
        algorithm != DILITHIUM_3 && 
        algorithm != DILITHIUM_5 && 
        algorithm != DILITHIUM_2_AES && 
        algorithm != DILITHIUM_3_AES && 
        algorithm != DILITHIUM_5_AES)
    {
        pqsError(ALGORITHME_ERROR, __LINE__, __FUNCTION__);
        exit(0);
    }

    // Vérifications spécifiques pour chaque type d'opération
    switch(algorithmetype) {

        case ENCRYPTION:

            if (publicKey == NULL) {
                pqsError(PUBLIC_KEY_ERROR, __LINE__, __FUNCTION__);
                exit(EXIT_FAILURE);
            }
            break;

        case DECRYPTION:

            if (privateKey == NULL) {
                pqsError(PRIVATE_KEY_ERROR, __LINE__, __FUNCTION__);
                exit(EXIT_FAILURE);
            }
            break;

        case SIGNATURE:
            if (privateKey == NULL) {
                pqsError(PRIVATE_KEY_ERROR, __LINE__, __FUNCTION__);
                exit(EXIT_FAILURE);
            }
            break;
        
        case SIGNATURE_VERIFICATION:
            if (publicKey == NULL) {
                pqsError(SIGNATURE_ERROR, __LINE__, __FUNCTION__);
                exit(EXIT_FAILURE);
            }
            break;

        case KEY_GENERATION:

            if (keySize <= 0) {
                pqsError(KEY_SIZE_ERROR, __LINE__, __FUNCTION__);
                exit(EXIT_FAILURE);
            }
            break;

        default:
            // Pour ENCRYPTION et SIGNATURE, vérification du message
            if ((algorithmetype == ENCRYPTION || algorithmetype == SIGNATURE) && (message == NULL || messageSize <= 0)) {
                pqsError(MESSAGE_ERROR, __LINE__, __FUNCTION__);
                exit(EXIT_FAILURE);
            }
    }
}



void PQS_API(PQS_API_PARAM *ctx) {

    if (ctx == NULL) {
        pqsError(CTX_IS_NULL, __LINE__, __FUNCTION__);
        return;
    }

    switch (ctx->mode) {
        case KEY_GENERATION: {

            switch (ctx->algorithm) {
                case FALCON_512: {
                    PQS_KEYGEN_CTX *keygen_ctx = createPqsKeygenCtx(); 
                    if (keygen_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    falconKeyGen(keygen_ctx, FALCON_PUBLIC_KEY_SIZE_512);

                    // Assurez-vous que ctx->publicKey et ctx->privateKey sont préalablement alloués.
                    memcpy(ctx->publicKey, keygen_ctx->publicKey, FALCON_PUBLIC_KEY_SIZE_512);
                    memcpy(ctx->privateKey, keygen_ctx->privateKey, FALCON_PRIVATE_KEY_SIZE_512);

                    freePqsKeygenCtx(keygen_ctx);
                    break;
                }
                
                case FALCON_1024 : {
                    PQS_KEYGEN_CTX *keygen_ctx = createPqsKeygenCtx(); 
                    if (keygen_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    falconKeyGen(keygen_ctx, FALCON_PUBLIC_KEY_SIZE_1024);

                    // Assurez-vous que ctx->publicKey et ctx->privateKey sont préalablement alloués.
                    memcpy(ctx->publicKey, keygen_ctx->publicKey, FALCON_PUBLIC_KEY_SIZE_1024);
                    memcpy(ctx->privateKey, keygen_ctx->privateKey, FALCON_PRIVATE_KEY_SIZE_1024);

                    freePqsKeygenCtx(keygen_ctx);
                    break;
                }

                case KYBER_512 :{
                    PQS_KEYGEN_CTX *keygen_ctx = createPqsKeygenCtx(); 
                    if (keygen_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    genKyberKeyPair(keygen_ctx, KYBER_PUBLIC_KEY_SIZE_512);

                    // Assurez-vous que ctx->publicKey et ctx->privateKey sont préalablement alloués.
                    memcpy(ctx->publicKey, keygen_ctx->publicKey, KYBER_PUBLIC_KEY_SIZE_512);
                    memcpy(ctx->privateKey, keygen_ctx->privateKey, KYBER_PRIVATE_KEY_SIZE_512);

                    freePqsKeygenCtx(keygen_ctx);
                    break;
                }

                case KYBER_768 : {
                    PQS_KEYGEN_CTX *keygen_ctx = createPqsKeygenCtx(); 
                    if (keygen_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    genKyberKeyPair(keygen_ctx, KYBER_PUBLIC_KEY_SIZE_768);

                    // Assurez-vous que ctx->publicKey et ctx->privateKey sont préalablement alloués.
                    memcpy(ctx->publicKey, keygen_ctx->publicKey, KYBER_PUBLIC_KEY_SIZE_768);
                    memcpy(ctx->privateKey, keygen_ctx->privateKey, KYBER_PRIVATE_KEY_SIZE_768);

                    freePqsKeygenCtx(keygen_ctx);
                    break;
                }

                case KYBER_1024 : {
                    PQS_KEYGEN_CTX *keygen_ctx = createPqsKeygenCtx(); 
                    if (keygen_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    genKyberKeyPair(keygen_ctx, KYBER_PUBLIC_KEY_SIZE_1024);

                    // Assurez-vous que ctx->publicKey et ctx->privateKey sont préalablement alloués.
                    memcpy(ctx->publicKey, keygen_ctx->publicKey, KYBER_PUBLIC_KEY_SIZE_1024);
                    memcpy(ctx->privateKey, keygen_ctx->privateKey, KYBER_PRIVATE_KEY_SIZE_1024);

                    freePqsKeygenCtx(keygen_ctx);
                    break;
                }

                case DILITHIUM_2 : {
                    PQS_KEYGEN_CTX *keygen_ctx = createPqsKeygenCtx(); 
                    if (keygen_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    genDilithiumKeyPair(keygen_ctx, DILIITHIUM_PUBLIC_KEY_SIZE_2);

                    // Assurez-vous que ctx->publicKey et ctx->privateKey sont préalablement alloués.
                    memcpy(ctx->publicKey, keygen_ctx->publicKey, DILIITHIUM_PUBLIC_KEY_SIZE_2);
                    memcpy(ctx->privateKey, keygen_ctx->privateKey, DILIITHIUM_PRIVATE_KEY_SIZE_2);

                    freePqsKeygenCtx(keygen_ctx);
                    break;
                }

                case DILITHIUM_3 : {
                    PQS_KEYGEN_CTX *keygen_ctx = createPqsKeygenCtx(); 
                    if (keygen_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    genDilithiumKeyPair(keygen_ctx, DILIITHIUM_PUBLIC_KEY_SIZE_3);

                    // Assurez-vous que ctx->publicKey et ctx->privateKey sont préalablement alloués.
                    memcpy(ctx->publicKey, keygen_ctx->publicKey, DILIITHIUM_PUBLIC_KEY_SIZE_3);
                    memcpy(ctx->privateKey, keygen_ctx->privateKey, DILIITHIUM_PRIVATE_KEY_SIZE_3);

                    freePqsKeygenCtx(keygen_ctx);
                    break;
                }

                case DILITHIUM_5 : {
                    PQS_KEYGEN_CTX *keygen_ctx = createPqsKeygenCtx(); 
                    if (keygen_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    genDilithiumKeyPair(keygen_ctx, DILIITHIUM_PUBLIC_KEY_SIZE_5);

                    // Assurez-vous que ctx->publicKey et ctx->privateKey sont préalablement alloués.
                    memcpy(ctx->publicKey, keygen_ctx->publicKey, DILIITHIUM_PUBLIC_KEY_SIZE_5);
                    memcpy(ctx->privateKey, keygen_ctx->privateKey, DILIITHIUM_PRIVATE_KEY_SIZE_5);

                    freePqsKeygenCtx(keygen_ctx);
                    break;
                }

                break;
            }

            break;
        }

        case SIGNATURE : {
            printf("SIGNATURE\n");
            
            switch (ctx->algorithm) {

                case FALCON_512 : {
                    PQS_SIGN_CTX *sign_ctx = createPqsSignCtx();
                    if (sign_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }
                    sign_ctx->privateKey = malloc(FALCON_PRIVATE_KEY_SIZE_512);
                    sign_ctx->message = malloc(ctx->messageSize);

                    if (sign_ctx->privateKey == NULL || sign_ctx->message == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(sign_ctx->privateKey, ctx->privateKey, FALCON_PRIVATE_KEY_SIZE_512);
                    memcpy(sign_ctx->message, ctx->message, ctx->messageSize);

                    falconSign(sign_ctx);

                    ctx->output = malloc(FALCON_SIGNATURE_MAX_SIZE_512);
                    if (ctx->output == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(ctx->output, sign_ctx->signature, FALCON_SIGNATURE_MAX_SIZE_512);

                    freePqsSignCtx(sign_ctx);
                    break;
                }

                case FALCON_1024 : {
                    PQS_SIGN_CTX *sign_ctx = createPqsSignCtx();
                    if (sign_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }
                    sign_ctx->privateKey = malloc(FALCON_PRIVATE_KEY_SIZE_1024);
                    sign_ctx->message = malloc(ctx->messageSize);

                    if (sign_ctx->privateKey == NULL || sign_ctx->message == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(sign_ctx->privateKey, ctx->privateKey, FALCON_PRIVATE_KEY_SIZE_1024);
                    memcpy(sign_ctx->message, ctx->message, ctx->messageSize);

                    falconSign(sign_ctx);

                    ctx->output = malloc(FALCON_SIGNATURE_MAX_SIZE_1024);
                    if (ctx->output == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(ctx->output, sign_ctx->signature, FALCON_SIGNATURE_MAX_SIZE_1024);

                    freePqsSignCtx(sign_ctx);
                    break;
                }

                case DILITHIUM_2 :{
                    PQS_SIGN_CTX *sign_ctx = createPqsSignCtx();
                    if (sign_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }
                    sign_ctx->privateKey = malloc(DILIITHIUM_PRIVATE_KEY_SIZE_2);
                    sign_ctx->message = malloc(ctx->messageSize);
                    sign_ctx->privateKeySize = ctx->keySize;

                    if (sign_ctx->privateKey == NULL || sign_ctx->message == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(sign_ctx->privateKey, ctx->privateKey, DILIITHIUM_PRIVATE_KEY_SIZE_2);
                    memcpy(sign_ctx->message, ctx->message, ctx->messageSize);

                    dilithiumSign(sign_ctx);

                    ctx->output = malloc(DILIITHIUM_SIGNATURE_SIZE_2);
                    if (ctx->output == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(ctx->output, sign_ctx->signature, DILIITHIUM_SIGNATURE_SIZE_2);

                    freePqsSignCtx(sign_ctx);
                    break;
                }

                case DILITHIUM_3 :{
                    PQS_SIGN_CTX *sign_ctx = createPqsSignCtx();
                    if (sign_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }
                    sign_ctx->privateKey = malloc(DILIITHIUM_PRIVATE_KEY_SIZE_3);
                    sign_ctx->message = malloc(ctx->messageSize);
                    sign_ctx->privateKeySize = ctx->keySize;

                    if (sign_ctx->privateKey == NULL || sign_ctx->message == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(sign_ctx->privateKey, ctx->privateKey, DILIITHIUM_PRIVATE_KEY_SIZE_3);
                    memcpy(sign_ctx->message, ctx->message, ctx->messageSize);

                    dilithiumSign(sign_ctx);

                    ctx->output = malloc(DILIITHIUM_SIGNATURE_SIZE_3);
                    if (ctx->output == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(ctx->output, sign_ctx->signature, DILIITHIUM_SIGNATURE_SIZE_3);

                    freePqsSignCtx(sign_ctx);
                    break;
                }

                case DILITHIUM_5 :{
                    PQS_SIGN_CTX *sign_ctx = createPqsSignCtx();
                    if (sign_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }
                    sign_ctx->privateKey = malloc(DILIITHIUM_PRIVATE_KEY_SIZE_5);
                    sign_ctx->message = malloc(ctx->messageSize);
                    sign_ctx->privateKeySize = ctx->keySize;

                    if (sign_ctx->privateKey == NULL || sign_ctx->message == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(sign_ctx->privateKey, ctx->privateKey, DILIITHIUM_PRIVATE_KEY_SIZE_5);
                    memcpy(sign_ctx->message, ctx->message, ctx->messageSize);

                    dilithiumSign(sign_ctx);

                    ctx->output = malloc(DILIITHIUM_SIGNATURE_SIZE_5);
                    if (ctx->output == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(ctx->output, sign_ctx->signature, DILIITHIUM_SIGNATURE_SIZE_5);

                    freePqsSignCtx(sign_ctx);
                    break;
                }

                break;
            }

            break;
        }

        case SIGNATURE_VERIFICATION : {
        
            switch (ctx->algorithm) {
                case FALCON_512 : {
                    PQS_SIGN_CTX *sign_ctx = createPqsSignCtx();
                    if (sign_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }
                    sign_ctx->publicKey = malloc(FALCON_PUBLIC_KEY_SIZE_512);
                    sign_ctx->message = malloc(ctx->messageSize);
                    sign_ctx->signature = malloc(FALCON_SIGNATURE_MAX_SIZE_512);

                    if (sign_ctx->publicKey == NULL || sign_ctx->message == NULL || sign_ctx->signature == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(sign_ctx->publicKey, ctx->publicKey, FALCON_PUBLIC_KEY_SIZE_512);
                    memcpy(sign_ctx->message, ctx->message, ctx->messageSize);
                    memcpy(sign_ctx->signature, ctx->output, FALCON_SIGNATURE_MAX_SIZE_512);

                    int result = falconVerifySign(sign_ctx);

                    int* outputValue = malloc(sizeof(int));
                    // Affecter la valeur
                    *outputValue = (result == 0) ? 0 : 1;

                    // Assigner l'adresse au pointeur output
                    ctx->output = (void*)outputValue;

                    freePqsSignCtx(sign_ctx);
                    break;
                }

                case FALCON_1024 : {
                    PQS_SIGN_CTX *sign_ctx = createPqsSignCtx();
                    if (sign_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }
                    sign_ctx->publicKey = malloc(FALCON_PUBLIC_KEY_SIZE_1024);
                    sign_ctx->message = malloc(ctx->messageSize);
                    sign_ctx->signature = malloc(FALCON_SIGNATURE_MAX_SIZE_1024);

                    if (sign_ctx->publicKey == NULL || sign_ctx->message == NULL || sign_ctx->signature == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(sign_ctx->publicKey, ctx->publicKey, FALCON_PUBLIC_KEY_SIZE_1024);
                    memcpy(sign_ctx->message, ctx->message, ctx->messageSize);
                    memcpy(sign_ctx->signature, ctx->output, FALCON_SIGNATURE_MAX_SIZE_1024);

                    int result = falconVerifySign(sign_ctx);


                    if (ctx->output == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    int* outputValue = malloc(sizeof(int));
                    // Affecter la valeur
                    *outputValue = (result == 0) ? 0 : 1;

                    // Assigner l'adresse au pointeur output
                    ctx->output = (void*)outputValue;

                    freePqsSignCtx(sign_ctx);
                    break;
                }

                case DILITHIUM_2 :{
                    PQS_SIGN_CTX *sign_ctx = createPqsSignCtx();
                    if (sign_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }
                    sign_ctx->publicKey = malloc(DILIITHIUM_PUBLIC_KEY_SIZE_2);
                    sign_ctx->message = malloc(ctx->messageSize);
                    sign_ctx->signature = malloc(DILIITHIUM_SIGNATURE_SIZE_2);
                    sign_ctx->publicKeySize = ctx->keySize;

                    if (sign_ctx->publicKey == NULL || sign_ctx->message == NULL || sign_ctx->signature == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(sign_ctx->publicKey, ctx->publicKey, DILIITHIUM_PUBLIC_KEY_SIZE_2);
                    memcpy(sign_ctx->message, ctx->message, ctx->messageSize);
                    memcpy(sign_ctx->signature, ctx->output, DILIITHIUM_SIGNATURE_SIZE_2);

                    int result = dilithiumVerifySign(sign_ctx);

                    if (ctx->output == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    int* outputValue = malloc(sizeof(int));
                    // Affecter la valeur
                    *outputValue = (result == 0) ? 0 : 1;

                    // Assigner l'adresse au pointeur output
                    ctx->output = (void*)outputValue;

                    freePqsSignCtx(sign_ctx);
                    break;
                }

                case DILITHIUM_3 :{
                    PQS_SIGN_CTX *sign_ctx = createPqsSignCtx();
                    if (sign_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }
                    sign_ctx->publicKey = malloc(DILIITHIUM_PUBLIC_KEY_SIZE_3);
                    sign_ctx->message = malloc(ctx->messageSize);
                    sign_ctx->signature = malloc(DILIITHIUM_SIGNATURE_SIZE_3);
                    sign_ctx->publicKeySize = ctx->keySize;

                    if (sign_ctx->publicKey == NULL || sign_ctx->message == NULL || sign_ctx->signature == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(sign_ctx->publicKey, ctx->publicKey, DILIITHIUM_PUBLIC_KEY_SIZE_3);
                    memcpy(sign_ctx->message, ctx->message, ctx->messageSize);
                    memcpy(sign_ctx->signature, ctx->output, DILIITHIUM_SIGNATURE_SIZE_3);


                    int result = dilithiumVerifySign(sign_ctx);

                    int* outputValue = malloc(sizeof(int));
                    // Affecter la valeur
                    *outputValue = (result == 0) ? 0 : 1;

                    // Assigner l'adresse au pointeur output
                    ctx->output = (void*)outputValue;

                    freePqsSignCtx(sign_ctx);
                    break;
                }

                case DILITHIUM_5: {
                    PQS_SIGN_CTX *sign_ctx = createPqsSignCtx();
                    if (sign_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    sign_ctx->publicKey = malloc(DILIITHIUM_PUBLIC_KEY_SIZE_5);
                    sign_ctx->message = malloc(ctx->messageSize);
                    sign_ctx->signature = malloc(DILIITHIUM_SIGNATURE_SIZE_5);
                    sign_ctx->publicKeySize = ctx->keySize;

                    // Vérification des allocations de mémoire
                    if (sign_ctx->publicKey == NULL || sign_ctx->message == NULL || sign_ctx->signature == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);

                        // Libération de la mémoire allouée précédemment avant de retourner
                        if (sign_ctx->publicKey) free(sign_ctx->publicKey);
                        if (sign_ctx->message) free(sign_ctx->message);
                        if (sign_ctx->signature) free(sign_ctx->signature);
                        freePqsSignCtx(sign_ctx);
                        return;
                    }

                    memcpy(sign_ctx->publicKey, ctx->publicKey, DILIITHIUM_PUBLIC_KEY_SIZE_5);
                    memcpy(sign_ctx->message, ctx->message, ctx->messageSize);
                    memcpy(sign_ctx->signature, ctx->output, DILIITHIUM_SIGNATURE_SIZE_5);

                    int result = dilithiumVerifySign(sign_ctx);

                    // Suppression de la double allocation pour ctx->output
                    ctx->output = malloc(sizeof(int));
                    if (ctx->output == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        freePqsSignCtx(sign_ctx);
                        return;
                    }

                    // Stockage du résultat dans ctx->output
                    *((int*)ctx->output) = result ? 1 : 0;

                    freePqsSignCtx(sign_ctx);
                    break;
                }

                break;
            }

            break;
        }

        case ENCRYPTION : {
            switch (ctx->algorithm) {

                case KYBER_512 : {
                    PQS_ENCRYPT_CTX *encrypt_ctx = createPqsEncryptCtx();
                    if (encrypt_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }
                    encrypt_ctx->publicKey = malloc(KYBER_PUBLIC_KEY_SIZE_512);
                    encrypt_ctx->message = malloc(ctx->messageSize);
                    encrypt_ctx->keySize = KYBER_PUBLIC_KEY_SIZE_512;

                    if (encrypt_ctx->publicKey == NULL || encrypt_ctx->message == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(encrypt_ctx->publicKey, ctx->publicKey, KYBER_PUBLIC_KEY_SIZE_512);
                    memcpy(encrypt_ctx->message, ctx->message, ctx->messageSize);

                    encryptKyber(encrypt_ctx);

                    ctx->keyExchangeToken = malloc(KYBER_KEY_EXCHANGE_TOKEN_SIZE_512);
                    ctx->symmetricKey = malloc(KYBER_SYMMETRIC_KEY_SIZE);

                    if (ctx->keyExchangeToken == NULL || ctx->symmetricKey == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(ctx->keyExchangeToken, encrypt_ctx->keyExchangeToken, KYBER_KEY_EXCHANGE_TOKEN_SIZE_512);
                    memcpy(ctx->symmetricKey, encrypt_ctx->symmetricKey, KYBER_SYMMETRIC_KEY_SIZE);
                    
                    freePqsEncryptCtx(encrypt_ctx);
                    break;
                }

                case KYBER_768 : {
                    PQS_ENCRYPT_CTX *encrypt_ctx = createPqsEncryptCtx();
                    if (encrypt_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }
                    encrypt_ctx->publicKey = malloc(KYBER_PUBLIC_KEY_SIZE_768);
                    encrypt_ctx->message = malloc(ctx->messageSize);
                    encrypt_ctx->keySize = KYBER_PUBLIC_KEY_SIZE_768;

                    if (encrypt_ctx->publicKey == NULL || encrypt_ctx->message == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(encrypt_ctx->publicKey, ctx->publicKey, KYBER_PUBLIC_KEY_SIZE_768);
                    memcpy(encrypt_ctx->message, ctx->message, ctx->messageSize);

                    encryptKyber(encrypt_ctx);

                    ctx->keyExchangeToken = malloc(KYBER_KEY_EXCHANGE_TOKEN_SIZE_768);
                    ctx->symmetricKey = malloc(KYBER_SYMMETRIC_KEY_SIZE);

                    if (ctx->keyExchangeToken == NULL || ctx->symmetricKey == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(ctx->keyExchangeToken, encrypt_ctx->keyExchangeToken, KYBER_KEY_EXCHANGE_TOKEN_SIZE_768);
                    memcpy(ctx->symmetricKey, encrypt_ctx->symmetricKey, KYBER_SYMMETRIC_KEY_SIZE);
                    
                    freePqsEncryptCtx(encrypt_ctx);
                    break;
                }

                case KYBER_1024 : {
                    PQS_ENCRYPT_CTX *encrypt_ctx = createPqsEncryptCtx();
                    if (encrypt_ctx == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }
                    encrypt_ctx->publicKey = malloc(KYBER_PUBLIC_KEY_SIZE_1024);
                    encrypt_ctx->message = malloc(ctx->messageSize);
                    encrypt_ctx->keySize = KYBER_PUBLIC_KEY_SIZE_1024;

                    if (encrypt_ctx->publicKey == NULL || encrypt_ctx->message == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(encrypt_ctx->publicKey, ctx->publicKey, KYBER_PUBLIC_KEY_SIZE_1024);
                    memcpy(encrypt_ctx->message, ctx->message, ctx->messageSize);

                    encryptKyber(encrypt_ctx);

                    ctx->keyExchangeToken = malloc(KYBER_KEY_EXCHANGE_TOKEN_SIZE_1024);
                    ctx->symmetricKey = malloc(KYBER_SYMMETRIC_KEY_SIZE);

                    if (ctx->keyExchangeToken == NULL || ctx->symmetricKey == NULL) {
                        pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                        return;
                    }

                    memcpy(ctx->keyExchangeToken, encrypt_ctx->keyExchangeToken, KYBER_KEY_EXCHANGE_TOKEN_SIZE_1024);
                    memcpy(ctx->symmetricKey, encrypt_ctx->symmetricKey, KYBER_SYMMETRIC_KEY_SIZE);
                    
                    freePqsEncryptCtx(encrypt_ctx);
                    break;
                }

                break;
            
            }
            break;
                
        }

        case DECRYPTION : {
            switch (ctx->algorithm) 
                {
                    case KYBER_512 : {
                        PQS_DECRYPT_CTX *decrypt_ctx = createPqsDecryptCtx();
                        if (decrypt_ctx == NULL) {
                            pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                            return;
                        }
                        decrypt_ctx->privateKey = malloc(KYBER_PRIVATE_KEY_SIZE_512);
                        decrypt_ctx->keyExchangeToken = malloc(KYBER_KEY_EXCHANGE_TOKEN_SIZE_512);
                        decrypt_ctx->symmetricKey = malloc(KYBER_SYMMETRIC_KEY_SIZE);

                        if (decrypt_ctx->privateKey == NULL || decrypt_ctx->keyExchangeToken == NULL || decrypt_ctx->symmetricKey == NULL) {
                            pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                            return;
                        }

                        memcpy(decrypt_ctx->privateKey, ctx->privateKey, KYBER_PRIVATE_KEY_SIZE_512);
                        memcpy(decrypt_ctx->keyExchangeToken, ctx->keyExchangeToken, KYBER_KEY_EXCHANGE_TOKEN_SIZE_512);
                        memcpy(decrypt_ctx->symmetricKey, ctx->symmetricKey, KYBER_SYMMETRIC_KEY_SIZE);

                        decryptKyber(decrypt_ctx);

                        ctx->message = malloc(ctx->messageSize);

                        if (ctx->message == NULL) {
                            pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                            return;
                        }

                        memcpy(ctx->message, decrypt_ctx->message, ctx->messageSize);
                        
                        freePqsDecryptCtx(decrypt_ctx);
                        break;
                    }

                    case KYBER_768 : {
                        PQS_DECRYPT_CTX *decrypt_ctx = createPqsDecryptCtx();
                        if (decrypt_ctx == NULL) {
                            pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                            return;
                        }
                        decrypt_ctx->privateKey = malloc(KYBER_PRIVATE_KEY_SIZE_768);
                        decrypt_ctx->keyExchangeToken = malloc(KYBER_KEY_EXCHANGE_TOKEN_SIZE_768);
                        decrypt_ctx->symmetricKey = malloc(KYBER_SYMMETRIC_KEY_SIZE);

                        if (decrypt_ctx->privateKey == NULL || decrypt_ctx->keyExchangeToken == NULL || decrypt_ctx->symmetricKey == NULL) {
                            pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                            return;
                        }

                        memcpy(decrypt_ctx->privateKey, ctx->privateKey, KYBER_PRIVATE_KEY_SIZE_768);
                        memcpy(decrypt_ctx->keyExchangeToken, ctx->keyExchangeToken, KYBER_KEY_EXCHANGE_TOKEN_SIZE_768);

                        decryptKyber(decrypt_ctx);

                        ctx->symmetricKey = malloc(KYBER_SYMMETRIC_KEY_SIZE);

                        if (ctx->symmetricKey == NULL) {
                            pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                            return;
                        }

                        memcpy(ctx->symmetricKey, decrypt_ctx->symmetricKey, KYBER_SYMMETRIC_KEY_SIZE);

                        freePqsDecryptCtx(decrypt_ctx);
                        break;

                    }

                    case KYBER_1024 : {
                        PQS_DECRYPT_CTX *decrypt_ctx = createPqsDecryptCtx();
                        if (decrypt_ctx == NULL) {
                            pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                            return;
                        }
                        decrypt_ctx->privateKey = malloc(KYBER_PRIVATE_KEY_SIZE_1024);
                        decrypt_ctx->keyExchangeToken = malloc(KYBER_KEY_EXCHANGE_TOKEN_SIZE_1024);
                        decrypt_ctx->symmetricKey = malloc(KYBER_SYMMETRIC_KEY_SIZE);

                        if (decrypt_ctx->privateKey == NULL || decrypt_ctx->keyExchangeToken == NULL || decrypt_ctx->symmetricKey == NULL) {
                            pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                            return;
                        }

                        memcpy(decrypt_ctx->privateKey, ctx->privateKey, KYBER_PRIVATE_KEY_SIZE_1024);
                        memcpy(decrypt_ctx->keyExchangeToken, ctx->keyExchangeToken, KYBER_KEY_EXCHANGE_TOKEN_SIZE_1024);

                        decryptKyber(decrypt_ctx);

                        ctx->symmetricKey = malloc(KYBER_SYMMETRIC_KEY_SIZE);

                        if (ctx->symmetricKey == NULL) {
                            pqsError(MALLOC_ERROR, __LINE__, __FUNCTION__);
                            return;
                        }

                        memcpy(ctx->symmetricKey, decrypt_ctx->symmetricKey, KYBER_SYMMETRIC_KEY_SIZE);

                        freePqsDecryptCtx(decrypt_ctx);
                        break;

                    }

                    break;
                }
                break;
            }

    }
}
        
    