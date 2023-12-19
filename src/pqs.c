#include "pqs.h"
#include "FALCON/falcon.h"
#include "KYBER/kyber.h"
#include "DILITHIUM/dilithium.h"
#include "PQS_ERROR/pqsError.h"
#include <assert.h>


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



void PQS_API(int algorithmetype, int algorithm, unsigned char* publicKey, unsigned char* privateKey, unsigned char* message,size_t messageSize ,int keySize, void** API_CALL_RETURN)
{
    verifyParameter(algorithmetype,
                    algorithm,
                    publicKey,
                    privateKey,
                    message,
                    messageSize,
                    keySize);

    PQS_API_PARAM *param = (PQS_API_PARAM*)malloc(sizeof(PQS_API_PARAM));
    param->algorithmetype = algorithmetype;
    param->algorithm = algorithm;
    param->publicKey = publicKey;
    param->privateKey = privateKey;
    param->message = message;
    param->messageSize = messageSize;
    param->keySize =(size_t)keySize;
    

    if (algorithmetype == KEY_GENERATION)
    {
        PQS_KEYGEN_CTX ctx;
        ctx.publicKey [FALCON_PUBLIC_KEY_SIZE_1024] ;
        ctx.privateKey [FALCON_PRIVATE_KEY_SIZE_1024];


        falconKeyGen(&ctx, param->keySize);

        *API_CALL_RETURN = &ctx;
    }

}

int main(int argc, char const *argv[]) {
    PQS_KEYGEN_CTX falcon_ctx;
    memset(&falcon_ctx, 0, sizeof(falcon_ctx)); // Initialiser le contexte

    PQS_API(KEY_GENERATION, FALCON_1024, NULL, NULL, NULL, 0, FALCON_PUBLIC_KEY_SIZE_1024, &falcon_ctx);
    printf("public key : %s\n", falcon_ctx.publicKey);
    printf("private key : %s\n", falcon_ctx.privateKey);

    return 0;
}
