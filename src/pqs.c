#include "pqs.h"
#include <assert.h>



void print_hex(unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

void handleErrorMessage(int errorCode)
{
    bool isValid = false;
    for (int i=0; i< ERROR_CODE_COUNT - 1; i++)
    {
        if (errorCode == i)
        {
            isValid = true;
            break;
        }
    }

    if (!isValid)
    {
        printf("ERROR CODE IS NOT VALID\n");
        return;
    }

    switch (errorCode)
    {
        case ERROR_POINTER_NOT_DEFINE:
            printf("ERROR_POINTER_NOT_DEFINE\n");
            break;

        case ALGORITHME_TYPE_ERROR:
            printf("ALGORITHME_TYPE_ERROR\n");
            break;

        case ALGORITHME_ERROR:
            printf("ALGORITHME_ERROR\n");
            break;
        
        case PUBLIC_KEY_ERROR:
            printf("PUBLIC_KEY_ERROR\n");
            break;

        case PRIVATE_KEY_ERROR:
            printf("PRIVATE_KEY_ERROR\n");
            break;
        
        case MESSAGE_ERROR:
            printf("MESSAGE_ERROR\n");
            break;

        case SIGNATURE_ERROR:
            printf("SIGNATURE_ERROR\n");
            break;
        
        case SIGNATURE_VERIFICATION_ERROR:
            printf("SIGNATURE_VERIFICATION_ERROR\n");
            break;

        case ENCRYPTION_ERROR:
            printf("ENCRYPTION_ERROR\n");
            break;
        
        case DECRYPTION_ERROR:
            printf("DECRYPTION_ERROR\n");
            break;

        case KEY_SIZE_ERROR:
            printf("KEY_SIZE_ERROR\n");
            break;
        
        case PUBLIC_KEY_SIZE_ERROR:
            printf("PUBLIC_KEY_SIZE_ERROR\n");
            break;

        case PRIVATE_KEY_SIZE_ERROR:
            printf("PRIVATE_KEY_SIZE_ERROR\n");
            break;

        case SIGNATURE_SIZE_ERROR:
            printf("SIGNATURE_SIZE_ERROR\n");
            break;

        case ENCRYPTION_SIZE_ERROR:
            printf("ENCRYPTION_SIZE_ERROR\n");
            break;

        case DECRYPTION_SIZE_ERROR:
            printf("DECRYPTION_SIZE_ERROR\n");
            break;

        case MALLOC_ERROR:
            printf("MALLOC_ERROR\n");
            break;

        case ERROR_SIG_KEYGEN:
            printf("ERROR_SIG_KEYGEN\n");
            break;

        default:
            printf("ERROR CODE IS NOT VALID\n");
            break;
    }
    
}
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
        handleErrorMessage(ALGORITHME_TYPE_ERROR);
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
        handleErrorMessage(ALGORITHME_ERROR);
        exit(0);
    }

    // Vérifications spécifiques pour chaque type d'opération
    switch(algorithmetype) {

        case ENCRYPTION:

            if (publicKey == NULL) {
                handleErrorMessage(PUBLIC_KEY_ERROR);
                exit(EXIT_FAILURE);
            }
            break;
        case DECRYPTION:

            if (privateKey == NULL) {
                handleErrorMessage(PRIVATE_KEY_ERROR);
                exit(EXIT_FAILURE);
            }
            break;

        case SIGNATURE:
            if (privateKey == NULL) {
                handleErrorMessage(PRIVATE_KEY_ERROR);
                exit(EXIT_FAILURE);
            }
            break;
        
        case SIGNATURE_VERIFICATION:
            if (publicKey == NULL) {
                handleErrorMessage(PUBLIC_KEY_ERROR);
                exit(EXIT_FAILURE);
            }
            break;

        case KEY_GENERATION:

            if (keySize <= 0) {
                handleErrorMessage(KEY_SIZE_ERROR);
                exit(EXIT_FAILURE);
            }
            break;

        default:
            // Pour ENCRYPTION et SIGNATURE, vérification du message
            if ((algorithmetype == ENCRYPTION || algorithmetype == SIGNATURE) && (message == NULL || messageSize <= 0)) {
                handleErrorMessage(MESSAGE_ERROR);
                exit(EXIT_FAILURE);
            }
    }
}

//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

void genFalconKeyPair(PQS_KEYGEN_CTX *ctx, unsigned int keySize)
{
    if (keySize != FALCON_PUCLIC_KEY_SIZE_1024 && keySize != FALCON_PUBLIC_KEY_SIZE_512 )  //key size management for falcon
    {
        handleErrorMessage(KEY_SIZE_ERROR);
        exit(0);
    }

    OQS_SIG *sig;

    switch(keySize){

        case FALCON_PUCLIC_KEY_SIZE_1024:
            sig = OQS_SIG_new(OQS_SIG_alg_falcon_1024);
            
            if (sig == NULL) {
                printf("ERROR: OQS_SIG_new failed\n");
                exit(EXIT_FAILURE);
            }
            
            ctx->publicKey = malloc(sig->length_public_key * sizeof(unsigned char));
            ctx->privateKey = malloc(sig->length_secret_key * sizeof(unsigned char));

            if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
                printf("ERROR: malloc failed\n");
                exit(EXIT_FAILURE);
            }
            
            OQS_SIG_keypair(sig, ctx->publicKey, ctx->privateKey);

            break;

        case FALCON_PUBLIC_KEY_SIZE_512:

            sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
            
            if (sig == NULL) {
                printf("ERROR: OQS_SIG_new failed\n");
                exit(EXIT_FAILURE);
            }
            
            ctx->publicKey = malloc(sig->length_public_key * sizeof(unsigned char));
            ctx->privateKey = malloc(sig->length_secret_key * sizeof(unsigned char));

            if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
                printf("ERROR: malloc failed\n");
                exit(EXIT_FAILURE);
            }
            
            OQS_SIG_keypair(sig, ctx->publicKey, ctx->privateKey); //OQS API CALL
            
            break;

        default:
            handleErrorMessage(KEY_SIZE_ERROR);
            exit(0);
    }
}

void genKyberKeyPair(PQS_KEYGEN_CTX *ctx, unsigned int keySize)
{

    if (keySize != KYBER_PUBLIC_KEY_SIZE_512 && keySize != KYBER_PUBLIC_KEY_SIZE_768 && keySize != KYBER_PUBLIC_KEY_SIZE_1024)  //key size management for kyber
    {
        handleErrorMessage(KEY_SIZE_ERROR);
        exit(0);
    }

    OQS_KEM *kem;

    switch(keySize){

        case KYBER_PUBLIC_KEY_SIZE_512:
            kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
            
            if (kem == NULL) {
                printf("ERROR: OQS_KEM_new failed\n");
                exit(EXIT_FAILURE);
            }
            
            ctx->publicKey = malloc(kem->length_public_key * sizeof(unsigned char));
            ctx->privateKey = malloc(kem->length_secret_key * sizeof(unsigned char));

            if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
                printf("ERROR: malloc failed\n");
                exit(EXIT_FAILURE);
            }
            
            OQS_KEM_keypair(kem, ctx->publicKey, ctx->privateKey);

            break;

        case KYBER_PUBLIC_KEY_SIZE_768:

            kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
            
            if (kem == NULL) {
                printf("ERROR: OQS_KEM_new failed\n");
                exit(EXIT_FAILURE);
            }
            
            ctx->publicKey = malloc(kem->length_public_key * sizeof(unsigned char));
            ctx->privateKey = malloc(kem->length_secret_key * sizeof(unsigned char));

            if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
                printf("ERROR: malloc failed\n");
                exit(EXIT_FAILURE);
            }
            
            OQS_KEM_keypair(kem, ctx->publicKey, ctx->privateKey); //OQS API CALL
            
            break;

        case KYBER_PUBLIC_KEY_SIZE_1024:

            kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
            
            if (kem == NULL) {
                printf("ERROR: OQS_KEM_new failed\n");
                exit(EXIT_FAILURE);
            }
            
            ctx->publicKey = malloc(kem->length_public_key * sizeof(unsigned char));
            ctx->privateKey = malloc(kem->length_secret_key * sizeof(unsigned char));

            if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
                printf("ERROR: malloc failed\n");
                exit(EXIT_FAILURE);
            }

            OQS_KEM_keypair(kem, ctx->publicKey, ctx->privateKey); //OQS API CALL

            break;
    }

}

void genDilithiumKeyPair(PQS_KEYGEN_CTX *ctx, unsigned int diliithiumKeySize){
    if (ctx == NULL)
    {
        handleErrorMessage(ERROR_POINTER_NOT_DEFINE);
        exit(0);
    }

    if(diliithiumKeySize != DILIITHIUM_PUBLIC_KEY_SIZE_2 && diliithiumKeySize != DILIITHIUM_PUBLIC_KEY_SIZE_3 && diliithiumKeySize != DILIITHIUM_PUBLIC_KEY_SIZE_5)
    {
        handleErrorMessage(KEY_SIZE_ERROR);
        exit(0);
    }

    OQS_SIG *sig;

    switch (diliithiumKeySize){

        case (DILIITHIUM_PUBLIC_KEY_SIZE_2):

            sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);

            if (sig == NULL) {
                printf("ERROR: OQS_SIG_new failed\n");
                exit(EXIT_FAILURE);
            }

            ctx->publicKey = malloc(sig->length_public_key * sizeof(unsigned char));
            ctx->privateKey = malloc(sig->length_secret_key * sizeof(unsigned char));

            if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
                printf("ERROR: malloc failed\n");
                exit(EXIT_FAILURE);
            }

            OQS_SIG_keypair(sig, ctx->publicKey, ctx ->privateKey); //OQS API CALL

            break;

        case (DILIITHIUM_PUBLIC_KEY_SIZE_3):

            sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);

            if (sig == NULL ){
                handleErrorMessage(ERROR_SIG_KEYGEN);
                exit(EXIT_FAILURE);
            }

            ctx->publicKey = malloc(sig->length_public_key * sizeof(unsigned char));
            ctx->privateKey = malloc(sig->length_secret_key * sizeof(unsigned char));

            if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
                printf("ERROR: malloc failed\n");
                exit(EXIT_FAILURE);
            }

            OQS_SIG_keypair(sig, ctx->publicKey, ctx->privateKey); //OQS API CALL

            break;

        case (DILIITHIUM_PUBLIC_KEY_SIZE_5):

            sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);

            if (sig == NULL ){
                handleErrorMessage(ERROR_SIG_KEYGEN);
                exit(EXIT_FAILURE);
            }

            ctx->publicKey = malloc(sig->length_public_key * sizeof(unsigned char));
            ctx->privateKey = malloc(sig->length_secret_key * sizeof(unsigned char));

            if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
                printf("ERROR: malloc failed\n");
                exit(EXIT_FAILURE);
            }

            OQS_SIG_keypair(sig, ctx->publicKey, ctx->privateKey); //OQS API CALL

            break;

    }
}
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////


void PQS_API(int algorithmetype, int algorithm, unsigned char* publicKey, unsigned char* privateKey, unsigned char* message,size_t messageSize ,int keySize, void* API_CALL_RETURN)
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
    param->keySize = keySize;
    param->output= API_CALL_RETURN;

    switch (algorithmetype){

        case ENCRYPTION :
            
            break;

        case DECRYPTION :
            
            break;

        case SIGNATURE :
            
            break;

        case SIGNATURE_VERIFICATION :
                
            break;

        case KEY_GENERATION :
            
            printf("key size : %d\n", keySize);
            switch (algorithm){

                case FALCON_1024 :
                    genFalconKeyPair(API_CALL_RETURN, keySize);
                    break;

                case FALCON_512 :
                    genFalconKeyPair(API_CALL_RETURN, keySize);
                    break;

                case KYBER_512 :
                    genKyberKeyPair(API_CALL_RETURN, keySize);
                    break;

                case KYBER_768 :
                    genKyberKeyPair(API_CALL_RETURN, keySize);
                    break;

                case KYBER_1024 :
                    genKyberKeyPair(API_CALL_RETURN, keySize);
                    break;

                case KYBER_512_90S :
                    genKyberKeyPair(API_CALL_RETURN, keySize);
                    break;

                case KYBER_768_90S :
                    genKyberKeyPair(API_CALL_RETURN, keySize);
                    break;

                case KYBER_1024_90S :
                    genKyberKeyPair(API_CALL_RETURN, keySize);
                    break;

                case DILITHIUM_2 :
                    genDilithiumKeyPair(API_CALL_RETURN, keySize);
                    break;

                case DILITHIUM_3 :
                    genDilithiumKeyPair(API_CALL_RETURN, keySize);
                    break;

                case DILITHIUM_5 :
                    genDilithiumKeyPair(API_CALL_RETURN, keySize);
                    break;

                case DILITHIUM_2_AES :
                    genDilithiumKeyPair(API_CALL_RETURN, keySize);
                    break;

                case DILITHIUM_3_AES :
                    genDilithiumKeyPair(API_CALL_RETURN, keySize);
                    break;

                case DILITHIUM_5_AES :
                    genDilithiumKeyPair(API_CALL_RETURN, keySize);
                    break;

            }
            break;
        
    }

}

