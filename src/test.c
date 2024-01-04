#include "pqs.h"


int main(int argc, char const *argv[]) {

    int public_key_size = FALCON_PUBLIC_KEY_SIZE_512;
    int private_key_size = FALCON_PRIVATE_KEY_SIZE_512;
    int algorithm = FALCON_512;
    
    unsigned char pubKey [public_key_size];
    unsigned char privKey [private_key_size];

    // Create the context for key generation
    PQS_API_PARAM ctx;
    ctx.mode = KEY_GENERATION;
    ctx.algorithm = algorithm;
    ctx.publicKey = pubKey;
    ctx.privateKey = privKey;
    ctx.message = NULL;
    ctx.messageSize = 0;
    ctx.keySize = public_key_size; // Use the public key size for keySize
    ctx.output = NULL;

    // Call the API for key generation
    PQS_API(&ctx);

    printf("Public key: ");
    print_hex(pubKey, public_key_size);

    printf("Private key: ");
    print_hex(privKey, private_key_size);

    unsigned char signature [FALCON_SIGNATURE_MAX_SIZE_512];
    size_t signatureSize;

    PQS_API_PARAM ctx2;
    ctx2.mode = SIGNATURE;
    ctx2.algorithm = algorithm;
    ctx2.publicKey = pubKey;
    ctx2.privateKey = ctx.privateKey;
    ctx2.message = "Hello World!";
    ctx2.messageSize = strlen(ctx2.message);
    ctx2.keySize = private_key_size;
    ctx2.output = NULL;
    ctx2.signature = signature ;  
    ctx2.signatureSize = 0;

    PQS_API(&ctx2);

    printf("Signature size: %d\n", ctx2.signatureSize);

    printf("Signature: ");
    print_hex(signature, ctx2.signatureSize);

    int result;

    PQS_API_PARAM ctx3;
    ctx3.mode = SIGNATURE_VERIFICATION;
    ctx3.algorithm = algorithm;
    ctx3.publicKey = pubKey;
    ctx3.privateKey = privKey;
    ctx3.message = ctx2.message;
    ctx3.messageSize = ctx2.messageSize;
    ctx3.keySize = public_key_size;
    ctx3.output = &result;
    ctx3.signature = signature ;
    ctx3.signatureSize = ctx2.signatureSize;

    PQS_API(&ctx3);

    printf("Verification result: %d\n", result);




    

    OPENSSL_cleanup();

    return 0;
}
