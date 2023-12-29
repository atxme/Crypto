#include "pqs.h"

int main(int argc, char const *argv[]) {
    PQS_API_PARAM ctx;
    ctx.mode = KEY_GENERATION;
    ctx.algorithm = DILITHIUM_5;
    ctx.publicKey = malloc(DILIITHIUM_PUBLIC_KEY_SIZE_5);
    ctx.privateKey = malloc(DILIITHIUM_PRIVATE_KEY_SIZE_5);
    ctx.message = NULL;
    ctx.messageSize = 0;
    ctx.keySize = DILIITHIUM_PUBLIC_KEY_SIZE_5;
    ctx.output = NULL;

    // Initialisation de la mémoire allouée à zéro
    memset(ctx.publicKey, 0, DILIITHIUM_PUBLIC_KEY_SIZE_5);
    memset(ctx.privateKey, 0, DILIITHIUM_PRIVATE_KEY_SIZE_5);

    PQS_API(&ctx);

    unsigned char signature [DILIITHIUM_SIGNATURE_SIZE_5];

    PQS_API_PARAM ctx2;
    ctx2.mode = SIGNATURE;
    ctx2.algorithm = DILITHIUM_5;
    ctx2.publicKey = NULL;
    ctx2.privateKey = ctx.privateKey;
    ctx2.message = (unsigned char*) "Hello world";
    ctx2.messageSize = strlen((char*)ctx2.message);
    ctx2.keySize = DILIITHIUM_PRIVATE_KEY_SIZE_5;
    ctx2.output = malloc(DILIITHIUM_SIGNATURE_SIZE_5);

    PQS_API(&ctx2);

    printf("Signature : ");
    print_hex(ctx2.output, DILIITHIUM_SIGNATURE_SIZE_5);

    PQS_API_PARAM ctx3;
    ctx3.mode = SIGNATURE_VERIFICATION;
    ctx3.algorithm = DILITHIUM_5;
    ctx3.publicKey = ctx.publicKey;
    ctx3.privateKey = NULL;
    ctx3.message = (unsigned char*) "Hello world";
    ctx3.messageSize = strlen((char*)ctx3.message);
    ctx3.keySize = DILIITHIUM_PUBLIC_KEY_SIZE_5;
    ctx3.output = malloc(sizeof(int));
    ctx3.signature = ctx2.output;

    PQS_API(&ctx3);

    printf("Verification : %d\n", *(int*)ctx3.output);

    free(ctx2.output);
    free(ctx.publicKey);
    free(ctx.privateKey);

    OPENSSL_cleanup();

    return 0;
}
