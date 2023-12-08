#include "pqs.h"


int main(int argc, char* argv[]) {
    PQS_KEYGEN_CTX keygenCtx;

    // Initialiser keygenCtx si nécessaire
    keygenCtx.publicKey = NULL;
    keygenCtx.privateKey = NULL;

    // Appel de la fonction PQS_API pour la génération de clés Falcon 1024
    PQS_API(KEY_GENERATION, KYBER_1024, NULL, NULL, NULL, 0, KYBER_PUBLIC_KEY_SIZE_1024, &keygenCtx);

    print_hex(keygenCtx.publicKey, FALCON_PUCLIC_KEY_SIZE_1024);
    print_hex(keygenCtx.privateKey, FALCON_PRIVATE_KEY_SIZE_1024);

    // N'oubliez pas de libérer les ressources allouées
    free(keygenCtx.publicKey);
    free(keygenCtx.privateKey);

    return 0;
}