#include "falcon.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // Création et initialisation du contexte de génération de clés
    PQS_KEYGEN_CTX keygen_ctx;
    memset(&keygen_ctx, 0, sizeof(keygen_ctx));
    keygen_ctx.publicKey = malloc(FALCON_PUBLIC_KEY_SIZE_1024);
    keygen_ctx.privateKey = malloc(FALCON_PRIVATE_KEY_SIZE_1024);

    // Génération de la paire de clés
    falconKeyGen(&keygen_ctx, FALCON_PUBLIC_KEY_SIZE_1024);
    

    // Création et initialisation du contexte de signature
    PQS_SIGN_CTX sign_ctx;
    memset(&sign_ctx, 0, sizeof(sign_ctx));
    sign_ctx.privateKey = keygen_ctx.privateKey;
    sign_ctx.message = (unsigned char*)"Exemple de message";
    sign_ctx.messageSize = strlen((char*)sign_ctx.message);
    sign_ctx.signature = malloc(FALCON_SIGNATURE_MAX_SIZE_1024);
    sign_ctx.privateKeySize = FALCON_PRIVATE_KEY_SIZE_1024;

    // Signature du message
    falconSign(&sign_ctx);

    // Impression de la signature
    printf("Signature : ");
    for (size_t i = 0; i < sign_ctx.signatureSize; i++) {
        printf("%02x", sign_ctx.signature[i]);
    }
    printf("\n");
    printf("%d", sign_ctx.signatureSize);
    printf("\n");

    // Création et initialisation du contexte de vérification de signature
    PQS_SIGN_CTX verify_ctx;
    memset(&verify_ctx, 0, sizeof(verify_ctx));
    verify_ctx.publicKey = keygen_ctx.publicKey;
    verify_ctx.message = sign_ctx.message;
    verify_ctx.messageSize = sign_ctx.messageSize;
    verify_ctx.signature = sign_ctx.signature;
    verify_ctx.signatureSize = sign_ctx.signatureSize; 
    verify_ctx.publicKeySize = FALCON_PUBLIC_KEY_SIZE_1024;

    // Vérification de la signature
    int verify_result = falconVerifySign(&verify_ctx);

    if (verify_result == 0) {
        printf("Signature valide.\n");
    } else {
        printf("Signature invalide.\n");
    }

    // Nettoyage et libération de la mémoire
    free(keygen_ctx.publicKey);
    free(keygen_ctx.privateKey);
    free(sign_ctx.signature); // Libération de la mémoire allouée pour la signature

    return 0;
}