#include "dilithium.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // Création et initialisation du contexte de génération de clés
    PQS_KEYGEN_CTX keygen_ctx;
    genDilithiumKeyPair(&keygen_ctx, DILIITHIUM_PUBLIC_KEY_SIZE_3);

    // Préparation du message à signer
    const char *message = "Exemple de message";
    size_t message_len = strlen(message);

    // Création et initialisation du contexte de signature
    PQS_SIGN_CTX sign_ctx;
    sign_ctx.message = (unsigned char *)message;
    sign_ctx.messageSize = message_len;
    sign_ctx.privateKey = keygen_ctx.privateKey;
    sign_ctx.signature = malloc(DILIITHIUM_SIGNATURE_SIZE_3);
    sign_ctx.signatureSize = DILIITHIUM_SIGNATURE_SIZE_3;
    sign_ctx.privateKeySize = DILIITHIUM_PRIVATE_KEY_SIZE_3;

    // Signature du message
    dilithiumSign(&sign_ctx);
    /*
    printf("publicKey :");
    for (size_t i = 0; i < DILIITHIUM_PUBLIC_KEY_SIZE_3; i++) {
        printf("%02x", keygen_ctx.publicKey[i]);
    }

    printf("\n");

    printf("privateKey :");
    for (size_t i = 0; i < sign_ctx.privateKeySize; i++) {
        printf("%02x", keygen_ctx.privateKey[i]);
    }

    printf("\n");
    
    // Impression de la signature
    printf("Signature : ");
    for (size_t i = 0; i < sign_ctx.signatureSize; i++) {
        printf("%02x", sign_ctx.signature[i]);
    }
    printf("\n");

    printf("signature size : %d\n", sign_ctx.signatureSize);

    */
    // Création et initialisation du contexte de vérification de signature
    PQS_SIGN_CTX verify_ctx;
    verify_ctx.publicKey = keygen_ctx.publicKey;
    verify_ctx.message = sign_ctx.message;
    verify_ctx.messageSize = sign_ctx.messageSize;
    verify_ctx.signature = sign_ctx.signature;
    verify_ctx.signatureSize = sign_ctx.signatureSize;
    verify_ctx.publicKeySize = DILIITHIUM_PUBLIC_KEY_SIZE_3;

    // Vérification de la signature
    int verify_result = dilithiumVerifySign(&verify_ctx);

    if (verify_result == PQS_DILIITHIUM_SIGNATURE_VERIFICATION_SUCCESS) {
        printf("Signature valide.\n");
    } else {
        printf("Signature invalide.\n");
    }

    // Nettoyage et libération de la mémoire
    free(sign_ctx.signature);
    // Assurez-vous également de libérer toute autre mémoire allouée dans les contextes de clés

    return 0;
}
