////////////////////////////////////////////////////////////////////////////////////////
// Context Integration for PQS API
//
// This file is a part of the "PQS" Post Quantum Security project.
// This code provides all the context for the PQS API.
//
// Project: PQS Crypto
// File: pqsCtx.h
// Author: Benedetti Christophe
//
// This code is provided under the MIT license.
// Please refer to the LICENSE file for licensing information.
//
////////////////////////////////////////////////////////////////////////////////////////

#ifndef PQS_CTX_H
#define PQS_CTX_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <oqs/oqs.h>
#include <stddef.h>

////////////////////////////////////////////////////////////////////////////////////////
// CONTEXT FOR PQS_API_PARAM
//
/// @brief This struct is used to pass parameters to the API.
/// @details You must correctly define the API call by specifying all parameters.
///          If you don't need a parameter, just pass NULL, and the API will accept the call.
//
/// @param algorithmetype: The type of algorithm to use.
/// @param algorithm: The algorithm to use.
/// @param publicKey: The public key to use for encryption/decryption/signature verification.
/// @param privateKey: The private key to use for encryption/decryption/signature.
/// @param message: The message to encrypt/decrypt.
/// @param messageSize: The size of the message to encrypt/decrypt.
/// @param keySize: The size of the key to generate.
/// @param output: The output of the API.
//
////////////////////////////////////////////////////////////////////////////////////////
typedef struct PQS_API_PARAM {
    int algorithmetype;           // Type of algorithm to use
    int algorithm;                // Algorithm to use
    unsigned char* publicKey;     // Public key for encryption/decryption/signature verification
    unsigned char* privateKey;    // Private key for encryption/decryption/signature
    unsigned char* message;       // Message to encrypt/decrypt
    size_t messageSize;           // Size of the message to encrypt/decrypt
    size_t keySize;               // Size of the key to generate
    void* output;                 // API output
} PQS_API_PARAM;


////////////////////////////////////////////////////////////////////////////////////////
// CONTEXT FOR PQS_KEY_GEN RETURN
//
/// @brief This struct is used to return the key pair from the API.
/// @details When using this struct, ensure that you correctly define the API call by providing all necessary parameters.
//
/// @param publicKey: The generated public key will be stored here.
/// @param privateKey: The generated private key will be stored here.
/// @param isogeny: An integer representing isogeny information.
//
////////////////////////////////////////////////////////////////////////////////////////
typedef struct PQS_KEYGEN_CTX {
    unsigned char *publicKey;
    unsigned char *privateKey;
    int isogeny;
} PQS_KEYGEN_CTX;


////////////////////////////////////////////////////////////////////////////////////////
// CONTEXT FOR PQS ENCRYPTION RETURN
//
/// @brief This struct is used for key negation and encryption.
///
/// @details You must correctly define the API call by specifying all necessary parameters.
///
/// @param message: The message to encrypt.
/// @param publicKey: The public key to use for encryption.
/// @param privateKey: The private key to use for encryption.
/// @param cipherText: The encrypted message will be stored here.
/// @param cipherTextSize: The size of the encrypted message.
/// @param sharedSecret: The shared secret between the two parties.
/// @param sharedSecretSize: The size of the shared secret.
/// @param keyExchangeToken: The key exchange token.
/// @param symmetricKey: The symmetric key.
/// @param keySize: The size of the key.
/// @param messageSize: The size of the message.
//
////////////////////////////////////////////////////////////////////////////////////////
typedef struct PQS_ENCRYPT_CTX {
    unsigned char *publicKey;
    unsigned char *privateKey;
    unsigned char *message;
    unsigned char *cipherText;
    size_t cipherTextSize;
    unsigned char *sharedSecret;
    size_t sharedSecretSize;
    unsigned char *keyExchangeToken;
    unsigned char *symmetricKey;
    size_t keySize;
    size_t messageSize;
} PQS_ENCRYPT_CTX;


////////////////////////////////////////////////////////////////////////////////////////
// CONTEXT FOR PQS DECRYPTION RETURN
//
/// @brief This struct is used to return the decrypted message from the API.
/// @brief You must define correctly the call off the API by defining all parameters.
//
/// @param cipherText: The cipher text to decrypt.
/// @param publicKey: The public key to use for decryption.
/// @param privateKey: The private key to use for decryption.
/// @param message: The decrypted message.
/// @param keyExchangeToken: The key exchange token.
/// @param symmetricKey: The symmetric key.
/// @param keySize: The size of the key.
/// @param messageSize: The size of the message.
/// @param sharedSecretSize: The size of the shared secret.
//
////////////////////////////////////////////////////////////////////////////////////////
typedef struct PQS_DECRYPT_CTX {
    unsigned char* cipherText;
    unsigned char* publicKey;
    unsigned char* privateKey;
    unsigned char* message;
    unsigned char* keyExchangeToken;
    unsigned char* symmetricKey;
    size_t keySize;
    size_t messageSize;
    size_t sharedSecretSize;
} PQS_DECRYPT_CTX;


////////////////////////////////////////////////////////////////////////////////////////
// CONTEXT FOR PQS SIGNATURE RETURN
//
/// @brief This struct is used to return the signature from the API.
/// @brief You must define correctly the call off the API by defining all parameters.
//
/// @param message: The message to sign.
/// @param privateKey: The private key to use for signature -> NULL if verify call.
/// @param publicKey: The public key to use for signature verification -> NULL if sign call.
/// @param signature: The signature.
/// @param publicKeySize: The size of the public key.
/// @param privateKeySize: The size of the private key.
/// @param signatureSize: The size of the signature.
/// @param messageSize: The size of the message.
//
////////////////////////////////////////////////////////////////////////////////////////
typedef struct PQS_SIGN_CTX {
    unsigned char* message;
    unsigned char* privateKey;
    unsigned char* publicKey;
    unsigned char* signature;
    size_t publicKeySize;
    size_t privateKeySize;
    size_t signatureSize;
    size_t messageSize;
} PQS_SIGN_CTX;


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // PQS_CTX_H
