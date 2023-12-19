////////////////////////////////////////////////////////////////////////////////////////
// Context integration for PQS API                                                    //     
//                                                                                    //                                                            //
//                                                                                    //                      
// This file is a part of the "PQS" Post Quantum Security  project.                   //
// This code provide all the context for the PQS API                                  //
//                                                                                    //
// Project : PQS Crypto                                                               //                  
// File    : pqsCtx.h                                                                 //                
// Author  : Benedetti Christophe                                                     //
//                                                                                    //
// This code is provided under the MIT license.                                       //
// Please refer to the LICENSE file for licensing information.                        //
//                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////


#ifndef PQS_CTX_H
#define PQS_CTX_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <oqs/oqs.h>
#include <stddef.h>

//////////////////////////////////////////////////////////////////////////////////////////
// CTX FOR QS_API_PARAM
//
/// @brief:  this struct is used to pass the parameters to the API
/// @brief:  you must define correctly the call off the API by defining all parameters
/// @brief:  if you don't need the parameter, just pass NULL and the API will accept the call
//
/// @param:  algorithmetype: the type of the algorithm to use
/// @param:  algorithm: the algorithm to use
/// @param:  publicKey: the public key to use for encryption/decryption/verificationsignature
/// @param:  privateKey: the private key to use for encryption/decryption/signature
/// @param:  message: the message to encrypt/decrypt
/// @param:  messageSize: the size of the message to encrypt/decrypt
/// @param:  keySize: the size of the key to generate
/// @param:  output: the output of the API
//
//////////////////////////////////////////////////////////////////////////////////////////
struct {
    int algorithmetype;           // Type de l'algorithme à utiliser
    int algorithm;                // Algorithme à utiliser
    unsigned char* publicKey;     // Clé publique pour le chiffrement/déchiffrement/vérification de signature
    unsigned char* privateKey;    // Clé privée pour le chiffrement/déchiffrement/signature
    unsigned char* message;       // Message à chiffrer/déchiffrer
    size_t messageSize;           // Taille du message à chiffrer/déchiffrer
    size_t keySize;                  // Taille de la clé à générer
    void* output;                 // Sortie de l'API
} typedef PQS_API_PARAM;


//////////////////////////////////////////////////////////////////////////////////////////
// CTX FOR PQS_KEY_GEN return
//
/// @brief:  this struct is used to return the key pair from the API 
/// @brief:  you must define correctly the call off the API by defining all parameters
//
/// @param:  publicKey: the public key generated
/// @param:  privateKey: the private key generated
//
//////////////////////////////////////////////////////////////////////////////////////////
struct {
    unsigned char *publicKey;
    unsigned char *privateKey;
    int isogeny;
}typedef PQS_KEYGEN_CTX;

//////////////////////////////////////////////////////////////////////////////////////////
// CTX FOR PQS encryption return
//
/// @brief:  this struct is used to return the encrypted message from the API
/// @brief:  you must define correctly the call off the API by defining all parameters
//
/// @param:  message: the message to encrypt
/// @param:  publicKey: the public key to use for encryption
/// @param:  privateKey: the private key to use for encryption
/// @param:  cipherText: the encrypted message
/// @param:  cipherTextSize: the size of the encrypted message
/// @param:  sharedSecret: the shared secret between the two parties
/// @param:  sharedSecretSize: the size of the shared secret
//
//////////////////////////////////////////////////////////////////////////////////////////
struct{
    unsigned char *publicKey;
    unsigned char *privateKey;
    unsigned char *message;
    unsigned char *cipherText;
    unsigned char *sharedSecret;
    unsigned char* keyExchangeToken;
    unsigned char* symetricKey;
    size_t keySize;
    size_t messageSize;
    size_t sharedSecretSize;
}typedef PQS_ENCRYPT_CTX;

//////////////////////////////////////////////////////////////////////////////////////////
// CTX FOR PQS decryption return
//
/// @brief:  this struct is used to return the decrypted message from the API
/// @brief:  you must define correctly the call off the API by defining all parameters
//
/// @param:  cipherText: the cipher text to decrypt
/// @param:  publicKey: the public key to use for decryption
/// @param:  privateKey: the private key to use for decryption
/// @param:  message: the decrypted message
/// @param:  messageSize: the size of the decrypted message
/// @param:  sharedSecret: the shared secret between the two parties
/// @param:  sharedSecretSize: the size of the shared secret
//
//////////////////////////////////////////////////////////////////////////////////////////
struct 
{
    unsigned char* cipherText;
    unsigned char* publicKey;
    unsigned char* privateKey;
    unsigned char* message;
    unsigned char* sharedSecret;
    unsigned char* keyExchangeToken;
    unsigned char* symetricKey;
    size_t keySize;
    size_t messageSize;
    size_t sharedSecretSize;
}typedef PQS_DECRYPT_CTX;


//////////////////////////////////////////////////////////////////////////////////////////
// CTX FOR PQS signature return
//
/// @brief:  this struct is used to return the signature from the API
/// @brief:  you must define correctly the call off the API by defining all parameters
//
/// @param:  message: the message to sign
/// @param:  privateKey: the private key to use for signature -> NULL if verify call
/// @param:  publicKey: the public key to use for signature verification -> NULL if sign call
/// @param:  signature: the signature
/// @param:  signatureSize: the size of the signature
//
//////////////////////////////////////////////////////////////////////////////////////////
struct{
    unsigned char* message;
    unsigned char* privateKey;
    unsigned char* publicKey;
    unsigned char* signature;
    size_t signatureSize;
    size_t messageSize;
}typedef PQS_SIGN_CTX;


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // PQS_CTX_H