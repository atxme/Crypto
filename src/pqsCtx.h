#pragma once
#include <oqs/oqs.h>
#include <stddef.h>
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//   pqsCtx.h
//
//  Crypto API implementation including all the PQC algorithms
//
//  PQS Crypto 2023, BENEDETTI CHRISTOPHE 
//
//   Definition of the PQS context
//   Description: Post Quantum Secure Context (PQS) 
//   PQS is a context that is used to store the PQS parameters and the PQS key pair during pqs opération 
//
//   No need to include it directly, it is included by pqs.h
//
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////
// CTX FOR QS_API_PARAM
//
// @brief:  this struct is used to pass the parameters to the API
// @brief:  you must define correctly the call off the API by defining all parameters
// @brief:  if you don't need the parameter, just pass NULL and the API will accept the call
//
// @param:  algorithmetype: the type of the algorithm to use
// @param:  algorithm: the algorithm to use
// @param:  publicKey: the public key to use for encryption/decryption/verificationsignature
// @param:  privateKey: the private key to use for encryption/decryption/signature
// @param:  message: the message to encrypt/decrypt
// @param:  messageSize: the size of the message to encrypt/decrypt
// @param:  keySize: the size of the key to generate
// @param:  output: the output of the API
//
//////////////////////////////////////////////////////////////////////////////////////////
struct{
    
    int algorithmetype;
    int algorithm;
    unsigned char* publicKey;
    unsigned char* privateKey;
    unsigned char* message;
    size_t messageSize;
    int keySize;
    void* output;

}typedef PQS_API_PARAM;

//////////////////////////////////////////////////////////////////////////////////////////
// CTX FOR PQS_KEY_GEN return
//
// @brief:  this struct is used to return the key pair from the API 
// @brief:  you must define correctly the call off the API by defining all parameters
//
// @param:  publicKey: the public key generated
// @param:  privateKey: the private key generated
//
//////////////////////////////////////////////////////////////////////////////////////////
struct {
    unsigned char *publicKey;
    unsigned char *privateKey;
}typedef PQS_KEYGEN_CTX;

//////////////////////////////////////////////////////////////////////////////////////////
// CTX FOR PQS encryption return
//
// @brief:  this struct is used to return the encrypted message from the API
// @brief:  you must define correctly the call off the API by defining all parameters
//
// @param:  message: the message to encrypt
// @param:  publicKey: the public key to use for encryption
// @param:  privateKey: the private key to use for encryption
// @param:  cipherText: the encrypted message
// @param:  cipherTextSize: the size of the encrypted message
// @param:  sharedSecret: the shared secret between the two parties
// @param:  sharedSecretSize: the size of the shared secret
//
//////////////////////////////////////////////////////////////////////////////////////////
struct{
    unsigned char *publicKey;
    unsigned char *privateKey;
    unsigned char *message;
    unsigned char *cipherText;
    unsigned char *sharedSecret;
    size_t messageSize;
    size_t sharedSecretSize;
}typedef PQS_ENCRYPT_CTX;

//////////////////////////////////////////////////////////////////////////////////////////
// CTX FOR PQS decryption return
//
// @brief:  this struct is used to return the decrypted message from the API
// @brief:  you must define correctly the call off the API by defining all parameters
//
// @param:  cipherText: the cipher text to decrypt
// @param:  publicKey: the public key to use for decryption
// @param:  privateKey: the private key to use for decryption
// @param:  message: the decrypted message
// @param:  messageSize: the size of the decrypted message
// @param:  sharedSecret: the shared secret between the two parties
// @param:  sharedSecretSize: the size of the shared secret
//
//////////////////////////////////////////////////////////////////////////////////////////
struct 
{
    unsigned char* cipherText;
    unsigned char* publicKey;
    unsigned char* privateKey;
    unsigned char* message;
    unsigned char* sharedSecret;
    size_t messageSize;
    size_t sharedSecretSize;
}typedef PQS_DECRYPT_CTX;


//////////////////////////////////////////////////////////////////////////////////////////
// CTX FOR PQS signature return
//
// @brief:  this struct is used to return the signature from the API
// @brief:  you must define correctly the call off the API by defining all parameters
//
// @param:  message: the message to sign
// @param:  privateKey: the private key to use for signature
// @param:  signature: the signature
// @param:  signatureSize: the size of the signature
//
//////////////////////////////////////////////////////////////////////////////////////////
struct{
    unsigned char* message;
    unsigned char* privateKey;
    unsigned char* signature;
    size_t signatureSize;
}typedef PQS_SIGN_CTX;