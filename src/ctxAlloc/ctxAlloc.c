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

#include "ctxAlloc.h"


//////////////////////////////////////
// init key generation ctx
//////////////////////////////////////

PQS_KEYGEN_CTX* createPqsKeygenCtx(){
    PQS_KEYGEN_CTX* ctx = (PQS_KEYGEN_CTX*) malloc(sizeof(PQS_KEYGEN_CTX));
    if(ctx == NULL){
        return NULL;
    }
    ctx->publicKey = NULL;
    ctx->privateKey = NULL;
    return ctx;
}

//////////////////////////////////////
// free key generation ctx
//////////////////////////////////////

void freePqsKeygenCtx(PQS_KEYGEN_CTX* ctx){
    if(ctx != NULL){
        if(ctx->publicKey != NULL){
            free(ctx->publicKey);
            ctx->publicKey = NULL;
        }
        if(ctx->privateKey != NULL){
            free(ctx->privateKey);
            ctx->privateKey = NULL;
        }
        free(ctx);
    }
}

//////////////////////////////////////
// init signature ctx
//////////////////////////////////////

PQS_SIGN_CTX* createPqsSignCtx(){
    PQS_SIGN_CTX* ctx = (PQS_SIGN_CTX*) malloc(sizeof(PQS_SIGN_CTX));
    if(ctx == NULL){
        return NULL;
    }
    ctx->message = NULL;
    ctx->signature = NULL;
    ctx->publicKey = NULL;
    ctx->privateKey = NULL;
    ctx->publicKeySize = 0;
    ctx->privateKeySize = 0;
    ctx->messageSize = 0;
    ctx->signatureSize = 0;
    return ctx;
}

//////////////////////////////////////
// free signature ctx
//////////////////////////////////////

void freePqsSignCtx(PQS_SIGN_CTX* ctx){
    if(ctx != NULL){
        if(ctx->message != NULL){
            free(ctx->message);
            ctx->message = NULL;
        }
        if(ctx->signature != NULL){
            free(ctx->signature);
            ctx->signature = NULL;
        }
        if(ctx->publicKey != NULL){
            free(ctx->publicKey);
            ctx->publicKey = NULL;
        }
        if(ctx->privateKey != NULL){
            free(ctx->privateKey);
            ctx->privateKey = NULL;
        }
        free(ctx);
    }
}

//////////////////////////////////////
// init encryption ctx
//////////////////////////////////////

PQS_ENCRYPT_CTX* createPqsEncryptCtx(){
    PQS_ENCRYPT_CTX* ctx = (PQS_ENCRYPT_CTX*) malloc(sizeof(PQS_ENCRYPT_CTX));
    if(ctx == NULL){
        return NULL;
    }
    ctx->cipherText = NULL;
    ctx->message = NULL;
    ctx->publicKey = NULL;
    ctx->privateKey = NULL;
    ctx->keyExchangeToken = NULL;
    ctx->symmetricKey = NULL;
    ctx->keySize = 0;
    ctx->messageSize = 0;
    ctx->sharedSecretSize = 0;
    return ctx;
}

//////////////////////////////////////
// free encryption ctx
//////////////////////////////////////

void freePqsEncryptCtx(PQS_ENCRYPT_CTX* ctx){
    if(ctx != NULL){
        if(ctx->cipherText != NULL){
            free(ctx->cipherText);
            ctx->cipherText = NULL;
        }
        if(ctx->message != NULL){
            free(ctx->message);
            ctx->message = NULL;
        }
        if(ctx->publicKey != NULL){
            free(ctx->publicKey);
            ctx->publicKey = NULL;
        }
        if(ctx->privateKey != NULL){
            free(ctx->privateKey);
            ctx->privateKey = NULL;
        }
        if(ctx->keyExchangeToken != NULL){
            free(ctx->keyExchangeToken);
            ctx->keyExchangeToken = NULL;
        }
        if(ctx->symmetricKey != NULL){
            free(ctx->symmetricKey);
            ctx->symmetricKey = NULL;
        }
        free(ctx);
    }
}

//////////////////////////////////////
// init decryption ctx
//////////////////////////////////////

PQS_DECRYPT_CTX* createPqsDecryptCtx(){
    PQS_DECRYPT_CTX* ctx = (PQS_DECRYPT_CTX*) malloc(sizeof(PQS_DECRYPT_CTX));
    if(ctx == NULL){
        return NULL;
    }
    ctx->cipherText = NULL;
    ctx->message = NULL;
    ctx->publicKey = NULL;
    ctx->privateKey = NULL;
    ctx->keyExchangeToken = NULL;
    ctx->symmetricKey = NULL;
    ctx->keySize = 0;
    ctx->messageSize = 0;
    ctx->sharedSecretSize = 0;
    return ctx;
}

//////////////////////////////////////
// free decryption ctx
//////////////////////////////////////

void freePqsDecryptCtx(PQS_DECRYPT_CTX* ctx){
    if(ctx != NULL){
        if(ctx->cipherText != NULL){
            free(ctx->cipherText);
            ctx->cipherText = NULL;
        }
        if(ctx->message != NULL){
            free(ctx->message);
            ctx->message = NULL;
        }
        if(ctx->publicKey != NULL){
            free(ctx->publicKey);
            ctx->publicKey = NULL;
        }
        if(ctx->privateKey != NULL){
            free(ctx->privateKey);
            ctx->privateKey = NULL;
        }
        if(ctx->keyExchangeToken != NULL){
            free(ctx->keyExchangeToken);
            ctx->keyExchangeToken = NULL;
        }
        if(ctx->symmetricKey != NULL){
            free(ctx->symmetricKey);
            ctx->symmetricKey = NULL;
        }
        free(ctx);
    }
}

