#include "crypto.h"


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void print_hex(unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

void print_hex_str(unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++)
        printf("%c", buf[i]);
    printf("\n");
}

void generateRandomIV(unsigned char *iv)
{
    if (!RAND_bytes(iv, IV_LEN))
    {
        handleErrors();
    }
}

void generateRandomKey(unsigned char *key)
{
    if (!RAND_bytes(key, AES_KEYLEN % 8))
    {
        handleErrors();
    }
}

void sha3_256(unsigned char *plaintext, unsigned long plaintextLen, unsigned char *digest)
{
    EVP_MD_CTX *mdctx;
    unsigned int md_len;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        handleErrors();
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL))
    {
        handleErrors();
    }

    if (1 != EVP_DigestUpdate(mdctx, plaintext, plaintextLen))
    {
        handleErrors();
    }

    if (1 != EVP_DigestFinal_ex(mdctx, digest, &md_len))
    {
        handleErrors();
    }

    EVP_MD_CTX_free(mdctx);
}

void sha3_512(unsigned char *plaintext, unsigned long plaintextLen, unsigned char *digest)
{
    EVP_MD_CTX *mdctx;
    unsigned int md_len;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        handleErrors();
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL))
    {
        handleErrors();
    }

    if (1 != EVP_DigestUpdate(mdctx, plaintext, plaintextLen))
    {
        handleErrors();
    }

    if (1 != EVP_DigestFinal_ex(mdctx, digest, &md_len))
    {
        handleErrors();
    }

    EVP_MD_CTX_free(mdctx);
}

void Aes256CbcHmacSha256Encryption(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned long plaintextLen, unsigned char *cipherText) {
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphertext_len = 0;

    // Calcul du hash SHA3-256 avant le chiffrement
    unsigned char digest[32];
    sha3_256(plaintext, plaintextLen, digest);

    // Allocation de la mémoire pour le texte chiffré et le hash
    unsigned char *buffer = (unsigned char *)malloc(plaintextLen + SHA256_DIGEST_LENGTH + (AES_BLOCK_SIZE -(plaintextLen % AES_BLOCK_SIZE)));
    memset(buffer, 0, plaintextLen + SHA256_DIGEST_LENGTH + (AES_BLOCK_SIZE -(plaintextLen % AES_BLOCK_SIZE)));

    // Initialisation du contexte de chiffrement
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    // Chiffrement du texte
    if (1 != EVP_EncryptUpdate(ctx, buffer, &len, plaintext, plaintextLen)) handleErrors();

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, buffer + len, &len)) handleErrors();
    ciphertext_len += len;

    // Ajout du hash à la fin du texte chiffré
    memcpy(buffer + ciphertext_len, digest, SHA256_DIGEST_LENGTH);
    memcpy(cipherText, buffer, ciphertext_len + SHA256_DIGEST_LENGTH);

    free(buffer);
    EVP_CIPHER_CTX_free(ctx);
}


void Aes256CbcHmacSha512Encryption(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned long plaintextLen, unsigned char *cipherText) {
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphertext_len = 0;

    // Calcul du hash SHA3-512 avant le chiffrement
    unsigned char digest[SHA512_DIGEST_LENGTH];
    sha3_512(plaintext, plaintextLen, digest);

    // Allocation de la mémoire pour le texte chiffré et le hash
    unsigned char *buffer = (unsigned char *)malloc(plaintextLen + AES_BLOCK_SIZE - (plaintextLen % AES_BLOCK_SIZE) + SHA512_DIGEST_LENGTH);
    memset(buffer, 0, plaintextLen + SHA512_DIGEST_LENGTH);

    // Chiffrement
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, buffer, &len, plaintext, plaintextLen)) handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, buffer + len, &len)) handleErrors();
    ciphertext_len += len;

    // Ajout du hash SHA3-512 à la fin du texte chiffré
    memcpy(buffer + ciphertext_len, digest, SHA512_DIGEST_LENGTH);
    memcpy(cipherText, buffer, ciphertext_len + SHA512_DIGEST_LENGTH);

    free(buffer);
    EVP_CIPHER_CTX_free(ctx);
}


void Aes256GcmEncryption(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned long plaintextLen, unsigned char *cipherText) {
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphertext_len = 0;
    unsigned char tag[16];

    unsigned char *buffer = (unsigned char *)malloc(plaintextLen + 16); // Taille du tag fixe à 16 octets
    if (!buffer) handleErrors();
    memset(buffer, 0, plaintextLen + 16);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) handleErrors();
    if (1 != EVP_EncryptUpdate(ctx, buffer, &len, plaintext, plaintextLen)) handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, buffer + len, &len)) handleErrors();
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) handleErrors();
    memcpy(buffer + ciphertext_len, tag, 16);

    memcpy(cipherText, buffer, ciphertext_len + 16);

    free(buffer);
    EVP_CIPHER_CTX_free(ctx);
}


void Aes256CbcEncryption(unsigned char *plaintext, unsigned char* key, unsigned char *iv, unsigned long plaintextLen, unsigned char *cipherText) {
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphertext_len = 0;

    // Calcul de la taille du texte chiffré (padding inclus)
    int paddedSize = plaintextLen + AES_BLOCK_SIZE - (plaintextLen % AES_BLOCK_SIZE);
    unsigned char *buffer = (unsigned char *)malloc(paddedSize);
    if (!buffer) {
        handleErrors();
    }
    memset(buffer, 0, paddedSize);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }

    if (1 != EVP_EncryptUpdate(ctx, buffer, &len, plaintext, plaintextLen)) {
        handleErrors();
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, buffer + len, &len)) {
        handleErrors();
    }
    ciphertext_len += len;

    memcpy(cipherText, buffer, ciphertext_len);

    free(buffer);
    EVP_CIPHER_CTX_free(ctx);
}


void Aes256encryption (unsigned char *plaintext , unsigned char* key, unsigned char* iv , unsigned long plaintextLen, int aesConf ,unsigned char* cipherText)
{
    switch (aesConf)
    {
        case AES_256_CBC_HMAC_SHA256:
            Aes256CbcHmacSha256Encryption(plaintext, key, iv, plaintextLen, cipherText);
            break;
        case AES_256_CBC_HMAC_SHA512:
            Aes256CbcHmacSha512Encryption(plaintext, key, iv, plaintextLen, cipherText);
            break;
        case AES_256_GCM:
            Aes256GcmEncryption(plaintext, key, iv, plaintextLen, cipherText);
            break;
        case AES_256_CBC:
            Aes256CbcEncryption(plaintext, key, iv, plaintextLen, cipherText);
            break;
        default:
            break;
    }

    return ;
}


void Aes256CbcHmacSha256Decryption(unsigned char *cipherText, unsigned char *key, unsigned char *iv, unsigned long cipherTextLen, unsigned char *decryptedText) {
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int plaintext_len = 0;

    // Extraction du hash du texte chiffré
    unsigned char digest[32];
    memcpy(digest, cipherText + (cipherTextLen - SHA256_DIGEST_LENGTH), SHA256_DIGEST_LENGTH);

    // Allocation de la mémoire pour le texte déchiffré
    unsigned char *buffer = malloc(cipherTextLen - SHA256_DIGEST_LENGTH);
    memset(buffer, 0, cipherTextLen - SHA256_DIGEST_LENGTH);

    // Initialisation du contexte de déchiffrement
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    // Déchiffrement du texte
    if (1 != EVP_DecryptUpdate(ctx, decryptedText, &len, cipherText, cipherTextLen - SHA256_DIGEST_LENGTH)) handleErrors();
    plaintext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, decryptedText + len, &len)) handleErrors();
    plaintext_len += len;

    // Vérification de l'intégrité avec le hash SHA3-256
    unsigned char calculatedDigest[32];
    sha3_256(decryptedText, plaintext_len, calculatedDigest);
    if (memcmp(digest, calculatedDigest, SHA256_DIGEST_LENGTH) != 0) {
        printf("Integrity Error\n");
        return;
    }

    EVP_CIPHER_CTX_free(ctx);
    free(buffer);
}


void Aes256CbcHmacSha512Decryption(unsigned char *cipherText, unsigned char *key, unsigned char *iv, unsigned long cipherTextLen, unsigned char *decryptedText) {
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int plaintext_len = 0;

    // Extraction du hash SHA3-512 du texte chiffré
    unsigned char digest[SHA512_DIGEST_LENGTH];
    memcpy(digest, cipherText + cipherTextLen - SHA512_DIGEST_LENGTH, SHA512_DIGEST_LENGTH);

    // Allocation de la mémoire pour le texte déchiffré
    unsigned char *buffer = (unsigned char *)malloc(cipherTextLen - SHA512_DIGEST_LENGTH);
    memset(buffer, 0, cipherTextLen - SHA512_DIGEST_LENGTH);

    // Déchiffrement
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();
    if (1 != EVP_DecryptUpdate(ctx, buffer, &len, cipherText, cipherTextLen - SHA512_DIGEST_LENGTH)) handleErrors();
    plaintext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, buffer + len, &len)) handleErrors();
    plaintext_len += len;

    // Vérification de l'intégrité avec le hash SHA3-512
    unsigned char calculatedDigest[SHA512_DIGEST_LENGTH];
    sha3_512(buffer, plaintext_len, calculatedDigest);
    if (memcmp(digest, calculatedDigest, SHA512_DIGEST_LENGTH) != 0) {
        printf("SHA512 digest not match\n");
        exit(1);
    }

    memcpy(decryptedText, buffer, plaintext_len);
    free(buffer);
    EVP_CIPHER_CTX_free(ctx);
}


void Aes256GcmDecryption(unsigned char *cipherText, unsigned char *key, unsigned char *iv, unsigned long cipherTextLen, unsigned char *decryptedText) {
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int plaintext_len = 0;
    unsigned char tag[16];

    memcpy(tag, cipherText + cipherTextLen - 16, 16);

    unsigned char *buffer = (unsigned char *)malloc(cipherTextLen - 16);
    if (!buffer) handleErrors();
    memset(buffer, 0, cipherTextLen - 16);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) handleErrors();
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) handleErrors();
    if (1 != EVP_DecryptUpdate(ctx, buffer, &len, cipherText, cipherTextLen - 16)) handleErrors();
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, buffer + len, &len) <= 0) {
        printf("Tag verification failed\n");
        handleErrors();
    }
    plaintext_len += len;

    memcpy(decryptedText, buffer, plaintext_len);

    free(buffer);
    EVP_CIPHER_CTX_free(ctx);
}


void Aes256CbcDecryption(unsigned char *cipherText, unsigned char *key, unsigned char *iv, unsigned long cipherTextLen, unsigned char *decryptedText) {
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int plaintext_len = 0;

    unsigned char *buffer = (unsigned char *)malloc(cipherTextLen);
    if (!buffer) {
        handleErrors();
    }
    memset(buffer, 0, cipherTextLen);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }

    if (1 != EVP_DecryptUpdate(ctx, buffer, &len, cipherText, cipherTextLen)) {
        handleErrors();
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, buffer + len, &len)) {
        handleErrors();
    }
    plaintext_len += len;

    memcpy(decryptedText, buffer, plaintext_len);

    free(buffer);
    EVP_CIPHER_CTX_free(ctx);
}

void Aes256decryption(unsigned char *cipherText, unsigned char* key, unsigned char* iv, unsigned long cipherTextLen, int aesConf, unsigned char* decryptedText)
{
    switch (aesConf)
    {
        case AES_256_CBC_HMAC_SHA256:
            Aes256CbcHmacSha256Decryption(cipherText, key, iv, cipherTextLen, decryptedText);
            break;
        case AES_256_CBC_HMAC_SHA512:
            Aes256CbcHmacSha512Decryption(cipherText, key, iv, cipherTextLen, decryptedText);
            break;
        case AES_256_GCM:
            Aes256GcmDecryption(cipherText, key, iv, cipherTextLen, decryptedText);
            break;
        case AES_256_CBC:
            Aes256CbcDecryption(cipherText, key, iv, cipherTextLen, decryptedText);
            break;
        default:
            break;
    }
}
