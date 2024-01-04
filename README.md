How to Use This API

It is not necessary to define unnecessary parameters for an API call.

1. KEY GENERATION

You should:

    Specify the algorithm.
    Specify the mode.
    Specify the key size: public key size.
    Dynamically allocate the public and private keys in the context (ctx) with the corresponding size.

2. ENCRYPTION -> Key Encapsulation
3. DECRYPTION -> Key Decapsulation

4. SIGNATURE 

paramters :mode, algorithm, message, messageSize, privateKey, privateKeySize

You should:

    Specify the algorithm.
    Specify the mode.
    Specify the key size: private key size.
    Specify the message to sign.
    Dynamically allocate the output buffer in the context (ctx) with the corresponding size for the signature.

You can obtain the signature in the ctx output buffer.

5. VERIFICATION

    Specify the algorithm.
    Specify the mode.
    Specify the message to verify the signature.
    Specify the message size.
    Specify the signature you want to verify.
    Specify the size of the signature.
    Specify the public key.
    Dynamically allocate the output with the size of int 

    result :

    0  -> valid 
    -1 -> invalid 