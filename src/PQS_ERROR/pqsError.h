#pragma once
////////////////////////////////////////////////////////////////////////////////////////
// ERROR integration for PQS API                                                      //     
//                                                                                    //   
// Manage all possible error defined and call the answer for it                       //
//                                                                                    //                      
// This file is a part of the "PQS" Post Quantum Security  project.                   //
//                                                                                    //
// Project : PQS_ERROR                                                                //                    
// File    : pqsError.h                                                               //                
// Author  : Benedetti Christophe                                                     //
//                                                                                    //
// This code is provided under the MIT license.                                       //
// Please refer to the LICENSE file for licensing information.                        //
//                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#ifndef WIN32
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <time.h>
#endif


#ifdef __cplusplus
extern "C" {
#endif // __cplusplus


/// @brief PQS_ERROR enum
/// @brief this enum define all possible error code provided by the PQS API
enum PQS_ERROR{
    ERROR_POINTER_NOT_DEFINE,
    MALLOC_ERROR,
    ALGORITHME_TYPE_ERROR,
    ALGORITHME_ERROR,
    PUBLIC_KEY_ERROR,
    PRIVATE_KEY_ERROR,
    MESSAGE_ERROR,
    SIGNATURE_ERROR,
    SIGNATURE_VERIFICATION_ERROR,
    ENCRYPTION_ERROR,
    DECRYPTION_ERROR,
    KEY_SIZE_ERROR,
    PUBLIC_KEY_SIZE_ERROR ,
    PRIVATE_KEY_SIZE_ERROR ,
    SIGNATURE_SIZE_ERROR ,
    ENCRYPTION_SIZE_ERROR ,
    DECRYPTION_SIZE_ERROR ,
    CTX_IS_NULL,

    /// @brief SIG_KEYGEN error code
    ERROR_SIG_KEYGEN,

    /// @brief the error code count
    ERROR_CODE_COUNT, // this should be the last one
}typedef PQS_ERROR;

const char* PQS_ERROR_MESSAGE[] = {
    "a pointer is not define",
    "manually memory allocation as failed",
    "algorithme type is not define or not supported",
    "algorithme is not define or not supported",
    "public key is empty or not defined or is not valid",
    "private key is empty or not defined or is not valid",
    "message is empty or not defined",
    "signature is empty or not defined or is not valid",
    "matching signature verification failed",
    "encryption as failed",
    "decryption as failed",
    "key size is invalid or not supported",
    "public key size is invalid or not supported",
    "private key size is invalid or not supported",
    "signature size is invalid or not supported",
    "encryption size is invalid or not supported",
    "decryption size is invalid or not supported",
    "ctx is not define or ctx pointer is NULL",



    /// @brief SIG_KEYGEN error code
    "key generation as failed",
};

/////////////////////////////////////////////////////////////
/// @brief flag to indicate the presence of a log file
/// @brief you must edit the flags before call the error function 
/////////////////////////////////////////////////////////////
static bool saveFile = false;
static char logFile [1000];

////////////////////////////////////////////////////////////////////////////////////////
//   ERROR management                                                                 //
//
/// @brief ERROR management
/// @brief this function must be call when an error is detected to print the error message
//
/// @brief remember to edit saveFile flag and logFile path before calling this function 
//
/// @param error_code the error code
/// @param file the file where the error is detected if not NULL
/// @param line the line where the error is detected if not NULL
/// @param function the function where the error is detected if not NULL
//
/// @return void
//
////////////////////////////////////////////////////////////////////////////////////////
void pqsError(PQS_ERROR error_code,int line , const char *function);


#ifdef __cplusplus
}
#endif // __cplusplus