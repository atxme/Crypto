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

#ifndef PQS_ERROR_H
#define PQS_ERROR_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#ifndef _WIN32
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
    KEYGEN_ERROR,

    /// @brief SIG_KEYGEN error code
    ERROR_SIG_KEYGEN,
    ERROR_SIG_ALLOC,
    CALL_FUNCTION_ERROR,
    SHARED_SECRET_ERROR,
    KYBER_MESSAGE_SIZE_ERROR,

    /// @brief the error code count
    ERROR_CODE_COUNT, // this should be the last one
}typedef PQS_ERROR;

extern const char* PQS_ERROR_MESSAGE[];

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

#endif // PQS_ERROR_H