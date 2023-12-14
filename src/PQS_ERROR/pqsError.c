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

#include "pqsError.h"

void writeFile(const char *file, int line, const char *function, int error_code) {

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    FILE *f = fopen(file, "a");
    if (f == NULL) {
        printf("ERROR: Failed to open the file.\n");
        return;
    }

    // Écrire le message dans le fichier
    fprintf(f, "Error: %s in %s at line %s. Time: %d-%02d-%02d %02d:%02d:%02d\n",
            PQS_ERROR_MESSAGE[error_code], function, line,
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);

    // Fermer le fichier
    fclose(f);
}


////////////////////////////////
// Error management 
////////////////////////////////
void pqsError(PQS_ERROR error_code, int line, const char *function)
{
    if (function == NULL || line == NULL)
    {
        printf("ERROR: function or file is NULL\n");
        return;
    }

    memset(logFile, 0, sizeof(logFile)); // Initialise logFile avec des caractères nuls

    if (saveFile){
        if (logFile[0] == '\0') {
            printf("ERROR: Log file not specified. Set 'saveFile' to true and provide a valid file name.\n");
            exit(EXIT_FAILURE);
        }

        #ifdef WIN32
            DWORD attrib = GetFileAttributesA(file);
            if (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY)){
                printf("ERROR : %s in %s at line %d\n", "file is not existing or is a directory", "\nid : PQS_ERROR_MANAGER");
            }
            writeFile(logFile, line, function, error_code);
    
        #else
            if (access(logFile, F_OK) != -1){
                printf("ERROR : %s in %s at line %d\n", "file is not existing or is a directory", "\nid : PQS_ERROR_MANAGER");
            }
            writeFile(logFile, line, function, error_code);
        #endif

    }
    
    else {
        printf("Error handled at line : %d in function : %s\n error : %s\n", line, function, PQS_ERROR_MESSAGE[error_code]);
    }

    exit(EXIT_FAILURE);
}