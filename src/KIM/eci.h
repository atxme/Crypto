#pragma once 

////////////////////////////////////////////////////////////////////////////////////////
// elliptic curve isogeny for PQS API                                                 //     
//                                                                                    //                          
// Kyber is a C library that implements the algorithm described in                    //
// "Kyber: a CCA-secure module-lattice-based KEM" by Eike Kiltz,                     ,//
// Alex Kyber, and Peter Schwabe, published in the proceedings of                     //
// CRYPTO 2017.                                                                       //
//                                                                                    //                  
// Kyber will provide a shared secret bettween two parties for symetric encryption    //
//                                                                                    //
// Project : kyber PQS                                                                //                    
// File    : eci.h                                                                  //                
// Author  : Benedetti Christophe                                                     //
//                                                                                    //
// This code is provided under the MIT license.                                       //
// Please refer to the LICENSE file for licensing information.                        //
//                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////


#ifndef ECI_H
#define ECI_H


#ifdef __cplusplus
extern "C" {
#endif

#include "pqsCtx.h"
#include "pqsCtx.h"

#define ECI_SIDH 0
#define ECI_SIKE 1



////////////////////////////////////////////////////////////////////////////////////////
//                                                                                    
/// elliptic curve isogeny keyGen
//
/// @param[in] ctx Pointer to a cryptographically secure PRNG context initialized
//
/// @return void 
////////////////////////////////////////////////////////////////////////////////////////
void eciKeygen(PQS_KEYGEN_CTX, )



#ifdef __cplusplus
}
#endif

#endif /* ECI_H */




