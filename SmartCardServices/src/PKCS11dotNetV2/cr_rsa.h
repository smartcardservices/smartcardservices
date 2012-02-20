/*
 *  PKCS#11 library for .Net smart cards
 *  Copyright (C) 2007-2009 Gemalto <support@gemalto.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef _CR_RSA_H_
#define _CR_RSA_H_

#ifdef WIN32
#include <Windows.h>
#else
#ifdef __APPLE__
#include <PCSC/wintypes.h>
#else
#include <wintypes.h>
#endif
#endif
#include "cr_random.h"

/**
 * RSA key lengths.
 */
#define MIN_RSA_MODULUS_BITS	512
#define MAX_RSA_MODULUS_BITS	2048
#define MAX_RSA_MODULUS_LEN		((MAX_RSA_MODULUS_BITS + 7) / 8)
#define MAX_RSA_PRIME_BITS		((MAX_RSA_MODULUS_BITS + 1) / 2)
#define MAX_RSA_PRIME_LEN		((MAX_RSA_PRIME_BITS + 7) / 8)


/**
 * RSA public key struct.
 */
typedef struct {
    unsigned int bits;                           /* length in bits of modulus */
    unsigned char modulus[MAX_RSA_MODULUS_LEN];                    /* modulus */
    unsigned char exponent[MAX_RSA_MODULUS_LEN];           /* public exponent */
} R_RSA_PUBLIC_KEY;


/**
 * RSA private key struct.
 *
 * The size of arrays for key should be:
 *
 * modulus			[MAX_RSA_MODULUS_LEN]
 * publicExponent	[MAX_RSA_MODULUS_LEN]
 * exponent			[MAX_RSA_MODULUS_LEN]
 * prime[2]			[MAX_RSA_PRIME_LEN]
 * primeExponent[2]	[MAX_RSA_PRIME_LEN]
 * coefficient		[MAX_RSA_PRIME_LEN]
 */
typedef struct {
  unsigned int bits;                           /* length in bits of modulus */
  unsigned char modulus[MAX_RSA_MODULUS_LEN];                    /* modulus */
  unsigned char publicExponent[MAX_RSA_MODULUS_LEN];     /* public exponent */
  unsigned char exponent[MAX_RSA_MODULUS_LEN];          /* private exponent */
  unsigned char prime[2][MAX_RSA_PRIME_LEN];               /* prime factors */
  unsigned char primeExponent[2][MAX_RSA_PRIME_LEN];   /* exponents for CRT */
  unsigned char coefficient[MAX_RSA_PRIME_LEN];          /* CRT coefficient */
} R_RSA_PRIVATE_KEY;


/**
 * RSA prototype key.
 */
typedef struct {
    unsigned int bits;						/* length in bits of modulus		*/
    int useFermat4;							/* public exponent (1 = F4, 0 = 3)	*/
} R_RSA_PROTO_KEY;


 /**
 * ------------------------------------------------------------------------
 * RSA Interfaces
 * ------------------------------------------------------------------------
 */

typedef struct
{
    DWORD  modulusLength;          /* length (bits) of modulus         */
    BYTE* modulus;                /* modulus                          */
    DWORD  publicExponentLength;   /* length (bits) of public exponent */
    BYTE* publicExponent;         /* public exponent                  */
} rsaPublicKey_t ;

typedef struct
{
    DWORD  modulusLength;          /* length (bits) of modulus         */
    BYTE* modulus;                /* modulus                          */
    DWORD  publicExponentLength;   /* length (bits) of public exponent */
    BYTE* publicExponent;         /* public exponent                  */
    BYTE* privateExponent;        /* private exponent                 */
    BYTE* prime[2];               /* prime factors                    */
    BYTE* primeExponent[2];       /* exponents for CRT                */
    BYTE* coefficient;            /* CRT coefficient                  */
} rsaPrivateKey_t ;


/**
 * RSA function declaration for private/public key operation
 */

int RSAPrivateDecrypt(
    unsigned char *output,                   /* output block				*/
    unsigned int *outputLen,                 /* length of output block		*/
    unsigned char *input,                    /* input block					*/
    unsigned int inputLen,                   /* length of input block		*/
    R_RSA_PRIVATE_KEY *privateKey);			 /* RSA private key				*/

int RSAPrivateEncrypt(
    unsigned char *output,                   /* output block                */
    unsigned int *outputLen,                 /* length of output block      */
    unsigned char *input,                    /* input block                 */
    unsigned int inputLen,                   /* length of input block       */
    R_RSA_PRIVATE_KEY *privateKey) ;         /* RSA private key				*/

int RSAPrivateBlock(
    unsigned char *output,                   /* output block				*/
    unsigned int *outputLen,                 /* length of output block		*/
    unsigned char *input,                    /* input block					*/
    unsigned int inputLen,                   /* length of input block		*/
    R_RSA_PRIVATE_KEY *privateKey) ;         /* RSA private key				*/


int RSAPublicEncrypt(
    unsigned char *output,					 /* output block				*/
    unsigned int *outputLen,				 /* length of output block		*/
    unsigned char *input,					 /* input block					*/
    unsigned int inputLen,					 /* length of input block		*/
    R_RSA_PUBLIC_KEY *publicKey,			 /* RSA public key				*/
    R_RANDOM_STRUCT *randomStruct) ;		 /* random structure			*/


int RSAPublicBlock(
    unsigned char *output,					 /* output block				*/
    unsigned int *outputLen,				 /* length of output block		*/
    unsigned char *input,					 /* input block					*/
    unsigned int inputLen,					 /* length of input block		*/
    R_RSA_PUBLIC_KEY *publicKey) ;			 /* RSA public key				*/


int RSAPublicDecrypt(
    unsigned char *output,                    /* output block				*/
    unsigned int *outputLen,                  /* length of output block		*/
    unsigned char *input,                     /* input block				*/
    unsigned int inputLen,                    /* length of input block		*/
    R_RSA_PUBLIC_KEY *publicKey) ;            /* RSA public key				*/


#endif

