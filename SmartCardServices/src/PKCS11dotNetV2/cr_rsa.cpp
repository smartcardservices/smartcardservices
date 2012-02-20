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

#include "stdafx.h"
#include "cr_rsa.h"
#include "cr_global.h"
#include "cr_nn.h"
#include "cr_random.h"

#include "ha_config.h"

/**
 * RSA private-key decryption, according to PKCS #1.
 */
int RSAPrivateDecrypt(
    unsigned char *output,				/* output block				*/
    unsigned int *outputLen,            /* length of output block	*/
    unsigned char *input,               /* input block				*/
    unsigned int inputLen,              /* length of input block	*/
    R_RSA_PRIVATE_KEY *privateKey)      /* RSA private key			*/
{
    int status;
    unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];
    unsigned int i, modulusLen, pkcsBlockLen;

    modulusLen = (privateKey->bits + 7) / 8;
    if (inputLen > modulusLen)
        return (RE_LEN);

    //if (status = RSAPrivateBlock(pkcsBlock, &pkcsBlockLen, input, inputLen, privateKey))
    status = RSAPrivateBlock(pkcsBlock, &pkcsBlockLen, input, inputLen, privateKey);
    if ( status )
        return (status);

    if (pkcsBlockLen != modulusLen)
        return (RE_LEN);

    /* Require block type 2.
    */
    if ((pkcsBlock[0] != 0) || (pkcsBlock[1] != 2))
        return (RE_DATA);

    for (i = 2; i < modulusLen-1; i++)
    {
        if (pkcsBlock[i] == 0)
            break;
    }

    i++;
    if (i >= modulusLen)
        return (RE_DATA);

    *outputLen = modulusLen - i;

    if (*outputLen + 11 > modulusLen)
        return (RE_DATA);

    R_memcpy ((POINTER)output, (POINTER)&pkcsBlock[i], *outputLen);

    /**
     * Zeroize sensitive information.
     */
    R_memset ((POINTER)pkcsBlock, 0, sizeof (pkcsBlock));

    return (0);
}


/**
 * Raw RSA private-key operation. Output has same length as modulus.
 *
 * Assumes inputLen < length of modulus.
 * Requires input < modulus.
 */
int RSAPrivateBlock (
    unsigned char *output,              /* output block				*/
    unsigned int *outputLen,            /* length of output block	*/
    unsigned char *input,               /* input block				*/
    unsigned int inputLen,              /* length of input block	*/
    R_RSA_PRIVATE_KEY *privateKey)      /* RSA private key			*/
{
    NN_DIGIT	c[MAX_NN_DIGITS], cP[MAX_NN_DIGITS], cQ[MAX_NN_DIGITS],
                dP[MAX_NN_DIGITS], dQ[MAX_NN_DIGITS], mP[MAX_NN_DIGITS],
                mQ[MAX_NN_DIGITS], n[MAX_NN_DIGITS], p[MAX_NN_DIGITS],
                q[MAX_NN_DIGITS], qInv[MAX_NN_DIGITS], t[MAX_NN_DIGITS] ;

    unsigned int cDigits, nDigits, pDigits;
    unsigned int len_Mod, len_Prime ;

    len_Mod = (privateKey->bits + 7) / 8  ;
    len_Prime = (((privateKey->bits + 1) / 2) + 7) / 8 ;

    NN_Decode (c, MAX_NN_DIGITS, input, inputLen);
    NN_Decode (n, MAX_NN_DIGITS, privateKey->modulus, len_Mod);
    NN_Decode (p, MAX_NN_DIGITS, privateKey->prime[0], len_Prime);
    NN_Decode (q, MAX_NN_DIGITS, privateKey->prime[1], len_Prime);
    NN_Decode (dP, MAX_NN_DIGITS, privateKey->primeExponent[0], len_Prime);
    NN_Decode (dQ, MAX_NN_DIGITS, privateKey->primeExponent[1], len_Prime);
    NN_Decode (qInv, MAX_NN_DIGITS, privateKey->coefficient, len_Prime);

    cDigits = NN_Digits (c, MAX_NN_DIGITS);
    nDigits = NN_Digits (n, MAX_NN_DIGITS);
    pDigits = NN_Digits (p, MAX_NN_DIGITS);

    if (NN_Cmp (c, n, nDigits) >= 0)
        return (RE_DATA);

    /**
     * Compute mP = cP^dP mod p  and  mQ = cQ^dQ mod q. (Assumes q has
     * length at most pDigits, i.e., p > q.)
     */
    NN_Mod (cP, c, cDigits, p, pDigits);
    NN_Mod (cQ, c, cDigits, q, pDigits);
    NN_ModExp (mP, cP, dP, pDigits, p, pDigits);
    NN_AssignZero (mQ, nDigits);
    NN_ModExp (mQ, cQ, dQ, pDigits, q, pDigits);

    /**
     * Chinese Remainder Theorem:
     * m = ((((mP - mQ) mod p) * qInv) mod p) * q + mQ.
     */
    if (NN_Cmp (mP, mQ, pDigits) >= 0)
    {
        NN_Sub (t, mP, mQ, pDigits);
    }
    else
    {
        NN_Sub (t, mQ, mP, pDigits);
        NN_Sub (t, p, t, pDigits);
    }
    NN_ModMult (t, t, qInv, p, pDigits);
    NN_Mult (t, t, q, pDigits);
    NN_Add (t, t, mQ, nDigits);

    *outputLen = (privateKey->bits + 7) / 8;
    NN_Encode (output, *outputLen, t, nDigits);

    /**
     * Zeroize sensitive information.
     */
    R_memset ((POINTER)c, 0, sizeof (c));
    R_memset ((POINTER)cP, 0, sizeof (cP));
    R_memset ((POINTER)cQ, 0, sizeof (cQ));
    R_memset ((POINTER)dP, 0, sizeof (dP));
    R_memset ((POINTER)dQ, 0, sizeof (dQ));
    R_memset ((POINTER)mP, 0, sizeof (mP));
    R_memset ((POINTER)mQ, 0, sizeof (mQ));
    R_memset ((POINTER)p, 0, sizeof (p));
    R_memset ((POINTER)q, 0, sizeof (q));
    R_memset ((POINTER)qInv, 0, sizeof (qInv));
    R_memset ((POINTER)t, 0, sizeof (t));

    return (0);
}


/**
 * RSA public-key encryption, according to PKCS #1.
 */
int RSAPublicEncrypt(
    unsigned char *output,				/* output block				*/
    unsigned int *outputLen,			/* length of output block	*/
    unsigned char *input,				/* input block				*/
    unsigned int inputLen,				/* length of input block	*/
    R_RSA_PUBLIC_KEY *publicKey,		/* RSA public key			*/
    R_RANDOM_STRUCT *randomStruct)		/* random structure			*/
{
    int status;
    unsigned char byte, pkcsBlock[MAX_RSA_MODULUS_LEN];
    unsigned int i, modulusLen;

    modulusLen = (publicKey->bits + 7) / 8;
    if (inputLen + 11 > modulusLen)
    {
        return (RE_LEN);
    }

    /**
     * block type 2
     */
    pkcsBlock[0] = 0;
    pkcsBlock[1] = 2;

    for (i = 2; i < modulusLen - inputLen - 1; i++)
    {
        /**
         * Find nonzero random byte.
         */
        do {
          R_GenerateBytes (&byte, 1, randomStruct);
        } while (byte == 0);

        pkcsBlock[i] = byte;
    }

    /**
     * separator
     */
    pkcsBlock[i++] = 0;
    R_memcpy ((POINTER)&pkcsBlock[i], (POINTER)input, inputLen);
    status = RSAPublicBlock(output, outputLen, pkcsBlock, modulusLen, publicKey);

    /**
     * Zeroize sensitive information.
     */
    byte = 0;
    R_memset ((POINTER)pkcsBlock, 0, sizeof (pkcsBlock));

    return (status);
}


/**
 * Raw RSA public-key operation. Output has same length as modulus.
 *
 * Assumes inputLen < length of modulus.
 * Requires input < modulus.
 */
int RSAPublicBlock(
    unsigned char *output,				/* output block				*/
    unsigned int *outputLen,			/* length of output block	*/
    unsigned char *input,				/* input block				*/
    unsigned int inputLen,				/* length of input block	*/
    R_RSA_PUBLIC_KEY *publicKey)		/* RSA public key			*/
{
    unsigned int eDigits, nDigits;
    NN_DIGIT c[MAX_NN_DIGITS],
             e[MAX_NN_DIGITS],
             m[MAX_NN_DIGITS],
             n[MAX_NN_DIGITS] ;

    unsigned int len_Mod ;

    len_Mod = (publicKey->bits + 7) / 8  ;

    NN_Decode (m, MAX_NN_DIGITS, input, inputLen);
    NN_Decode (n, MAX_NN_DIGITS, publicKey->modulus, len_Mod);
    NN_Decode (e, MAX_NN_DIGITS, publicKey->exponent, len_Mod);
    nDigits = NN_Digits (n, MAX_NN_DIGITS);
    eDigits = NN_Digits (e, MAX_NN_DIGITS);

    if (NN_Cmp (m, n, nDigits) >= 0)
    {
        return (RE_DATA);
    }

    /**
     * Compute c = m^e mod n.
     */
    NN_ModExp (c, m, e, eDigits, n, nDigits);

    *outputLen = (publicKey->bits + 7) / 8;
    NN_Encode (output, *outputLen, c, nDigits);

    /**
     * Zeroize sensitive information.
     */
    R_memset ((POINTER)c, 0, sizeof (c));
    R_memset ((POINTER)m, 0, sizeof (m));

    return (0);
}


/**
 * RSA public-key decryption, according to PKCS #1.
 */
int RSAPublicDecrypt(
    unsigned char *output,              /* output block				*/
    unsigned int *outputLen,            /* length of output block	*/
    unsigned char *input,               /* input block				*/
    unsigned int inputLen,              /* length of input block	*/
    R_RSA_PUBLIC_KEY *publicKey)        /* RSA public key			*/
{
    int status;
    unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];
    unsigned int i, modulusLen, pkcsBlockLen;

    modulusLen = (publicKey->bits + 7) / 8;
    if (inputLen > modulusLen)
        return (RE_LEN);

    status = RSAPublicBlock(pkcsBlock, &pkcsBlockLen, input, inputLen, publicKey) ;
    if (status)
        return (status);

    if (pkcsBlockLen != modulusLen)
        return (RE_LEN);

    /**
     * Require block type 1.
     */
    if ((pkcsBlock[0] != 0) || (pkcsBlock[1] != 1))
        return (RE_DATA);

    for (i = 2; i < modulusLen-1; i++)
    {
        if (pkcsBlock[i] != 0xff)
            break;
    }

    /* separator */
    if (pkcsBlock[i++] != 0)
        return (RE_DATA);

    *outputLen = modulusLen - i;

    if (*outputLen + 11 > modulusLen)
        return (RE_DATA);

    R_memcpy((POINTER)output, (POINTER)&pkcsBlock[i], *outputLen);

    /**
     * Zeroize potentially sensitive information.
     */
    R_memset ((POINTER)pkcsBlock, 0, sizeof (pkcsBlock));

    return (0);
}

/* RSA private-key encryption, according to PKCS #1.
 */
int RSAPrivateEncrypt(
    unsigned char *output,                                      /* output block */
    unsigned int *outputLen,                          /* length of output block */
    unsigned char *input,                                        /* input block */
    unsigned int inputLen,                             /* length of input block */
    R_RSA_PRIVATE_KEY *privateKey)                           /* RSA private key */
{
    int status;
    unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];
    unsigned int i, modulusLen;

    modulusLen = (privateKey->bits + 7) / 8;
    if (inputLen + 11 > modulusLen)
        return (RE_LEN);

    pkcsBlock[0] = 0;
    /* block type 1 */
    pkcsBlock[1] = 1;

    for (i = 2; i < modulusLen - inputLen - 1; i++)
    pkcsBlock[i] = 0xff;

    /* separator */
    pkcsBlock[i++] = 0;

    R_memcpy ((POINTER)&pkcsBlock[i], (POINTER)input, inputLen);

    status = RSAPrivateBlock(output, outputLen, pkcsBlock, modulusLen, privateKey);

    /* Zeroize potentially sensitive information.
    */
    R_memset ((POINTER)pkcsBlock, 0, sizeof (pkcsBlock));

    return (status);
}

