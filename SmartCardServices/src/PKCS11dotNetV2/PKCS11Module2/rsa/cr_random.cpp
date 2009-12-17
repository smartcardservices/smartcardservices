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
#include "ha_config.h"
#include "cr_random.h"
#include "cr_global.h"
#include "platconfig.h"
#include "digest.h"
#include "md5.h"

#include "cr_rsa.h"

#define RANDOM_BYTES_NEEDED 256

int R_GenerateBytes(
    unsigned char *block,				/* block			*/
    unsigned int blockLen,				/* length of block	*/
    R_RANDOM_STRUCT *randomStruct)		/* random structure */
{
    unsigned int available, i;

    if (randomStruct->bytesNeeded)
    {
        return (RE_NEED_RANDOM);
    }

    available = randomStruct->outputAvailable;

    while (blockLen > available)
    {
        R_memcpy( (POINTER)block,
                  (POINTER)&randomStruct->output[16-available],
                  available) ;
        block += available;
        blockLen -= available;

        // Generate new output
        CMD5* md4Ctx = new CMD5();
        md4Ctx->HashCore(randomStruct->state,0,16);
        md4Ctx->HashFinal(randomStruct->output);
        delete md4Ctx;

        available = 16;

        /**
         * increment state
         */
        for (i = 0; i < 16; i++)
        {
            if (randomStruct->state[15-i]++)
                break;
        }
    }

    R_memcpy((POINTER)block, (POINTER)&randomStruct->output[16-available], blockLen);
    randomStruct->outputAvailable = available - blockLen;

    return (0);
}


int R_RandomInit(R_RANDOM_STRUCT *randomStruct)
{
    randomStruct->bytesNeeded = RANDOM_BYTES_NEEDED;
    R_memset ((POINTER)randomStruct->state, 0, sizeof (randomStruct->state));
    randomStruct->outputAvailable = 0;

    return (0);
}


int R_RandomUpdate(
    R_RANDOM_STRUCT *randomStruct,            /* random structure			*/
    unsigned char *block,                     /* block of values to mix in	*/
    unsigned int blockLen)                    /* length of block			*/
{
    unsigned char digest[16];
    unsigned int i, x;

    CMD5* md5Ctx = new CMD5();
    md5Ctx->HashCore(block,0,blockLen);
    md5Ctx->HashFinal(digest);
    delete md5Ctx;

    /* add digest to state */
    x = 0;
    for (i = 0; i < 16; i++)
    {
        x += randomStruct->state[15-i] + digest[15-i];
        randomStruct->state[15-i] = (unsigned char)x;
        x >>= 8;
    }

    if (randomStruct->bytesNeeded < blockLen)
        randomStruct->bytesNeeded = 0;
    else
        randomStruct->bytesNeeded -= blockLen;

    /**
     * Zeroize sensitive information.
     */
    R_memset ((POINTER)digest, 0, sizeof (digest));
    x = 0;

    return (0);
}


int R_GetRandomBytesNeeded(
    unsigned int *bytesNeeded,             /* number of mix-in bytes needed */
    R_RANDOM_STRUCT *randomStruct)         /* random structure				*/
{
    *bytesNeeded = randomStruct->bytesNeeded;
    return (0);
}


void R_RandomFinal(R_RANDOM_STRUCT *randomStruct)
{
    R_memset((POINTER)randomStruct, 0, sizeof (*randomStruct)) ;
}


/**
 * Initialize the random structure with all zero seed bytes.
 *
 * NOTE: that this will cause the output of the "random" process
 * to be the same every time. To produce random bytes, the random
 * struct needs random seeds.
 */
void InitRandomStruct(R_RANDOM_STRUCT *randomStruct)
{
    static unsigned char seedByte = 0;
    unsigned int bytesNeeded;

    R_RandomInit (randomStruct);

    /**
     * Initialize with all zero seed bytes, which will not yield
     * an actual random number output.
     */
    int iCondition = 1;
    while( iCondition )
    {
        R_GetRandomBytesNeeded (&bytesNeeded, randomStruct);
        if (bytesNeeded == 0)
            break;

        R_RandomUpdate (randomStruct, &seedByte, 1);
    }
}

