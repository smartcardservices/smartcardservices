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
#include "platconfig.h"
#include "digest.h"
#include "sha1.h"

CSHA1::CSHA1(){
    this->_hashValue     = (CK_BYTE_PTR)malloc(SHA1_HASH_LENGTH);
    this->_workingBuffer = (CK_BYTE_PTR)malloc(SHA1_BLOCK_LENGTH);
    this->_hashLength    = SHA1_HASH_LENGTH;
    this->_blockLength   = SHA1_BLOCK_LENGTH;
}

CSHA1::~CSHA1(){
}

void CSHA1::TransformBlock(CK_BYTE_PTR data,CK_LONG counter,CK_BYTE_PTR result)
{
    algo_sha1_context ctx;

    ctx.digest = (u4*)result;

    if (counter == 0) {
		algo_sha1_starts(&ctx);
    } else {
        ctx.total[0] = counter;
        ctx.total[1] = 0;
    }

    algo_sha1_update(&ctx, data, SHA1_BLOCK_LENGTH);
}

void CSHA1::TransformFinalBlock(CK_BYTE_PTR data,CK_LONG length,CK_LONG counter,CK_BYTE_PTR result)
{
    algo_sha1_context ctx;

    ctx.digest = (u4*)result;

    if (counter == 0) {
		algo_sha1_starts(&ctx);
    } else {
        ctx.total[0] = counter;
        ctx.total[1] = 0;
    }

    ctx.input = (u1*)malloc(SHA1_BLOCK_LENGTH);
    memset(ctx.input,0,SHA1_BLOCK_LENGTH);

    algo_sha1_update(&ctx, data, length);
    algo_sha1_finish(&ctx);

    free(ctx.input);
}

