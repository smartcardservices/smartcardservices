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
#include "sha256.h"

CSHA256::CSHA256(){
    this->_hashValue     = (CK_BYTE_PTR)malloc(SHA256_HASH_LENGTH);
    this->_workingBuffer = (CK_BYTE_PTR)malloc(SHA256_BLOCK_LENGTH);
    this->_hashLength    = SHA256_HASH_LENGTH;
    this->_blockLength   = SHA256_BLOCK_LENGTH;
}

CSHA256::~CSHA256(){
}

void CSHA256::TransformBlock(CK_BYTE_PTR data,CK_LONG counter,CK_BYTE_PTR result)
{
    algo_sha256_context* ctx = (algo_sha256_context*)malloc(sizeof(algo_sha256_context));

    ctx->digest = (u4*)result;

    if (counter == 0) {
		algo_sha256_starts(ctx);
    } else {
        ctx->total[0] = counter;
        ctx->total[1] = 0;
    }

    algo_sha256_update(ctx, data, SHA256_BLOCK_LENGTH);

    free((u1*)ctx);
}

void CSHA256::TransformFinalBlock(CK_BYTE_PTR data,CK_LONG length,CK_LONG counter,CK_BYTE_PTR result)
{
    algo_sha256_context* ctx = (algo_sha256_context*)malloc(sizeof(algo_sha256_context));

    ctx->digest = (u4*)result;

    if (counter == 0) {
		algo_sha256_starts(ctx);
    } else {
        ctx->total[0] = counter;
        ctx->total[1] = 0;
    }

    // allocate tempory working buffer
    ctx->input = (u1*)malloc(SHA256_BLOCK_LENGTH);
    memset(ctx->input, 0,SHA256_BLOCK_LENGTH);

    // warning: algo_sha1_update must not throw any exception.
    algo_sha256_update(ctx, data, length);
    algo_sha256_finish(ctx);

    free(ctx->input);
    free((u1*)ctx);
}

