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
#include "md5.h"

CMD5::CMD5(){
    this->_hashValue     = (CK_BYTE_PTR)malloc(MD5_HASH_LENGTH);
    this->_workingBuffer = (CK_BYTE_PTR)malloc(MD5_BLOCK_LENGTH);
    this->_hashLength    = MD5_HASH_LENGTH;
    this->_blockLength   = MD5_BLOCK_LENGTH;
}

CMD5::~CMD5(){
}

void CMD5::TransformBlock(CK_BYTE_PTR data,CK_LONG counter,CK_BYTE_PTR result)
{
    algo_md5_context ctx;

    ctx.digest = (u4*)result;

    if (counter == 0) {
		algo_md5_starts(&ctx);
    } else {
        ctx.total[0] = counter;
        ctx.total[1] = 0;
    }

    algo_md5_update(&ctx, data, MD5_BLOCK_LENGTH);
}

void CMD5::TransformFinalBlock(CK_BYTE_PTR data,CK_LONG length,CK_LONG counter,CK_BYTE_PTR result)
{
    algo_md5_context ctx;

    ctx.digest = (u4*)result;

    if (counter == 0) {
		algo_md5_starts(&ctx);
    } else {
        ctx.total[0] = counter;
        ctx.total[1] = 0;
    }

    // allocate tempory working buffer
    ctx.input = (u1*)malloc(MD5_BLOCK_LENGTH);
    memset(ctx.input,0,MD5_BLOCK_LENGTH);

    algo_md5_update(&ctx,data,length);
    algo_md5_finish(&ctx);

    free(ctx.input);
}

