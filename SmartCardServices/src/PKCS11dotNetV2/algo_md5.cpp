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

#include <cstring>

#include "MarshallerCfg.h"
#include "algo_utils.h"
#include "algo_md5.h"

extern bool IS_LITTLE_ENDIAN;
extern bool IS_BIG_ENDIAN;

const u1 md5_padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#define md5_S(x,n)              ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define md5_P(a,b,c,d,k,s,t)    {a += F(b,c,d) + data[k] + t; a = md5_S(a,s) + b;}

void algo_md5_starts(algo_md5_context* ctx)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->digest[0] = 0x67452301;
    ctx->digest[1] = 0xEFCDAB89;
    ctx->digest[2] = 0x98BADCFE;
    ctx->digest[3] = 0x10325476;
}


static void algo_md5_compress(algo_md5_context *ctx, u4* data)
{
    u4 A, B, C, D;

    // big endian processing
    if (IS_BIG_ENDIAN)
    {
        u1 i;
        for (i = 0; i < (MD5_BLOCK_LENGTH / sizeof(u4)); i++) {
            data[i] = swapbytes_u4(data[i]);
        }
    }

    A = ctx->digest[0];
    B = ctx->digest[1];
    C = ctx->digest[2];
    D = ctx->digest[3];

#define F(x,y,z) (z ^ (x & (y ^ z)))

    md5_P(A, B, C, D,  0,  7, 0xD76AA478);
    md5_P(D, A, B, C,  1, 12, 0xE8C7B756);
    md5_P(C, D, A, B,  2, 17, 0x242070DB);
    md5_P(B, C, D, A,  3, 22, 0xC1BDCEEE);
    md5_P(A, B, C, D,  4,  7, 0xF57C0FAF);
    md5_P(D, A, B, C,  5, 12, 0x4787C62A);
    md5_P(C, D, A, B,  6, 17, 0xA8304613);
    md5_P(B, C, D, A,  7, 22, 0xFD469501);
    md5_P(A, B, C, D,  8,  7, 0x698098D8);
    md5_P(D, A, B, C,  9, 12, 0x8B44F7AF);
    md5_P(C, D, A, B, 10, 17, 0xFFFF5BB1);
    md5_P(B, C, D, A, 11, 22, 0x895CD7BE);
    md5_P(A, B, C, D, 12,  7, 0x6B901122);
    md5_P(D, A, B, C, 13, 12, 0xFD987193);
    md5_P(C, D, A, B, 14, 17, 0xA679438E);
    md5_P(B, C, D, A, 15, 22, 0x49B40821);

#undef F

#define F(x,y,z) (y ^ (z & (x ^ y)))

    md5_P(A, B, C, D,  1,  5, 0xF61E2562);
    md5_P(D, A, B, C,  6,  9, 0xC040B340);
    md5_P(C, D, A, B, 11, 14, 0x265E5A51);
    md5_P(B, C, D, A,  0, 20, 0xE9B6C7AA);
    md5_P(A, B, C, D,  5,  5, 0xD62F105D);
    md5_P(D, A, B, C, 10,  9, 0x02441453);
    md5_P(C, D, A, B, 15, 14, 0xD8A1E681);
    md5_P(B, C, D, A,  4, 20, 0xE7D3FBC8);
    md5_P(A, B, C, D,  9,  5, 0x21E1CDE6);
    md5_P(D, A, B, C, 14,  9, 0xC33707D6);
    md5_P(C, D, A, B,  3, 14, 0xF4D50D87);
    md5_P(B, C, D, A,  8, 20, 0x455A14ED);
    md5_P(A, B, C, D, 13,  5, 0xA9E3E905);
    md5_P(D, A, B, C,  2,  9, 0xFCEFA3F8);
    md5_P(C, D, A, B,  7, 14, 0x676F02D9);
    md5_P(B, C, D, A, 12, 20, 0x8D2A4C8A);

#undef F

#define F(x,y,z) (x ^ y ^ z)

    md5_P(A, B, C, D,  5,  4, 0xFFFA3942);
    md5_P(D, A, B, C,  8, 11, 0x8771F681);
    md5_P(C, D, A, B, 11, 16, 0x6D9D6122);
    md5_P(B, C, D, A, 14, 23, 0xFDE5380C);
    md5_P(A, B, C, D,  1,  4, 0xA4BEEA44);
    md5_P(D, A, B, C,  4, 11, 0x4BDECFA9);
    md5_P(C, D, A, B,  7, 16, 0xF6BB4B60);
    md5_P(B, C, D, A, 10, 23, 0xBEBFBC70);
    md5_P(A, B, C, D, 13,  4, 0x289B7EC6);
    md5_P(D, A, B, C,  0, 11, 0xEAA127FA);
    md5_P(C, D, A, B,  3, 16, 0xD4EF3085);
    md5_P(B, C, D, A,  6, 23, 0x04881D05);
    md5_P(A, B, C, D,  9,  4, 0xD9D4D039);
    md5_P(D, A, B, C, 12, 11, 0xE6DB99E5);
    md5_P(C, D, A, B, 15, 16, 0x1FA27CF8);
    md5_P(B, C, D, A,  2, 23, 0xC4AC5665);

#undef F

#define F(x,y,z) (y ^ (x | ~z))

    md5_P(A, B, C, D,  0,  6, 0xF4292244);
    md5_P(D, A, B, C,  7, 10, 0x432AFF97);
    md5_P(C, D, A, B, 14, 15, 0xAB9423A7);
    md5_P(B, C, D, A,  5, 21, 0xFC93A039);
    md5_P(A, B, C, D, 12,  6, 0x655B59C3);
    md5_P(D, A, B, C,  3, 10, 0x8F0CCC92);
    md5_P(C, D, A, B, 10, 15, 0xFFEFF47D);
    md5_P(B, C, D, A,  1, 21, 0x85845DD1);
    md5_P(A, B, C, D,  8,  6, 0x6FA87E4F);
    md5_P(D, A, B, C, 15, 10, 0xFE2CE6E0);
    md5_P(C, D, A, B,  6, 15, 0xA3014314);
    md5_P(B, C, D, A, 13, 21, 0x4E0811A1);
    md5_P(A, B, C, D,  4,  6, 0xF7537E82);
    md5_P(D, A, B, C, 11, 10, 0xBD3AF235);
    md5_P(C, D, A, B,  2, 15, 0x2AD7D2BB);
    md5_P(B, C, D, A,  9, 21, 0xEB86D391);

#undef F

    ctx->digest[0] += A;
    ctx->digest[1] += B;
    ctx->digest[2] += C;
    ctx->digest[3] += D;
}

void algo_md5_update(algo_md5_context* ctx, u1* input, u4 length)
{
    u4 left, fill;

    if (!length) return;

    left = ctx->total[0] & 0x3F;
    fill = MD5_BLOCK_LENGTH - left;

    ctx->total[0] += length;
    ctx->total[0] &= 0xFFFFFFFF;

    if(ctx->total[0] < length) {
        ctx->total[1]++;
    }

    if (left && (length >= fill)) {
        memcpy(ctx->input + left,input,fill);
        algo_md5_compress(ctx, (u4*)ctx->input);
        length -= fill;
        input  += fill;
        left = 0;
    }

    while(length >= MD5_BLOCK_LENGTH) {
        algo_md5_compress(ctx, (u4*)input);
        length -= MD5_BLOCK_LENGTH;
        input  += MD5_BLOCK_LENGTH;
    }

    if (length) {
        memcpy(ctx->input + left,input,length);
    }
}

void algo_md5_finish(algo_md5_context *ctx)
{
    u4 last, padn;
    u4 msglen[2];

	// little endian processing
    if (IS_LITTLE_ENDIAN)
    {
        msglen[0] = (ctx->total[0] << 3);
        msglen[1] = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    }
    // big endian processing
    else
    {
        msglen[0] = swapbytes_u4((ctx->total[0] >> 29) | (ctx->total[1] << 3));
        msglen[1] = swapbytes_u4((ctx->total[0] << 3));
    }

    last = ctx->total[0] & 0x3F;
    padn = (last < (MD5_BLOCK_LENGTH - sizeof(msglen))) ? ((MD5_BLOCK_LENGTH - sizeof(msglen)) - last) : (((2 * MD5_BLOCK_LENGTH) - sizeof(msglen)) - last);

    algo_md5_update(ctx, (u1*)md5_padding, padn);
    algo_md5_update(ctx, (u1*)msglen, sizeof(msglen));

	// big endian processing
    if (IS_BIG_ENDIAN)
    {
        u1 i;
        for (i = 0; i < (MD5_HASH_LENGTH / sizeof(u4)); i++) {
            ctx->digest[i] = swapbytes_u4(ctx->digest[i]);
        }
    }
}

