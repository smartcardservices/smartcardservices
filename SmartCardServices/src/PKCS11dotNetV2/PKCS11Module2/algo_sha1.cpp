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
#include "MarshallerCfg.h"
#include "algo_utils.h"
#include "algo_sha1.h"

const u1 sha1_padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#define sha1_S(x,n)             ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define sha1_R(t)               (temp = data[(t - 3) & 0x0F] ^ data[(t - 8) & 0x0F] ^ data[(t - 14) & 0x0F] ^ data[t & 0x0F], (data[t & 0x0F] = sha1_S(temp,1)))

#define sha1_P(a,b,c,d,e,x)     {e += sha1_S(a,5) + F(b,c,d) + K + x; b = sha1_S(b,30);}

void algo_sha1_starts(algo_sha1_context *ctx)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->digest[0] = 0x67452301;
    ctx->digest[1] = 0xEFCDAB89;
    ctx->digest[2] = 0x98BADCFE;
    ctx->digest[3] = 0x10325476;
    ctx->digest[4] = 0xC3D2E1F0;
}

static void algo_sha1_compress(algo_sha1_context *ctx, u4* data)
{
    u4 temp, A, B, C, D, E;
    u1 i;

	// little endian processing
    if (IS_LITTLE_ENDIAN)
    {
        for (i = 0; i < (SHA1_BLOCK_LENGTH / sizeof(u4)); i++) {
            data[i] = swapbytes_u4(data[i]);
        }
    }

    A = ctx->digest[0];
    B = ctx->digest[1];
    C = ctx->digest[2];
    D = ctx->digest[3];
    E = ctx->digest[4];

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

    sha1_P(A, B, C, D, E, data[0]);
    sha1_P(E, A, B, C, D, data[1]);
    sha1_P(D, E, A, B, C, data[2]);
    sha1_P(C, D, E, A, B, data[3]);
    sha1_P(B, C, D, E, A, data[4]);
    sha1_P(A, B, C, D, E, data[5]);
    sha1_P(E, A, B, C, D, data[6]);
    sha1_P(D, E, A, B, C, data[7]);
    sha1_P(C, D, E, A, B, data[8]);
    sha1_P(B, C, D, E, A, data[9]);
    sha1_P(A, B, C, D, E, data[10]);
    sha1_P(E, A, B, C, D, data[11]);
    sha1_P(D, E, A, B, C, data[12]);
    sha1_P(C, D, E, A, B, data[13]);
    sha1_P(B, C, D, E, A, data[14]);
    sha1_P(A, B, C, D, E, data[15]);
    sha1_P(E, A, B, C, D, sha1_R(16));
    sha1_P(D, E, A, B, C, sha1_R(17));
    sha1_P(C, D, E, A, B, sha1_R(18));
    sha1_P(B, C, D, E, A, sha1_R(19));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

    sha1_P(A, B, C, D, E, sha1_R(20));
    sha1_P(E, A, B, C, D, sha1_R(21));
    sha1_P(D, E, A, B, C, sha1_R(22));
    sha1_P(C, D, E, A, B, sha1_R(23));
    sha1_P(B, C, D, E, A, sha1_R(24));
    sha1_P(A, B, C, D, E, sha1_R(25));
    sha1_P(E, A, B, C, D, sha1_R(26));
    sha1_P(D, E, A, B, C, sha1_R(27));
    sha1_P(C, D, E, A, B, sha1_R(28));
    sha1_P(B, C, D, E, A, sha1_R(29));
    sha1_P(A, B, C, D, E, sha1_R(30));
    sha1_P(E, A, B, C, D, sha1_R(31));
    sha1_P(D, E, A, B, C, sha1_R(32));
    sha1_P(C, D, E, A, B, sha1_R(33));
    sha1_P(B, C, D, E, A, sha1_R(34));
    sha1_P(A, B, C, D, E, sha1_R(35));
    sha1_P(E, A, B, C, D, sha1_R(36));
    sha1_P(D, E, A, B, C, sha1_R(37));
    sha1_P(C, D, E, A, B, sha1_R(38));
    sha1_P(B, C, D, E, A, sha1_R(39));

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

    sha1_P(A, B, C, D, E, sha1_R(40));
    sha1_P(E, A, B, C, D, sha1_R(41));
    sha1_P(D, E, A, B, C, sha1_R(42));
    sha1_P(C, D, E, A, B, sha1_R(43));
    sha1_P(B, C, D, E, A, sha1_R(44));
    sha1_P(A, B, C, D, E, sha1_R(45));
    sha1_P(E, A, B, C, D, sha1_R(46));
    sha1_P(D, E, A, B, C, sha1_R(47));
    sha1_P(C, D, E, A, B, sha1_R(48));
    sha1_P(B, C, D, E, A, sha1_R(49));
    sha1_P(A, B, C, D, E, sha1_R(50));
    sha1_P(E, A, B, C, D, sha1_R(51));
    sha1_P(D, E, A, B, C, sha1_R(52));
    sha1_P(C, D, E, A, B, sha1_R(53));
    sha1_P(B, C, D, E, A, sha1_R(54));
    sha1_P(A, B, C, D, E, sha1_R(55));
    sha1_P(E, A, B, C, D, sha1_R(56));
    sha1_P(D, E, A, B, C, sha1_R(57));
    sha1_P(C, D, E, A, B, sha1_R(58));
    sha1_P(B, C, D, E, A, sha1_R(59));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

    sha1_P(A, B, C, D, E, sha1_R(60));
    sha1_P(E, A, B, C, D, sha1_R(61));
    sha1_P(D, E, A, B, C, sha1_R(62));
    sha1_P(C, D, E, A, B, sha1_R(63));
    sha1_P(B, C, D, E, A, sha1_R(64));
    sha1_P(A, B, C, D, E, sha1_R(65));
    sha1_P(E, A, B, C, D, sha1_R(66));
    sha1_P(D, E, A, B, C, sha1_R(67));
    sha1_P(C, D, E, A, B, sha1_R(68));
    sha1_P(B, C, D, E, A, sha1_R(69));
    sha1_P(A, B, C, D, E, sha1_R(70));
    sha1_P(E, A, B, C, D, sha1_R(71));
    sha1_P(D, E, A, B, C, sha1_R(72));
    sha1_P(C, D, E, A, B, sha1_R(73));
    sha1_P(B, C, D, E, A, sha1_R(74));
    sha1_P(A, B, C, D, E, sha1_R(75));
    sha1_P(E, A, B, C, D, sha1_R(76));
    sha1_P(D, E, A, B, C, sha1_R(77));
    sha1_P(C, D, E, A, B, sha1_R(78));
    sha1_P(B, C, D, E, A, sha1_R(79));

#undef K
#undef F

    ctx->digest[0] += A;
    ctx->digest[1] += B;
    ctx->digest[2] += C;
    ctx->digest[3] += D;
    ctx->digest[4] += E;
}

void algo_sha1_update(algo_sha1_context* ctx, u1* input, u4 length)
{
    u4 left, fill;

    if (!length) return;

    left = ctx->total[0] & 0x3F;
    fill = SHA1_BLOCK_LENGTH - left;

    ctx->total[0] += length;
    ctx->total[0] &= 0xFFFFFFFF;

    if(ctx->total[0] < length) {
        ctx->total[1]++;
    }

    if (left && (length >= fill)) {
        //CopyVolatile(input, ctx->input + left, fill);
        memcpy(ctx->input + left,input,fill);
        algo_sha1_compress(ctx, (u4*)ctx->input);
        length -= fill;
        input  += fill;
        left = 0;
    }

    while(length >= SHA1_BLOCK_LENGTH) {
        algo_sha1_compress(ctx, (u4*)input);
        length -= SHA1_BLOCK_LENGTH;
        input  += SHA1_BLOCK_LENGTH;
    }

    if (length) {
        //CopyVolatile(input, ctx->input + left, length);
        memcpy(ctx->input + left,input,length);
    }
}

void algo_sha1_finish(algo_sha1_context *ctx)
{
    u4 last, padn;
    u4 msglen[2];
    u1 i;

	// little endian processing
    if (IS_LITTLE_ENDIAN)
    {
        msglen[0] = swapbytes_u4((ctx->total[0] >> 29) | (ctx->total[1] << 3));
        msglen[1] = swapbytes_u4((ctx->total[0] << 3));
    }
    else
    {
        msglen[0] = (ctx->total[0] << 3);
        msglen[1] = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    }

    last = ctx->total[0] & 0x3F;
    padn = (last < (SHA1_BLOCK_LENGTH - sizeof(msglen))) ? ((SHA1_BLOCK_LENGTH - sizeof(msglen)) - last) : (((2 * SHA1_BLOCK_LENGTH) - sizeof(msglen)) - last);

    algo_sha1_update(ctx, (u1*)sha1_padding, padn);
    algo_sha1_update(ctx, (u1*)msglen, 8);

	// little endian processing
    if (IS_LITTLE_ENDIAN)
    {
        for (i = 0; i < (SHA1_HASH_LENGTH / sizeof(u4)); i++) {
            ctx->digest[i] = swapbytes_u4(ctx->digest[i]);
        }
    }
}

