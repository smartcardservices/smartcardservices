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
#include "algo_sha256.h"

const u1 sha256_padding[64] =
{
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#define SHR(x,n)  ((x & 0xFFFFFFFF) >> n)
#define ROTR(x,n) (SHR(x,n) | (x << (32 - n)))

#define SHA256_S0(x) (ROTR(x, 7) ^ ROTR(x,18) ^  SHR(x, 3))
#define SHA256_S1(x) (ROTR(x,17) ^ ROTR(x,19) ^  SHR(x,10))
#define SHA256_S2(x) (ROTR(x, 2) ^ ROTR(x,13) ^  ROTR(x,22))
#define SHA256_S3(x) (ROTR(x, 6) ^ ROTR(x,11) ^  ROTR(x,25))

#define SHA256_F0(x,y,z) ((x & y) | (z & (x | y)))
#define SHA256_F1(x,y,z) (z ^ (x & (y ^ z)))

void algo_sha256_starts(algo_sha256_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->digest[0] = 0x6A09E667;
    ctx->digest[1] = 0xBB67AE85;
    ctx->digest[2] = 0x3C6EF372;
    ctx->digest[3] = 0xA54FF53A;
    ctx->digest[4] = 0x510E527F;
    ctx->digest[5] = 0x9B05688C;
    ctx->digest[6] = 0x1F83D9AB;
    ctx->digest[7] = 0x5BE0CD19;
}

#ifdef _SHA256_SIZE_OPTIMIZED_VERSION

    static algo_sha256_context* algo_sha256_tmpCtx;

    static void sha256_P(u4 a, u4 b, u4 c, u4* d, u4 e, u4 f, u4 g, u4* h, u1 i, u4 K)
    {
        u4 temp1;
        u4 temp2;

	    if (i > 15) {
    	    algo_sha256_tmpCtx->processingBuffer[i] = SHA256_S1(algo_sha256_tmpCtx->processingBuffer[i -  2]) + algo_sha256_tmpCtx->processingBuffer[i -  7] + SHA256_S0(algo_sha256_tmpCtx->processingBuffer[i - 15]) + algo_sha256_tmpCtx->processingBuffer[i - 16];
	    }

	    temp1 = *h + SHA256_S3(e) + SHA256_F1(e,f,g) + K + algo_sha256_tmpCtx->processingBuffer[i];
	    temp2 = SHA256_S2(a) + SHA256_F0(a,b,c);

        *d += temp1;
	    *h = temp1 + temp2;
    }

    static void algo_sha256_compress(algo_sha256_context *ctx, u4* input)
    {

        u4 A, B, C, D, E, F, G, H;
        u1 i;

        // little endian processing
        if (IS_LITTLE_ENDIAN)
        {
            for (i = 0; i < (SHA256_BLOCK_LENGTH / sizeof(u4)); i++) {
                ctx->processingBuffer[i] = swapbytes_u4(input[i]);
            }
        }
        A = ctx->digest[0];
        B = ctx->digest[1];
        C = ctx->digest[2];
        D = ctx->digest[3];
        E = ctx->digest[4];
        F = ctx->digest[5];
        G = ctx->digest[6];
        H = ctx->digest[7];

        algo_sha256_tmpCtx = ctx;

        sha256_P(A, B, C, &D, E, F, G, &H, 0, 0x428A2F98);
        sha256_P(H, A, B, &C, D, E, F, &G, 1, 0x71374491);
        sha256_P(G, H, A, &B, C, D, E, &F, 2, 0xB5C0FBCF);
        sha256_P(F, G, H, &A, B, C, D, &E, 3, 0xE9B5DBA5);
        sha256_P(E, F, G, &H, A, B, C, &D, 4, 0x3956C25B);
        sha256_P(D, E, F, &G, H, A, B, &C, 5, 0x59F111F1);
        sha256_P(C, D, E, &F, G, H, A, &B, 6, 0x923F82A4);
        sha256_P(B, C, D, &E, F, G, H, &A, 7, 0xAB1C5ED5);
        sha256_P(A, B, C, &D, E, F, G, &H, 8, 0xD807AA98);
        sha256_P(H, A, B, &C, D, E, F, &G, 9, 0x12835B01);
        sha256_P(G, H, A, &B, C, D, E, &F, 10, 0x243185BE);
        sha256_P(F, G, H, &A, B, C, D, &E, 11, 0x550C7DC3);
        sha256_P(E, F, G, &H, A, B, C, &D, 12, 0x72BE5D74);
        sha256_P(D, E, F, &G, H, A, B, &C, 13, 0x80DEB1FE);
        sha256_P(C, D, E, &F, G, H, A, &B, 14, 0x9BDC06A7);
        sha256_P(B, C, D, &E, F, G, H, &A, 15, 0xC19BF174);
        sha256_P(A, B, C, &D, E, F, G, &H, 16, 0xE49B69C1);
        sha256_P(H, A, B, &C, D, E, F, &G, 17, 0xEFBE4786);
        sha256_P(G, H, A, &B, C, D, E, &F, 18, 0x0FC19DC6);
        sha256_P(F, G, H, &A, B, C, D, &E, 19, 0x240CA1CC);
        sha256_P(E, F, G, &H, A, B, C, &D, 20, 0x2DE92C6F);
        sha256_P(D, E, F, &G, H, A, B, &C, 21, 0x4A7484AA);
        sha256_P(C, D, E, &F, G, H, A, &B, 22, 0x5CB0A9DC);
        sha256_P(B, C, D, &E, F, G, H, &A, 23, 0x76F988DA);
        sha256_P(A, B, C, &D, E, F, G, &H, 24, 0x983E5152);
        sha256_P(H, A, B, &C, D, E, F, &G, 25, 0xA831C66D);
        sha256_P(G, H, A, &B, C, D, E, &F, 26, 0xB00327C8);
        sha256_P(F, G, H, &A, B, C, D, &E, 27, 0xBF597FC7);
        sha256_P(E, F, G, &H, A, B, C, &D, 28, 0xC6E00BF3);
        sha256_P(D, E, F, &G, H, A, B, &C, 29, 0xD5A79147);
        sha256_P(C, D, E, &F, G, H, A, &B, 30, 0x06CA6351);
        sha256_P(B, C, D, &E, F, G, H, &A, 31, 0x14292967);
        sha256_P(A, B, C, &D, E, F, G, &H, 32, 0x27B70A85);
        sha256_P(H, A, B, &C, D, E, F, &G, 33, 0x2E1B2138);
        sha256_P(G, H, A, &B, C, D, E, &F, 34, 0x4D2C6DFC);
        sha256_P(F, G, H, &A, B, C, D, &E, 35, 0x53380D13);
        sha256_P(E, F, G, &H, A, B, C, &D, 36, 0x650A7354);
        sha256_P(D, E, F, &G, H, A, B, &C, 37, 0x766A0ABB);
        sha256_P(C, D, E, &F, G, H, A, &B, 38, 0x81C2C92E);
        sha256_P(B, C, D, &E, F, G, H, &A, 39, 0x92722C85);
        sha256_P(A, B, C, &D, E, F, G, &H, 40, 0xA2BFE8A1);
        sha256_P(H, A, B, &C, D, E, F, &G, 41, 0xA81A664B);
        sha256_P(G, H, A, &B, C, D, E, &F, 42, 0xC24B8B70);
        sha256_P(F, G, H, &A, B, C, D, &E, 43, 0xC76C51A3);
        sha256_P(E, F, G, &H, A, B, C, &D, 44, 0xD192E819);
        sha256_P(D, E, F, &G, H, A, B, &C, 45, 0xD6990624);
        sha256_P(C, D, E, &F, G, H, A, &B, 46, 0xF40E3585);
        sha256_P(B, C, D, &E, F, G, H, &A, 47, 0x106AA070);
        sha256_P(A, B, C, &D, E, F, G, &H, 48, 0x19A4C116);
        sha256_P(H, A, B, &C, D, E, F, &G, 49, 0x1E376C08);
        sha256_P(G, H, A, &B, C, D, E, &F, 50, 0x2748774C);
        sha256_P(F, G, H, &A, B, C, D, &E, 51, 0x34B0BCB5);
        sha256_P(E, F, G, &H, A, B, C, &D, 52, 0x391C0CB3);
        sha256_P(D, E, F, &G, H, A, B, &C, 53, 0x4ED8AA4A);
        sha256_P(C, D, E, &F, G, H, A, &B, 54, 0x5B9CCA4F);
        sha256_P(B, C, D, &E, F, G, H, &A, 55, 0x682E6FF3);
        sha256_P(A, B, C, &D, E, F, G, &H, 56, 0x748F82EE);
        sha256_P(H, A, B, &C, D, E, F, &G, 57, 0x78A5636F);
        sha256_P(G, H, A, &B, C, D, E, &F, 58, 0x84C87814);
        sha256_P(F, G, H, &A, B, C, D, &E, 59, 0x8CC70208);
        sha256_P(E, F, G, &H, A, B, C, &D, 60, 0x90BEFFFA);
        sha256_P(D, E, F, &G, H, A, B, &C, 61, 0xA4506CEB);
        sha256_P(C, D, E, &F, G, H, A, &B, 62, 0xBEF9A3F7);
        sha256_P(B, C, D, &E, F, G, H, &A, 63, 0xC67178F2);

        ctx->digest[0] += A;
        ctx->digest[1] += B;
        ctx->digest[2] += C;
        ctx->digest[3] += D;
        ctx->digest[4] += E;
        ctx->digest[5] += F;
        ctx->digest[6] += G;
        ctx->digest[7] += H;
    }

#else

    #define SHA256_R(t)                                       \
    (                                                         \
        ctx->processingBuffer[t] = SHA256_S1(ctx->processingBuffer[t -  2]) + ctx->processingBuffer[t -  7] +    \
                SHA256_S0(ctx->processingBuffer[t - 15]) + ctx->processingBuffer[t - 16]      \
    )

    #define SHA256_P(a,b,c,d,e,f,g,h,x,K)                         \
    {                                                             \
        temp1 = h + SHA256_S3(e) + SHA256_F1(e,f,g) + K + x;      \
        temp2 = SHA256_S2(a) + SHA256_F0(a,b,c);                  \
        d += temp1; h = temp1 + temp2;                            \
    }

    static void algo_sha256_compress(algo_sha256_context *ctx, u4* input)
    {
        u4 temp1, temp2;
        u4 A, B, C, D, E, F, G, H;
        u1 i;

        // little endian processing
        if (IS_LITTLE_ENDIAN)
        {
            for (i = 0; i < (SHA256_BLOCK_LENGTH / sizeof(u4)); i++) {
                ctx->processingBuffer[i] = swapbytes_u4(input[i]);
            }
        }
        else
        {
            for (i = 0; i < (SHA256_BLOCK_LENGTH / sizeof(u4)); i++) {
                ctx->processingBuffer[i] = input[i];
            }
        }

        A = ctx->digest[0];
        B = ctx->digest[1];
        C = ctx->digest[2];
        D = ctx->digest[3];
        E = ctx->digest[4];
        F = ctx->digest[5];
        G = ctx->digest[6];
        H = ctx->digest[7];

        SHA256_P( A, B, C, D, E, F, G, H, ctx->processingBuffer[ 0], 0x428A2F98 );
        SHA256_P( H, A, B, C, D, E, F, G, ctx->processingBuffer[ 1], 0x71374491 );
        SHA256_P( G, H, A, B, C, D, E, F, ctx->processingBuffer[ 2], 0xB5C0FBCF );
        SHA256_P( F, G, H, A, B, C, D, E, ctx->processingBuffer[ 3], 0xE9B5DBA5 );
        SHA256_P( E, F, G, H, A, B, C, D, ctx->processingBuffer[ 4], 0x3956C25B );
        SHA256_P( D, E, F, G, H, A, B, C, ctx->processingBuffer[ 5], 0x59F111F1 );
        SHA256_P( C, D, E, F, G, H, A, B, ctx->processingBuffer[ 6], 0x923F82A4 );
        SHA256_P( B, C, D, E, F, G, H, A, ctx->processingBuffer[ 7], 0xAB1C5ED5 );
        SHA256_P( A, B, C, D, E, F, G, H, ctx->processingBuffer[ 8], 0xD807AA98 );
        SHA256_P( H, A, B, C, D, E, F, G, ctx->processingBuffer[ 9], 0x12835B01 );
        SHA256_P( G, H, A, B, C, D, E, F, ctx->processingBuffer[10], 0x243185BE );
        SHA256_P( F, G, H, A, B, C, D, E, ctx->processingBuffer[11], 0x550C7DC3 );
        SHA256_P( E, F, G, H, A, B, C, D, ctx->processingBuffer[12], 0x72BE5D74 );
        SHA256_P( D, E, F, G, H, A, B, C, ctx->processingBuffer[13], 0x80DEB1FE );
        SHA256_P( C, D, E, F, G, H, A, B, ctx->processingBuffer[14], 0x9BDC06A7 );
        SHA256_P( B, C, D, E, F, G, H, A, ctx->processingBuffer[15], 0xC19BF174 );
        SHA256_P( A, B, C, D, E, F, G, H, SHA256_R(16), 0xE49B69C1 );
        SHA256_P( H, A, B, C, D, E, F, G, SHA256_R(17), 0xEFBE4786 );
        SHA256_P( G, H, A, B, C, D, E, F, SHA256_R(18), 0x0FC19DC6 );
        SHA256_P( F, G, H, A, B, C, D, E, SHA256_R(19), 0x240CA1CC );
        SHA256_P( E, F, G, H, A, B, C, D, SHA256_R(20), 0x2DE92C6F );
        SHA256_P( D, E, F, G, H, A, B, C, SHA256_R(21), 0x4A7484AA );
        SHA256_P( C, D, E, F, G, H, A, B, SHA256_R(22), 0x5CB0A9DC );
        SHA256_P( B, C, D, E, F, G, H, A, SHA256_R(23), 0x76F988DA );
        SHA256_P( A, B, C, D, E, F, G, H, SHA256_R(24), 0x983E5152 );
        SHA256_P( H, A, B, C, D, E, F, G, SHA256_R(25), 0xA831C66D );
        SHA256_P( G, H, A, B, C, D, E, F, SHA256_R(26), 0xB00327C8 );
        SHA256_P( F, G, H, A, B, C, D, E, SHA256_R(27), 0xBF597FC7 );
        SHA256_P( E, F, G, H, A, B, C, D, SHA256_R(28), 0xC6E00BF3 );
        SHA256_P( D, E, F, G, H, A, B, C, SHA256_R(29), 0xD5A79147 );
        SHA256_P( C, D, E, F, G, H, A, B, SHA256_R(30), 0x06CA6351 );
        SHA256_P( B, C, D, E, F, G, H, A, SHA256_R(31), 0x14292967 );
        SHA256_P( A, B, C, D, E, F, G, H, SHA256_R(32), 0x27B70A85 );
        SHA256_P( H, A, B, C, D, E, F, G, SHA256_R(33), 0x2E1B2138 );
        SHA256_P( G, H, A, B, C, D, E, F, SHA256_R(34), 0x4D2C6DFC );
        SHA256_P( F, G, H, A, B, C, D, E, SHA256_R(35), 0x53380D13 );
        SHA256_P( E, F, G, H, A, B, C, D, SHA256_R(36), 0x650A7354 );
        SHA256_P( D, E, F, G, H, A, B, C, SHA256_R(37), 0x766A0ABB );
        SHA256_P( C, D, E, F, G, H, A, B, SHA256_R(38), 0x81C2C92E );
        SHA256_P( B, C, D, E, F, G, H, A, SHA256_R(39), 0x92722C85 );
        SHA256_P( A, B, C, D, E, F, G, H, SHA256_R(40), 0xA2BFE8A1 );
        SHA256_P( H, A, B, C, D, E, F, G, SHA256_R(41), 0xA81A664B );
        SHA256_P( G, H, A, B, C, D, E, F, SHA256_R(42), 0xC24B8B70 );
        SHA256_P( F, G, H, A, B, C, D, E, SHA256_R(43), 0xC76C51A3 );
        SHA256_P( E, F, G, H, A, B, C, D, SHA256_R(44), 0xD192E819 );
        SHA256_P( D, E, F, G, H, A, B, C, SHA256_R(45), 0xD6990624 );
        SHA256_P( C, D, E, F, G, H, A, B, SHA256_R(46), 0xF40E3585 );
        SHA256_P( B, C, D, E, F, G, H, A, SHA256_R(47), 0x106AA070 );
        SHA256_P( A, B, C, D, E, F, G, H, SHA256_R(48), 0x19A4C116 );
        SHA256_P( H, A, B, C, D, E, F, G, SHA256_R(49), 0x1E376C08 );
        SHA256_P( G, H, A, B, C, D, E, F, SHA256_R(50), 0x2748774C );
        SHA256_P( F, G, H, A, B, C, D, E, SHA256_R(51), 0x34B0BCB5 );
        SHA256_P( E, F, G, H, A, B, C, D, SHA256_R(52), 0x391C0CB3 );
        SHA256_P( D, E, F, G, H, A, B, C, SHA256_R(53), 0x4ED8AA4A );
        SHA256_P( C, D, E, F, G, H, A, B, SHA256_R(54), 0x5B9CCA4F );
        SHA256_P( B, C, D, E, F, G, H, A, SHA256_R(55), 0x682E6FF3 );
        SHA256_P( A, B, C, D, E, F, G, H, SHA256_R(56), 0x748F82EE );
        SHA256_P( H, A, B, C, D, E, F, G, SHA256_R(57), 0x78A5636F );
        SHA256_P( G, H, A, B, C, D, E, F, SHA256_R(58), 0x84C87814 );
        SHA256_P( F, G, H, A, B, C, D, E, SHA256_R(59), 0x8CC70208 );
        SHA256_P( E, F, G, H, A, B, C, D, SHA256_R(60), 0x90BEFFFA );
        SHA256_P( D, E, F, G, H, A, B, C, SHA256_R(61), 0xA4506CEB );
        SHA256_P( C, D, E, F, G, H, A, B, SHA256_R(62), 0xBEF9A3F7 );
        SHA256_P( B, C, D, E, F, G, H, A, SHA256_R(63), 0xC67178F2 );

        ctx->digest[0] += A;
        ctx->digest[1] += B;
        ctx->digest[2] += C;
        ctx->digest[3] += D;
        ctx->digest[4] += E;
        ctx->digest[5] += F;
        ctx->digest[6] += G;
        ctx->digest[7] += H;
    }

#endif


void algo_sha256_update(algo_sha256_context *ctx, u1 *input, u4 length )
{
    u4 left, fill;

    if(!length ) return;

    left = ctx->total[0] & 0x3F;
    fill = SHA256_BLOCK_LENGTH - left;

    ctx->total[0] += length;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < length )
        ctx->total[1]++;

    if( left && length >= fill )
    {
        memcpy(ctx->input + left,input,fill);

        algo_sha256_compress( ctx,(u4*)ctx->input );
        length -= fill;
        input  += fill;
        left = 0;
    }

    while( length >= SHA256_BLOCK_LENGTH )
    {
        algo_sha256_compress( ctx, (u4*)input );
        length -= SHA256_BLOCK_LENGTH;
        input  += SHA256_BLOCK_LENGTH;
    }

    if( length ){
        memcpy(ctx->input + left,input,length);
    }
}

void algo_sha256_finish(algo_sha256_context *ctx)
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
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    algo_sha256_update( ctx, (u1*)sha256_padding, padn );
    algo_sha256_update( ctx, (u1*)msglen, 8 );

    // little endian processing
    if (IS_LITTLE_ENDIAN)
    {
        for (i = 0; i < (SHA256_HASH_LENGTH / sizeof(u4)); i++) {
            ctx->digest[i] = swapbytes_u4(ctx->digest[i]);
        }
    }
}

