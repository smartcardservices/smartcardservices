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

//#include "stdafx.h"
#include "MarshallerCfg.h"
#include "algo_des.h"

typedef struct _DES_Context
{
    u4 encrypt_subkeys[32];
    u4 decrypt_subkeys[32];
} _DES_Context;

typedef struct _3DES_Context
{
    u4 encrypt_subkeys[96];
    u4 decrypt_subkeys[96];
} _3DES_Context;

/*
 * The s-box values are permuted according to the 'primitive function P'
 * and are rotated one bit to the left.
 */
static const u4 sbox1[64] =
{
  0x01010400, 0x00000000, 0x00010000, 0x01010404, 0x01010004, 0x00010404, 0x00000004, 0x00010000,
  0x00000400, 0x01010400, 0x01010404, 0x00000400, 0x01000404, 0x01010004, 0x01000000, 0x00000004,
  0x00000404, 0x01000400, 0x01000400, 0x00010400, 0x00010400, 0x01010000, 0x01010000, 0x01000404,
  0x00010004, 0x01000004, 0x01000004, 0x00010004, 0x00000000, 0x00000404, 0x00010404, 0x01000000,
  0x00010000, 0x01010404, 0x00000004, 0x01010000, 0x01010400, 0x01000000, 0x01000000, 0x00000400,
  0x01010004, 0x00010000, 0x00010400, 0x01000004, 0x00000400, 0x00000004, 0x01000404, 0x00010404,
  0x01010404, 0x00010004, 0x01010000, 0x01000404, 0x01000004, 0x00000404, 0x00010404, 0x01010400,
  0x00000404, 0x01000400, 0x01000400, 0x00000000, 0x00010004, 0x00010400, 0x00000000, 0x01010004
};

static const u4 sbox2[64] =
{
  0x80108020, 0x80008000, 0x00008000, 0x00108020, 0x00100000, 0x00000020, 0x80100020, 0x80008020,
  0x80000020, 0x80108020, 0x80108000, 0x80000000, 0x80008000, 0x00100000, 0x00000020, 0x80100020,
  0x00108000, 0x00100020, 0x80008020, 0x00000000, 0x80000000, 0x00008000, 0x00108020, 0x80100000,
  0x00100020, 0x80000020, 0x00000000, 0x00108000, 0x00008020, 0x80108000, 0x80100000, 0x00008020,
  0x00000000, 0x00108020, 0x80100020, 0x00100000, 0x80008020, 0x80100000, 0x80108000, 0x00008000,
  0x80100000, 0x80008000, 0x00000020, 0x80108020, 0x00108020, 0x00000020, 0x00008000, 0x80000000,
  0x00008020, 0x80108000, 0x00100000, 0x80000020, 0x00100020, 0x80008020, 0x80000020, 0x00100020,
  0x00108000, 0x00000000, 0x80008000, 0x00008020, 0x80000000, 0x80100020, 0x80108020, 0x00108000
};

static const u4 sbox3[64] =
{
  0x00000208, 0x08020200, 0x00000000, 0x08020008, 0x08000200, 0x00000000, 0x00020208, 0x08000200,
  0x00020008, 0x08000008, 0x08000008, 0x00020000, 0x08020208, 0x00020008, 0x08020000, 0x00000208,
  0x08000000, 0x00000008, 0x08020200, 0x00000200, 0x00020200, 0x08020000, 0x08020008, 0x00020208,
  0x08000208, 0x00020200, 0x00020000, 0x08000208, 0x00000008, 0x08020208, 0x00000200, 0x08000000,
  0x08020200, 0x08000000, 0x00020008, 0x00000208, 0x00020000, 0x08020200, 0x08000200, 0x00000000,
  0x00000200, 0x00020008, 0x08020208, 0x08000200, 0x08000008, 0x00000200, 0x00000000, 0x08020008,
  0x08000208, 0x00020000, 0x08000000, 0x08020208, 0x00000008, 0x00020208, 0x00020200, 0x08000008,
  0x08020000, 0x08000208, 0x00000208, 0x08020000, 0x00020208, 0x00000008, 0x08020008, 0x00020200
};

static const u4 sbox4[64] =
{
  0x00802001, 0x00002081, 0x00002081, 0x00000080, 0x00802080, 0x00800081, 0x00800001, 0x00002001,
  0x00000000, 0x00802000, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00800080, 0x00800001,
  0x00000001, 0x00002000, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002001, 0x00002080,
  0x00800081, 0x00000001, 0x00002080, 0x00800080, 0x00002000, 0x00802080, 0x00802081, 0x00000081,
  0x00800080, 0x00800001, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00000000, 0x00802000,
  0x00002080, 0x00800080, 0x00800081, 0x00000001, 0x00802001, 0x00002081, 0x00002081, 0x00000080,
  0x00802081, 0x00000081, 0x00000001, 0x00002000, 0x00800001, 0x00002001, 0x00802080, 0x00800081,
  0x00002001, 0x00002080, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002000, 0x00802080
};

static const u4 sbox5[64] =
{
  0x00000100, 0x02080100, 0x02080000, 0x42000100, 0x00080000, 0x00000100, 0x40000000, 0x02080000,
  0x40080100, 0x00080000, 0x02000100, 0x40080100, 0x42000100, 0x42080000, 0x00080100, 0x40000000,
  0x02000000, 0x40080000, 0x40080000, 0x00000000, 0x40000100, 0x42080100, 0x42080100, 0x02000100,
  0x42080000, 0x40000100, 0x00000000, 0x42000000, 0x02080100, 0x02000000, 0x42000000, 0x00080100,
  0x00080000, 0x42000100, 0x00000100, 0x02000000, 0x40000000, 0x02080000, 0x42000100, 0x40080100,
  0x02000100, 0x40000000, 0x42080000, 0x02080100, 0x40080100, 0x00000100, 0x02000000, 0x42080000,
  0x42080100, 0x00080100, 0x42000000, 0x42080100, 0x02080000, 0x00000000, 0x40080000, 0x42000000,
  0x00080100, 0x02000100, 0x40000100, 0x00080000, 0x00000000, 0x40080000, 0x02080100, 0x40000100
};

static const u4 sbox6[64] =
{
  0x20000010, 0x20400000, 0x00004000, 0x20404010, 0x20400000, 0x00000010, 0x20404010, 0x00400000,
  0x20004000, 0x00404010, 0x00400000, 0x20000010, 0x00400010, 0x20004000, 0x20000000, 0x00004010,
  0x00000000, 0x00400010, 0x20004010, 0x00004000, 0x00404000, 0x20004010, 0x00000010, 0x20400010,
  0x20400010, 0x00000000, 0x00404010, 0x20404000, 0x00004010, 0x00404000, 0x20404000, 0x20000000,
  0x20004000, 0x00000010, 0x20400010, 0x00404000, 0x20404010, 0x00400000, 0x00004010, 0x20000010,
  0x00400000, 0x20004000, 0x20000000, 0x00004010, 0x20000010, 0x20404010, 0x00404000, 0x20400000,
  0x00404010, 0x20404000, 0x00000000, 0x20400010, 0x00000010, 0x00004000, 0x20400000, 0x00404010,
  0x00004000, 0x00400010, 0x20004010, 0x00000000, 0x20404000, 0x20000000, 0x00400010, 0x20004010
};

static const u4 sbox7[64] =
{
  0x00200000, 0x04200002, 0x04000802, 0x00000000, 0x00000800, 0x04000802, 0x00200802, 0x04200800,
  0x04200802, 0x00200000, 0x00000000, 0x04000002, 0x00000002, 0x04000000, 0x04200002, 0x00000802,
  0x04000800, 0x00200802, 0x00200002, 0x04000800, 0x04000002, 0x04200000, 0x04200800, 0x00200002,
  0x04200000, 0x00000800, 0x00000802, 0x04200802, 0x00200800, 0x00000002, 0x04000000, 0x00200800,
  0x04000000, 0x00200800, 0x00200000, 0x04000802, 0x04000802, 0x04200002, 0x04200002, 0x00000002,
  0x00200002, 0x04000000, 0x04000800, 0x00200000, 0x04200800, 0x00000802, 0x00200802, 0x04200800,
  0x00000802, 0x04000002, 0x04200802, 0x04200000, 0x00200800, 0x00000000, 0x00000002, 0x04200802,
  0x00000000, 0x00200802, 0x04200000, 0x00000800, 0x04000002, 0x04000800, 0x00000800, 0x00200002
};

static const u4 sbox8[64] =
{
  0x10001040, 0x00001000, 0x00040000, 0x10041040, 0x10000000, 0x10001040, 0x00000040, 0x10000000,
  0x00040040, 0x10040000, 0x10041040, 0x00041000, 0x10041000, 0x00041040, 0x00001000, 0x00000040,
  0x10040000, 0x10000040, 0x10001000, 0x00001040, 0x00041000, 0x00040040, 0x10040040, 0x10041000,
  0x00001040, 0x00000000, 0x00000000, 0x10040040, 0x10000040, 0x10001000, 0x00041040, 0x00040000,
  0x00041040, 0x00040000, 0x10041000, 0x00001000, 0x00000040, 0x10040040, 0x00001000, 0x00041040,
  0x10001000, 0x00000040, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x00040000, 0x10001040,
  0x00000000, 0x10041040, 0x00040040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0x00000000,
  0x10041040, 0x00041000, 0x00041000, 0x00001040, 0x00001040, 0x00040040, 0x10000000, 0x10041000
};

static const u4 leftkey_swap[16] =
{
  0x00000000, 0x00000001, 0x00000100, 0x00000101,
  0x00010000, 0x00010001, 0x00010100, 0x00010101,
  0x01000000, 0x01000001, 0x01000100, 0x01000101,
  0x01010000, 0x01010001, 0x01010100, 0x01010101
};

static const u4 rightkey_swap[16] =
{
  0x00000000, 0x01000000, 0x00010000, 0x01010000,
  0x00000100, 0x01000100, 0x00010100, 0x01010100,
  0x00000001, 0x01000001, 0x00010001, 0x01010001,
  0x00000101, 0x01000101, 0x00010101, 0x01010101,
};

static const u1 encrypt_rotate_tab[16] =
{
  1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

#define DO_PERMUTATION(a, temp, b, offset, mask)	\
    temp = ((a>>offset) ^ b) & mask;			\
    b ^= temp;						\
    a ^= temp<<offset;

#define INITIAL_PERMUTATION(left, temp, right)		\
    DO_PERMUTATION(left, temp, right, 4, 0x0f0f0f0f)	\
    DO_PERMUTATION(left, temp, right, 16, 0x0000ffff)	\
    DO_PERMUTATION(right, temp, left, 2, 0x33333333)	\
    DO_PERMUTATION(right, temp, left, 8, 0x00ff00ff)	\
    right =  (right << 1) | (right >> 31);		\
    temp  =  (left ^ right) & 0xaaaaaaaa;		\
    right ^= temp;					\
    left  ^= temp;					\
    left  =  (left << 1) | (left >> 31);

#define FINAL_PERMUTATION(left, temp, right)		\
    left  =  (left << 31) | (left >> 1);		\
    temp  =  (left ^ right) & 0xaaaaaaaa;		\
    left  ^= temp;					\
    right ^= temp;					\
    right  =  (right << 31) | (right >> 1);		\
    DO_PERMUTATION(right, temp, left, 8, 0x00ff00ff)	\
    DO_PERMUTATION(right, temp, left, 2, 0x33333333)	\
    DO_PERMUTATION(left, temp, right, 16, 0x0000ffff)	\
    DO_PERMUTATION(left, temp, right, 4, 0x0f0f0f0f)

#define DES_ROUND(from, to, work, subkey)		\
    work = from ^ *subkey++;				\
    to ^= sbox8[  work	    & 0x3f ];			\
    to ^= sbox6[ (work>>8)  & 0x3f ];			\
    to ^= sbox4[ (work>>16) & 0x3f ];			\
    to ^= sbox2[ (work>>24) & 0x3f ];			\
    work = ((from << 28) | (from >> 4)) ^ *subkey++;	\
    to ^= sbox7[  work	    & 0x3f ];			\
    to ^= sbox5[ (work>>8)  & 0x3f ];			\
    to ^= sbox3[ (work>>16) & 0x3f ];			\
    to ^= sbox1[ (work>>24) & 0x3f ];

#define READ_64BIT_DATA(data, left, right)					\
    left  = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];	\
    right = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];

#define WRITE_64BIT_DATA(data, left, right)					\
    data[0] = (left >> 24) &0xff; data[1] = (left >> 16) &0xff; 		\
    data[2] = (left >> 8) &0xff; data[3] = left &0xff;				\
    data[4] = (right >> 24) &0xff; data[5] = (right >> 16) &0xff;		\
    data[6] = (right >> 8) &0xff; data[7] = right &0xff;


static void algo_DES_KeySchedule(const u1 * rawkey, u4 * subkey)
{
    u4 left, right, work;
    u1 round;

    READ_64BIT_DATA (rawkey, left, right)

    DO_PERMUTATION (right, work, left, 4, 0x0f0f0f0f)
    DO_PERMUTATION (right, work, left, 0, 0x10101010)

    left = (leftkey_swap[(left >> 0) & 0xf] << 3) | (leftkey_swap[(left >> 8) & 0xf] << 2)
        | (leftkey_swap[(left >> 16) & 0xf] << 1) | (leftkey_swap[(left >> 24) & 0xf])
        | (leftkey_swap[(left >> 5) & 0xf] << 7) | (leftkey_swap[(left >> 13) & 0xf] << 6)
        | (leftkey_swap[(left >> 21) & 0xf] << 5) | (leftkey_swap[(left >> 29) & 0xf] << 4);

    left &= 0x0fffffff;

    right = (rightkey_swap[(right >> 1) & 0xf] << 3) | (rightkey_swap[(right >> 9) & 0xf] << 2)
        | (rightkey_swap[(right >> 17) & 0xf] << 1) | (rightkey_swap[(right >> 25) & 0xf])
        | (rightkey_swap[(right >> 4) & 0xf] << 7) | (rightkey_swap[(right >> 12) & 0xf] << 6)
        | (rightkey_swap[(right >> 20) & 0xf] << 5) | (rightkey_swap[(right >> 28) & 0xf] << 4);

    right &= 0x0fffffff;

    for (round = 0; round < 16; ++round) {

        left = ((left << encrypt_rotate_tab[round]) | (left >> (28 - encrypt_rotate_tab[round]))) & 0x0fffffff;
        right = ((right << encrypt_rotate_tab[round]) | (right >> (28 - encrypt_rotate_tab[round]))) & 0x0fffffff;

        *subkey++ = ((left << 4) & 0x24000000)
            | ((left << 28) & 0x10000000)
            | ((left << 14) & 0x08000000)
            | ((left << 18) & 0x02080000)
            | ((left << 6) & 0x01000000)
            | ((left << 9) & 0x00200000)
            | ((left >> 1) & 0x00100000)
            | ((left << 10) & 0x00040000)
            | ((left << 2) & 0x00020000)
            | ((left >> 10) & 0x00010000)
            | ((right >> 13) & 0x00002000)
            | ((right >> 4) & 0x00001000)
            | ((right << 6) & 0x00000800)
            | ((right >> 1) & 0x00000400)
            | ((right >> 14) & 0x00000200)
            | (right & 0x00000100)
            | ((right >> 5) & 0x00000020)
            | ((right >> 10) & 0x00000010)
            | ((right >> 3) & 0x00000008)
            | ((right >> 18) & 0x00000004)
            | ((right >> 26) & 0x00000002)
            | ((right >> 24) & 0x00000001);

        *subkey++ = ((left << 15) & 0x20000000)
            | ((left << 17) & 0x10000000)
            | ((left << 10) & 0x08000000)
            | ((left << 22) & 0x04000000)
            | ((left >> 2) & 0x02000000)
            | ((left << 1) & 0x01000000)
            | ((left << 16) & 0x00200000)
            | ((left << 11) & 0x00100000)
            | ((left << 3) & 0x00080000)
            | ((left >> 6) & 0x00040000)
            | ((left << 15) & 0x00020000)
            | ((left >> 4) & 0x00010000)
            | ((right >> 2) & 0x00002000)
            | ((right << 8) & 0x00001000)
            | ((right >> 14) & 0x00000808)
            | ((right >> 9) & 0x00000400)
            | ((right) & 0x00000200)
            | ((right << 7) & 0x00000100)
            | ((right >> 7) & 0x00000020)
            | ((right >> 3) & 0x00000011)
            | ((right << 2) & 0x00000004)
            | ((right >> 21) & 0x00000002);
    }
}

static void algo_DES_Setkey(_DES_Context *ctx, const u1 * key)
{
    u1 i;

    algo_DES_KeySchedule(key, ctx->encrypt_subkeys);

    for(i = 0; i < 32; i += 2) {
        ctx->decrypt_subkeys[i]	= ctx->encrypt_subkeys[30-i];
        ctx->decrypt_subkeys[i+1] = ctx->encrypt_subkeys[31-i];
    }
}

static void algo_DES_Set2keys(_3DES_Context *ctx, const u1 * key1, const u1 * key2)
{
    u1 i;

    algo_DES_KeySchedule(key1, ctx->encrypt_subkeys);
    algo_DES_KeySchedule(key2, &(ctx->decrypt_subkeys[32]));

    for(i = 0; i < 32; i += 2) {
        ctx->decrypt_subkeys[i] = ctx->encrypt_subkeys[30-i];
        ctx->decrypt_subkeys[i+1] = ctx->encrypt_subkeys[31-i];

        ctx->encrypt_subkeys[i+32] = ctx->decrypt_subkeys[62-i];
        ctx->encrypt_subkeys[i+33] = ctx->decrypt_subkeys[63-i];

        ctx->encrypt_subkeys[i+64] = ctx->encrypt_subkeys[i];
        ctx->encrypt_subkeys[i+65] = ctx->encrypt_subkeys[i+1];

        ctx->decrypt_subkeys[i+64] = ctx->decrypt_subkeys[i];
        ctx->decrypt_subkeys[i+65] = ctx->decrypt_subkeys[i+1];
    }
}

static void algo_DES_Set3keys(_3DES_Context *ctx, const u1 * key1, const u1 * key2, const u1 * key3)
{
    u1 i;

    algo_DES_KeySchedule(key1, ctx->encrypt_subkeys);
    algo_DES_KeySchedule(key2, &(ctx->decrypt_subkeys[32]));
    algo_DES_KeySchedule(key3, &(ctx->encrypt_subkeys[64]));

    for(i = 0; i < 32; i += 2) {
        ctx->decrypt_subkeys[i]	 = ctx->encrypt_subkeys[94-i];
        ctx->decrypt_subkeys[i+1]  = ctx->encrypt_subkeys[95-i];
        ctx->encrypt_subkeys[i+32] = ctx->decrypt_subkeys[62-i];
        ctx->encrypt_subkeys[i+33] = ctx->decrypt_subkeys[63-i];
        ctx->decrypt_subkeys[i+64] = ctx->encrypt_subkeys[30-i];
        ctx->decrypt_subkeys[i+65] = ctx->encrypt_subkeys[31-i];
    }
}

void algo_DES_DESProcess(u1* key, u1* from, u1* to, u1 mode)
{
    _DES_Context ctx;
    u4 left, right, work;
    u4 *keys;

    algo_DES_Setkey(&ctx, key);

    keys = (mode == TRUE) ? ctx.encrypt_subkeys : ctx.decrypt_subkeys;

    READ_64BIT_DATA(from, left, right)
    INITIAL_PERMUTATION(left, work, right)

    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)

    FINAL_PERMUTATION(right, work, left)
    WRITE_64BIT_DATA(to, right, left)
}

void algo_DES_3DESProcess(u1 keyLength, u1* key, u1 * from, u1 * to, u1 mode)
{
    _3DES_Context ctx;
    u4 left, right, work;
    u4 *keys;

    if (keyLength == 0x10) {
        algo_DES_Set2keys(&ctx, &key[0], &key[8]);
    } else {
        algo_DES_Set3keys(&ctx, &key[0], &key[8], &key[16]);
    }

    keys = (mode == TRUE) ? ctx.encrypt_subkeys : ctx.decrypt_subkeys;

    READ_64BIT_DATA(from, left, right)
    INITIAL_PERMUTATION(left, work, right)

    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)

    DES_ROUND(left, right, work, keys) DES_ROUND(right, left, work, keys)
    DES_ROUND(left, right, work, keys) DES_ROUND(right, left, work, keys)
    DES_ROUND(left, right, work, keys) DES_ROUND(right, left, work, keys)
    DES_ROUND(left, right, work, keys) DES_ROUND(right, left, work, keys)
    DES_ROUND(left, right, work, keys) DES_ROUND(right, left, work, keys)
    DES_ROUND(left, right, work, keys) DES_ROUND(right, left, work, keys)
    DES_ROUND(left, right, work, keys) DES_ROUND(right, left, work, keys)
    DES_ROUND(left, right, work, keys) DES_ROUND(right, left, work, keys)

    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)
    DES_ROUND(right, left, work, keys) DES_ROUND(left, right, work, keys)

    FINAL_PERMUTATION(right, work, left)
    WRITE_64BIT_DATA(to, right, left)
}

