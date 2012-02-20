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

#ifndef _include_algo_md5_h
#define _include_algo_md5_h

#include "MarshallerCfg.h"

typedef struct algo_md5_context{
    u4 total[2];
    u4* digest;
    u1* input;
} algo_md5_context;

#define MD5_HASH_LENGTH 16
#define MD5_BLOCK_LENGTH 64

extern void algo_md5_starts(algo_md5_context* ctx);
extern void algo_md5_update(algo_md5_context* ctx, u1* input, u4 length);
extern void algo_md5_finish(algo_md5_context* ctx);

#endif

