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


#ifndef _include_algo_sha1_h
#define _include_algo_sha1_h


typedef struct algo_sha1_context {

    unsigned int total[ 2 ];
    
    unsigned int* digest;

    unsigned char* input;

} algo_sha1_context;


#define SHA1_HASH_LENGTH  20

#define SHA1_BLOCK_LENGTH 64


extern void algo_sha1_starts( algo_sha1_context* ctx );

extern void algo_sha1_update( algo_sha1_context* ctx, unsigned char* input, unsigned int length );

extern void algo_sha1_finish( algo_sha1_context* ctx );


#endif
